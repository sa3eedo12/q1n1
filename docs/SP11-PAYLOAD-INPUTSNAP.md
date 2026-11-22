<!-- SPDX-License-Identifier: MIT -->
# SP11 payload `inputsnap`: a read-only snapshot of the two input engines, taken before anything is started

`payloads/inputsnap.c` (with `payloads/inputsnap-regs.h`, its register table) is one payload of the stick payload runner described in
[SP11-PAYLOAD.md](SP11-PAYLOAD.md): the manifest and the stick files, [the chain](SP11-PAYLOAD.md#the-chain-several-payloads-in-one-boot), ABI v1 and the
[line catalogue](SP11-PAYLOAD.md#line-catalogue) are defined there and not repeated. The register table with its citations, the words Linux reads and the reference copies are in
[SP11-PAYLOAD-INPUTSNAP-REGISTERS.md](SP11-PAYLOAD-INPUTSNAP-REGISTERS.md). The payload exists for the first question of the input path of the Surface Pro 11 port: after
the firmware's hand-off, can anything of ours reach the engines that carry the keyboard, the touchpad, the touchscreen and the pen? The design note that specified it
decoded the devices from the unit's own dumped ACPI tables (OBSERVED; no table bytes are in this tree, UV1). They show a **Surface Aggregator Module (SAM) device on a UART**, QUP
wrapper 0 engine 2 (`uart2`, window `0x00b88000`, GSIV 616, 4 Mbps 8N1 with hardware flow control, wake line gpio91); that the **Type Cover's keyboard, touchpad and pen stash are
devices behind it** is what the Linux registry and third parties report, not something this unit has shown (INFERRED, never seen on a wire here). They show the **touchscreen and the pen as
one HID-over-SPI device** on QUP wrapper 1 engine 2 (`spi10`, window `0x00a88000`, GSIV 834, interrupt gpio51 and power gpio64; the reset line gpio48 is INFERRED, no descriptor of the dumped tables names it, and so is that the pen shares the device), and no
HID-over-I2C device at all; the A16's allow-list address `0x00B80000` is the SP11's I2C1, an unrelated group of devices. The device trees agree where they say anything (VERIFIED as what they
say: dt:2337-2343, dt:1688-1694, den:1316-1327). A second reading of the dumped tables (OBSERVED, one unit): the SAM device is a UART serial bus on `UAR3` with a GPIO IO on gpio91, the touch
device an SPI serial bus on `SP11` with a GPIO interrupt on gpio51 and a GPIO IO on gpio64, the secure-device table names no QUP engine and no pin controller (their ownership is INFERRED non-secure),
and the SPCR console UART is the one at `0x894000` (QUP wrapper 2 engine 5), not `uart2`. `inputsnap` prints, on the filmed panel and **before anything is started**, the words that say whether those two engines are clocked,
configured and quiet, and what the GIC and the pin controller hold for their interrupts and pins, once at entry and once after an 8 s wait (as a list of what moved); last of all it
prints the words no Linux driver reads. So a hang leaves the evidence on the film and costs the words after it, never the ones before.

Evidence labels as in the study: VERIFIED (a pinned Linux file or the architecture says so; never "it was run"), OBSERVED (the unit's own tables, an earlier boot or the operator's own report
showed it, once), INFERRED, EXPERIMENTAL, UNIMPLEMENTED, UNKNOWN.

**EXPERIMENTAL; hardware NOT RUN.** Nothing in this document was read from the unit by this payload: the host model, the compiled-code audits, the pinned-copy test and QEMU are
all the evidence there is. The engines' registers, the pin controller's and the clock words of the two QUP wrappers have **never been read on the unit** (UNKNOWN); only the GIC
distributor's control words and the clock controller's window were (OBSERVED, boots 3, 12, 14 and 18A). It stores **nothing** by its own code (its only stores are to its own
stack; the runner draws the lines it prints), makes no `smc` or `hvc`, starts no timer and waits once. It needs its own record and the operator's approval of its SHA-256
before any run; this document authorises none.

## What it answers, and what it does not

It answers, by what the film shows: at entry, are the clocks of the two wrappers and of the two engines on; do the engines hold the protocol firmware the devices need (2 is
the UART, the SPI engine's number is UV2) and are they configured and idle; do the FIFOs, the interrupt status words and the UART's `CTS` input **move during 8 s of doing
nothing** (a cover that is attached and typed on, against one that is detached); which of INTID 240 (the pin controller's summary interrupt), 616 and 834 the GIC has enabled,
pending, grouped, configured and routed; and what the pin controller holds for the UART's pins (gpio8-11), the SPI engine's (gpio40-43), the lid (gpio2), the touch
controller's reset, interrupt and power lines (gpio48 INFERRED, 51, 64) and the Surface Aggregator's wake line (gpio91).

It does **not** answer: whether the Type Cover is attached or powered, what any frame on the UART means, whether the embedded controller answers a host that skipped Windows'
initialisation, or what Windows' next boot will think of any of it (all UNKNOWN: it reads nothing of the link); the pen's transport (INFERRED to share the touch device); who
owns the pins (UV4); or anything about the SPI protocol of the touch device. A value is a lead, never a finding, and a missing value (`FAULT:6`, `SKIP`, `GATED`) is a result too.

## What it reads, block by block

Five windows, each read at most once per snapshot, 32 bits at a time through the runner's guarded `load32`, and never a store:

| Window | Base | Read | Device tree |
| --- | --- | --- | --- |
| `GCC` the clock controller | `0x00100000` | `0x200000` | dt:758-760 |
| `GIC` the interrupt distributor | `0x17000000` | `0x10000` | dt:8558-8560 |
| `U2` the SAM engine, QUP wrapper 0 engine 2 | `0x00b88000` | the first `0x1000` of the node's `0x4000` | dt:2337-2343 |
| `S10` the touch engine, QUP wrapper 1 engine 2 | `0x00a88000` | the first `0x1000` of the node's `0x4000` | dt:1688-1694 |
| `TLMM` the pin controller | `0x0f100000` | `0xf00000` | dt:6119-6123 |

**Order.** The page is in the order of what one abort or one hang costs, because the first abort in a window ends the window and a hang ends the page. Snapshot 1 reads only words a
pinned Linux driver reads ([Which words Linux reads](SP11-PAYLOAD-INPUTSNAP-REGISTERS.md#which-words-linux-reads)): `GCC` first, because its clock words decide whether either engine may be
read at all, and in it each engine's gate words before the core 2x clock, which gates nothing; then `GIC`; then `U2` and `S10`, each **only if its own clock words all read ON**; the pin
controller **last**, because nobody has read it on this unit and which pins are the secure world's is UNKNOWN (UV4). **The first load of every block is a word Linux reads** (`MA0`,
`CTL`, `FW`, `FW`, `F8`), and within a block what the run exists for comes first: an engine's identity and mode words, then the words that move, then its enables and configuration. After
the 8 s wait come snapshot 2 and its drift report, and only then **the 24 words no pinned driver reads**, in three late blocks, `X U2`, `X S10`, `X GIC`, each under its own `NEXT` line. The
late blocks are the one exception to "the first load is a word Linux reads": they hold nothing Linux reads, they come after everything the run exists for, and a hang in one costs only the
late blocks after it. Every block is announced by a `NEXT <block>` line before its first load, and a block whose `NEXT` line cannot be printed is not read (a late block is also left out,
its bit set in `BLK`, when no line of values would fit after its `NEXT` line), so the last line on the panel names what hung. A line goes out as soon as its loads are done and also at the
table's `F_BREAK` rows (the second wrapper's words, the votes, the first interrupt, and the UART engine's first moving word and first enable word), so that what was read before a weaker
word is on the film before that word is loaded.

**The clock words.** A branch clock's word has `CLK_OFF` in bit 31 (cb:63) and the NoC FSM status in bits 30:28, whose value 2 is ON (cb:64-65). The payload calls a clock **stopped**
(`.OFF`) when `CLK_OFF` is set and the FSM status is not ON, which is Linux's own test for an enabled clock (cbc:54-57); an all-ones word, what a failed read returns, is `.ODD` and is no
clock word. Linux does not wait for the halt bit of a clock in hardware gating mode (cbc:72), and a clock is in that mode only if it names a hardware gating register (`hwcg_reg` with
`hwcg_bit`) whose bit is set (cbc:17-26, cb:15-16): in `gcc-x1e80100.c` that is the **four AHB clocks** (`MA0`, `SA0`, `MA1`, `SA1`: gcc:4955-4961, gcc:4970-4976, gcc:4985-4991,
gcc:5000-5006; the bit is `HW_CTL`, bit 1 of the same word). For those four a set `CLK_OFF` with `HW_CTL` set is `.HW`: the word itself has no verdict, and the gate counts it as running only
with the clock's vote set (**vote evidence**, below); for every other clock word `CLK_OFF` alone
decides (the table's `F_HWCG` flag; the host model carries its own list of the four). The whole word is printed. The engines each need the wrapper's two AHB clocks, its core clock and
the engine's own clock (dt:2141-2146 and dt:2337-2343 for `U2`, dt:1491-1496 and dt:1688-1694 for `S10`; the SPI engine's QSPI clock too, gcc:4569-4573); the two core 2x clocks gate
nothing. The vote words (gcc:4337-4341, gcc:4543-4547, gcc:4569-4573) are printed for context. `clk-branch.c` is not among the files the stick log pins: the copy the ledger uses has its
digest in [Fetching the reference copies](SP11-PAYLOAD-INPUTSNAP-REGISTERS.md#fetching-the-reference-copies), and the citations of it say so.

**Gating fails closed.** An engine is read only if every one of its clock words was read OK in **that snapshot** and none says stopped. A word that aborted, was skipped after an abort,
was never read or reads as all ones is a clock whose state is **unknown**, and an unknown clock is not read through either: the engine's block is the one line `<engine> GATED ERR`, and
**never** `GATED OFF`, which is for a word that read and says stopped (a failed read is not reported as the clock it gates). A gated engine is one line and no load of its window.
Snapshot 2 decides again from its own clock words, read just before the engine, and skips an engine whose clocks went off, or could not be read, during the wait
(`S2 <window> SKIP GATED OFF` or `ERR`); the late blocks decide on the freshest clock words there are (snapshot 2's if it read them). The load itself checks once more before it is made.

**Vote evidence.** A clock word cannot tell a healthy idle hardware-gated clock from one nobody asked for, nor a clock that runs from a window that reads zero everywhere. So the gate asks the
vote words, read in snapshot 1 before any engine block, for two more things (the review of v1, findings 1 and 4). An AHB clock that says only `.HW` counts as running when its apps vote is
set (`MA0` bit 6 and `SA0` bit 7 of `VT0`, `MA1` bit 20 and `SA1` bit 21 of `VT1`: gcc:4955-4961, gcc:4970-4976, gcc:4985-4991, gcc:5000-5006), as stopped (`GATED OFF`) when the vote word read and its bit is clear, and as unknown
(`GATED ERR`) when it did not read; a clock that reads `.ON` needs no vote, another master's vote may run it. And when all three vote words read zero no clock word counts (a window of zeros
shows every branch as running): both engines are `GATED ERR`; a vote word that did not read is not one that read zero. Snapshot 2 and the late blocks use snapshot 1's vote words: they are not
read again, and nothing runs between the two (INFERRED). Known limit of v1.1: a vote word that reads all ones (a failed read) counts as a set vote for a `.HW` clock, so it does not close the gate on that clock.

**Interrupts.** The GIC rows are written out for INTID 240, 616 and 834, which are the device tree's SPI numbers plus 32 (the pin controller's summary interrupt GIC_SPI 208:
dt:6119-6123; `uart2` GIC_SPI 584: dt:2337-2343; `spi10` GIC_SPI 802: dt:1688-1694). INTID n is bit n % 32 of word n / 32 of ISENABLER, ISPENDR and IGROUPR (gic3:456-469), a
two-bit field n % 16 of word n / 16 of ICFGR (gicc:51-52) and the 64-bit register n of IROUTER at `0x6000 + 8n` (gic3:976-977); the base offsets are gic:22-25, gic:30 and
gic:42. The enable, pending and configuration words are in the `GIC` block; the group and routing words, which Linux only writes, are in `X GIC`. `GICD_CTLR` was read as `0x10` in
boots 3, 12 and 14 (OBSERVED: only ARE_NS set, group 1 delivery off; the bits are gic:60-63): whether a non-secure read of IGROUPR or IROUTER answers with the real value or with zero
when `DS` is clear is the architecture's, not a pinned file's (UV3), so those words print raw and a zero is not a finding. IROUTER is read as two 32-bit loads, low then high,
never as a 64-bit load (gic:97-98 for what its bit 31 means).

**The engines.** Every word is a GENI register defined in `geni-se.h` (gse:87-92, gse:94, gse:96, gse:99-100, gse:108-109, gse:115-120, gse:152-154) and, for the UART's own
configuration, in `qcom_geni_serial.c` (gser:37-47); all lie in the first page, the highest being `SE_HW_PARAM_1` at `0xe28`. The firmware revision word carries the protocol
in bits 15:8 (gse:180-181): none 0, SPI 1, UART 2, I2C 3, I3C 4, SPI slave 5, invalid 255 (gse:34-40), and the UART driver loads firmware only when it reads 255 and refuses an
engine that reads anything but 2 (gser:1343-1350). `STATUS` bits 0 and 12 say that the main or the secondary sequencer has a command active (gse:168-169); the FIFO status
words carry the word count in bits 27:0 and 24:0 (gse:272, gse:278) and mean it in FIFO mode only, so `TXN` and `RXN` are decoded only when `IFD` bit 0 and `DMA` bit 0 are both 0
(the UART driver's interrupt handler reads the DMA mode word first, gser:1237-1241), else `ODD`; `IOS` bit 1 is IO2 data in (gse:281), which the UART driver reads as `CTS`, asserted
when low (gser:243-245), and is decoded as `CTS` only when `PR` is 2, else `ODD`. The SPI engine's block is the **common words only** (it has none of the UART's own); its `IOS` is
printed raw, since IO2 is a data line there. **The FIFO windows of an engine are never read** (`0x700-0x73f` and `0x780-0x7bf`: gse:113-114; a read of the receive FIFO pops bytes),
and the host model rejects any load there whatever the table says.

**The pins.** The pin controller's registers are 0x1000 apart: CFG at `0x1000 * pin`, IN_OUT at +4, INTR_CFG at +8, INTR_STATUS at +0xc (pin:12, pin:32-35); in CFG the function
select is bits 5:2, the pull bits 1:0, the drive strength 8:6 and output enable bit 9, in IN_OUT the input bit is 0 and the output bit 1, and in INTR_CFG enable is bit 0, polarity
bit 1 and detection 3:2 (pin:36-52; msm:185 for the four-bit function field, msm:626 for the level, msmh:45-53). Function 1 of gpio8-11 is `qup0_se2`, the UART's (pin:1575-1578);
of gpio40-43 `qup1_se2`, the SPI engine's (pin:1607-1610); gpio48 and 51 are `qup1_se4` (pin:1615, pin:1618: gpio51 has `qup1_se2` as function 2); gpio2 is `qup0_se0`, gpio64
`qup2_se0`, gpio91 `qup2_se6` (pin:1569, pin:1631, pin:1658); the controller has 239 pins (pin:1837). The lid is gpio2 and the Surface Aggregator's wake line gpio91
(den:20-49, den:1221-1223, den:1316-1327); the UART's pins are the node's `qup_uart2_default` state (dt:2356, dt:6692-6719). The words are printed raw; `F<pin>=` is the CFG word and
`L<pin>=` the IN_OUT word. **gpio44-47 (the TPM's) and gpio238 (the UFS reset) are never read** (den:1198-1199: the device tree reserves them), and a pin number above 91 is not in the table.

**What nobody has read.** The TLMM words, the GENI words and the QUP wrappers' clock words were never read on the unit (UV4): a pin that firmware gave to the secure world may
abort when read at EL2 (the payload prints `FAULT:6` under its own name and reads nothing more of the window), and nothing guards against a hang.

## The page

The numbers below are measured on runs of the host model (`python3 tools/test-q1n1-sp11-payload-inputsnap.py` compares this block with the model's `--numbers`):

<!-- numbers -->
| name | value |
| --- | --- |
| `registers` | 110 |
| `blocks` | 8 |
| `windows` | 5 |
| `line_cap` | 34 |
| `load_cap` | 400 |
| `abi_lines` | 40 |
| `abi_loads` | 4096 |
| `snapshot1_loads_max` | 86 |
| `snapshot2_loads_max` | 19 |
| `late_loads_max` | 27 |
| `unit_lines` | 33 |
| `unit_loads` | 132 |
| `unit_snapshot1_loads` | 86 |
| `unit_snapshot2_loads` | 19 |
| `unit_late_loads` | 27 |
| `wide_lines` | 34 |
| `wide_cuts` | 23 |
| `wideflip_lines` | 34 |
| `wideflip_cuts` | 32 |
| `gated_lines` | 30 |
| `gated_loads` | 77 |
<!-- /numbers -->

The page of the unit-like fixture of the host model, run with `--page`. It is a **made-up page**: the fixture's values are invented (except `GICD_CTLR`, `CTL=0X10`, which is
OBSERVED), so that a reader can tell the decodes apart (`C21` is the one stopped clock that gates nothing; `PR` is 2 on the UART engine and 9 on the SPI engine, the number a third
party reports for QSPI, UV2); it is not the unit's page and must not be read as one:

<!-- page -->
```
PAYLOAD INPUTSNAP READ ONLY EL=2 HZ=0X124F800 GAP=8 S
PAYLOAD INPUTSNAP KEY=VALUE FAULT:6=ABORT SKIP=AFTER ONE GATED=NOT READ ODD=DECODE NOT VALID
PAYLOAD INPUTSNAP NEXT GCC
PAYLOAD INPUTSNAP GCC MA0=1.ON SA0=1.ON CR0=1.ON SE0=1.ON C20=1.ON
PAYLOAD INPUTSNAP GCC MA1=1.ON SA1=1.ON CR1=1.ON SE1=1.ON QS1=1.ON C21=0X80000000.OFF
PAYLOAD INPUTSNAP GCC VT0=0X10C0 VT1=0X1380000 VT2=0X10
PAYLOAD INPUTSNAP NEXT GIC
PAYLOAD INPUTSNAP GIC CTL=0X10 TYP=0X7790F1F
PAYLOAD INPUTSNAP GIC E616=0 P616=1 C616=2 E834=0 P834=0 C834=2 E240=1 P240=0 C240=2
PAYLOAD INPUTSNAP NEXT U2
PAYLOAD INPUTSNAP U2 FW=0X230 PR=2 IFD=0 ST=0 M=0 S=0 DMA=0
PAYLOAD INPUTSNAP U2 TXF=0 TXN=0 RXF=0 RXN=0 MIS=0 SIS=0 IOS=2 CTS=1
PAYLOAD INPUTSNAP U2 MIE=0 SIE=0 IOM=0X1FF TCF=7 RCF=7 TPA=0 RPA=0 HW0=0XA80E0D4 HW1=0XB02
PAYLOAD INPUTSNAP NEXT S10
PAYLOAD INPUTSNAP S10 FW=0X930 PR=9 IFD=0 ST=0 M=0 S=0 DMA=0 TXF=0 TXN=0 RXF=0 RXN=0 MIS=0
PAYLOAD INPUTSNAP S10 SIS=0 IOS=2 MIE=0 SIE=0 HW0=0XA80E0D4 HW1=0XB02
PAYLOAD INPUTSNAP NEXT TLMM
PAYLOAD INPUTSNAP TLMM F8=4 L8=0 F9=4 L9=1 F10=4 L10=0 F11=4 L11=1 F91=1 L91=0 N91=5 S91=0
PAYLOAD INPUTSNAP TLMM F40=8 L40=0 F41=8 L41=1 F42=8 L42=0 F43=8 L43=1 F51=1 L51=0 N51=5 S51=0
PAYLOAD INPUTSNAP TLMM F48=1 L48=1 F64=1 L64=1 F2=1 L2=0
PAYLOAD INPUTSNAP NEXT WAIT 8 S
PAYLOAD INPUTSNAP NEXT S2 GCC
PAYLOAD INPUTSNAP NEXT S2 U2 GCC=SAME
PAYLOAD INPUTSNAP NEXT S2 TLMM
PAYLOAD INPUTSNAP DRIFT NONE CMP=19
PAYLOAD INPUTSNAP NEXT X U2
PAYLOAD INPUTSNAP X U2 CM=0X10 CS=0 CK=0 CC=3 TWL=8 TSB=0X20 RWL=8 STL=0X18 MRF=0 TWM=4
PAYLOAD INPUTSNAP X U2 RWM=0X20 RFW=0X20 DIF=1
PAYLOAD INPUTSNAP NEXT X S10
PAYLOAD INPUTSNAP X S10 CM=0X10 CS=0 CK=0 CC=3 DIF=1
PAYLOAD INPUTSNAP NEXT X GIC
PAYLOAD INPUTSNAP X GIC G616=1 R616=0X100 G834=1 R834=0X80000000 G240=1 R240=0
PAYLOAD INPUTSNAP END LOADS=132 FAULTS=0 SKIPS=0 BLK=0 CUTS=0 GAP_MS=8020 LINES=33
```
<!-- /page -->

Lines of other pages the model prints. Both engines gated in snapshot 1 and in the late blocks (every clock word stopped):

<!-- gated-lines -->
```
PAYLOAD INPUTSNAP NEXT U2
PAYLOAD INPUTSNAP U2 GATED OFF
PAYLOAD INPUTSNAP NEXT S10
PAYLOAD INPUTSNAP S10 GATED OFF
PAYLOAD INPUTSNAP NEXT S2 TLMM GCC=SAME
PAYLOAD INPUTSNAP DRIFT NONE CMP=13
PAYLOAD INPUTSNAP NEXT X U2
PAYLOAD INPUTSNAP X U2 GATED OFF
PAYLOAD INPUTSNAP END LOADS=77 FAULTS=0 SKIPS=0 BLK=0X6C CUTS=0 GAP_MS=8020 LINES=30
```
<!-- /gated-lines -->

A clock that went off during the wait (`MA0` turns off after snapshot 1 read it ON), in snapshot 2 and then in the late block:

<!-- s2gated-lines -->
```
PAYLOAD INPUTSNAP NEXT S2 GCC
PAYLOAD INPUTSNAP S2 U2 SKIP GATED OFF GCC=CHG:1
PAYLOAD INPUTSNAP NEXT S2 TLMM
PAYLOAD INPUTSNAP DG MA0=1-0X80000000
PAYLOAD INPUTSNAP DRIFT CHANGED=1 LOST=0 CMP=13
PAYLOAD INPUTSNAP NEXT X U2
PAYLOAD INPUTSNAP X U2 GATED OFF
```
<!-- /s2gated-lines -->

An abort in the UART engine (its `STATUS` word aborts: the window is silent after it, in the late block too):

<!-- abort-lines -->
```
PAYLOAD INPUTSNAP NEXT U2
PAYLOAD INPUTSNAP U2 FW=0X230 PR=2 IFD=0 ST=FAULT:6 DMA=SKIP
PAYLOAD INPUTSNAP U2 TXF=SKIP RXF=SKIP MIS=SKIP SIS=SKIP IOS=SKIP
PAYLOAD INPUTSNAP NEXT X U2
PAYLOAD INPUTSNAP X U2 CM=SKIP CS=SKIP CK=SKIP CC=SKIP TWL=SKIP TSB=SKIP RWL=SKIP STL=SKIP
PAYLOAD INPUTSNAP END LOADS=98 FAULTS=1 SKIPS=28 BLK=0X24 CUTS=0 GAP_MS=8020 LINES=33
```
<!-- /abort-lines -->

What moved during the wait (one core 2x clock, the UART engine's `STATUS`, the touch interrupt line's level); the page is then full and the third late block is left out (`BLK` bit `0x80`):

<!-- drift-lines -->
```
PAYLOAD INPUTSNAP NEXT S2 U2 GCC=CHG:1
PAYLOAD INPUTSNAP DU ST=0-1
PAYLOAD INPUTSNAP DT L51=0-1
PAYLOAD INPUTSNAP DG C20=1-3
PAYLOAD INPUTSNAP DRIFT CHANGED=3 LOST=0 CMP=19
PAYLOAD INPUTSNAP NEXT X U2
PAYLOAD INPUTSNAP NEXT X S10
PAYLOAD INPUTSNAP END LOADS=123 FAULTS=0 SKIPS=0 BLK=0X80 CUTS=0 GAP_MS=8020 LINES=34
```
<!-- /drift-lines -->

### How to read it

Every line starts `PAYLOAD INPUTSNAP `. Line 1 is `READ ONLY EL=2`, the counter frequency and the gap; line 2 is the key. A block is its `NEXT <block>` line and then one to a few lines of
`KEY=VALUE` words, in the order of the [register table](SP11-PAYLOAD-INPUTSNAP-REGISTERS.md#the-register-table); a value below 10 is one digit, a larger one `0X` and the fewest upper-case hex digits.
A group of words that belong together starts a new line, and a field that does not fit on a line is dropped and counted in `CUTS`, never cut in half. Snapshot 2 is announced by
`NEXT WAIT 8 S`, reads again only the words the table flags (the 11 clock words, six of the UART engine's, the two pin levels: 19 loads), says what it found in GCC on the next `NEXT`
line, and prints **what moved** as drift lines, not as a second page. The late blocks follow the drift summary: 27 more loads, once.

* `PR` is the protocol (bits 15:8 of `FW`), `M` and `S` are bits 0 and 12 of `ST`, `TXN` and `RXN` the word counts of `TXF` and `RXF`, `CTS` bit 1 of the UART engine's `IOS` (low is
  asserted); printed only when the word they come from was read, and `TXN`, `RXN` and `CTS` only when their mode words say they hold (`ODD` otherwise).
* `E240`, `P240`, `G240` are the interrupt's enable, pending and group bits, `C240` its two-bit configuration field and `R240` its 64-bit routing register (likewise `E616`, `C616`,
  `R834`...). `CTL` and `TYP` are `GICD_CTLR` and `GICD_TYPER`. `F8=` is the CFG word of gpio8 and `L8=` its IN_OUT word.
* `DU`, `DT` and `DG` are the drift lines of the UART engine's words, of the pins and of the clock words, in that order: `KEY=OLD-NEW`, where `NEW` may be `FAULT:6` or `SKIP`.

### Every token, and what to do

Every token the payload can print has a row; a row says what the token means and what follows from it. The test `python3 tools/test-q1n1-sp11-payload-inputsnap.py` derives the tokens from the
payload's own strings and from the pages of every scenario of the host model (and of the build with a smaller wait bound), and fails for a token with no row. A reading of the film is
INFERRED until a run shows it. Whatever the film shows, the payload wrote nothing.

| Token | What it says | Then |
| --- | --- | --- |
| `.ON` | a clock word with `CLK_OFF` clear, or the NoC FSM saying ON (cb:63, cb:64-65, cbc:54-57): the clock runs (INFERRED: the word is the only evidence) | nothing |
| `.OFF` | `CLK_OFF` set with no FSM verdict and no hardware gating: stopped; an engine it gates prints `GATED OFF` | not clocked at the hand-off: stop (bringing a clock up is a write) |
| `.HW` | `CLK_OFF` set with `HW_CTL` set, on one of the four AHB clocks only (cbc:72): hardware gating, no verdict in the word; the engine is read only if the clock's vote bit is set (vote evidence) | nothing; with the vote clear or unread the engine prints `GATED OFF` or `GATED ERR` |
| `.ODD` | an all-ones clock word, what a failed read returns: no clock word is; unknown, never "stopped"; an engine it gates prints `GATED ERR` | the window answers all ones: see its other words |
| `FAULT:6` | the guarded load aborted (the ABI's code 6) | the window, in GCC the group, is silent after it (`SKIP`). On the first word of a block: not reachable at EL2, or not clocked (INFERRED). On a later word: the words before it read, so it is that word. Nothing is retried |
| `SKIP` | not read: an earlier load of its window (in GCC: its group) aborted; in a drift line, the new value could not be read | find the `FAULT:6` before it |
| `GATED OFF` | `<engine> GATED OFF`, and `X <engine> GATED OFF` in the late block: a clock word of the engine read and says stopped, or says `.HW` while its vote bit is clear; its window was not read | stop: not clocked |
| `GATED ERR` | the same line with `ERR`: a clock word did not read (abort, skip, never read) or read as all ones, or says `.HW` while its vote word did not read, or all three vote words read zero (a window of zeros), and none says stopped: the state is unknown and the window was not read; never called `OFF` | read the clock words' own cells |
| `S2 <window> SKIP GATED OFF` | in snapshot 2 the same decision on snapshot 2's own words: the window is not visited and not compared | a clock went off during the 8 s |
| `S2 <window> SKIP GATED ERR` | the same, a clock word could not be read after the wait | read the clock words' own cells |
| `GATED` | as a cell (`ST=0-GATED`): the load itself refused what the window's decision allowed; no scenario of the model reaches it | a payload defect: stop and report |
| `ODD` | `TXN`, `RXN` or `CTS` whose mode words do not say the decode holds (a FIFO count needs `IFD` bit 0 and `DMA` bit 0 both 0, `CTS` needs `PR=2`), or did not read | read the raw word on the line before |
| `BUDGET` | a load past the payload's own cap of 400 was not made | unreachable in the shipped build (132 loads at most) |
| `NA` | no value though the word was neither read nor skipped (an address the table gets wrong) | a payload defect |
| `CUTS` | `CUTS=<n>` on the end line: n fields or lines did not fit the 34 lines of the page; they were read, not printed | boot the stick again with this payload alone, or read the UART mirror |
| `MORE` | `MORE=<n>` on the drift summary: n drift items did not fit | as `CUTS` |
| `DRIFT NONE` `DRIFT CHANGED` | the drift summary: nothing moved, or `CHANGED=<n> LOST=<n>` words differ or could not be read; `CMP=<n>` is how many were compared | the lines above it say which |
| `GCC=SAME` `GCC=CHG:<n>` | on the `NEXT S2` line after GCC: n clock words differ or could not be read, said there so that a page with no room for the drift lines still has it | as the drift summary |
| `DU` `DT` `DG` | drift lines: the UART engine's words, the pins, the clock words, `KEY=OLD-NEW` | the engine and the pins are what run A and run B compare |
| `S2 SKIPPED NO_COUNTER` | the counter is absent, stands still for 2 million reads or runs backwards: no wait was made, so no snapshot 2 and no drift report | the late blocks still follow |
| `S2 SKIPPED SPIN` | the counter runs, but 2^32 - 1 reads of it did not reach 8 s (it is far slower than `CNTFRQ_EL0` says): the wait is cut, so no snapshot 2 | the counter's rate is in question, not the engines |
| `BLK` | `BLK=<hex>` on the end line: a bit per block with a missing value (GCC 1, GIC 2, U2 4, S10 8, TLMM 0x10, X U2 0x20, X S10 0x40, X GIC 0x80), or left out for lack of room | the bit names the block |
| `DEFAULT` | after `HZ=`: `CNTFRQ_EL0` is outside 1 MHz to 1 GHz and 19.2 MHz was assumed: the 8 s may not be 8 s | `GAP_MS` cannot show it (same counter) |
| `SKIPPED_NOT_AT_EL2` `REFUSED_NO_LOAD32` | the one-line pages: not at EL2, or the runner gave no guarded load; nothing was read | the stick is not the one in the record |
| `NEXT <block>` | the last line of a page that stops there: that block was being read when the page stopped (a hang, an SError, a reset or a dark panel); `NEXT WAIT 8 S` and `NEXT S2 <window>` are the same for the wait and snapshot 2 | the word that hung is in that block; read nothing else of it before the record says why |
| `END` | the end line: `LOADS FAULTS SKIPS BLK CUTS GAP_MS LINES`; `GAP_MS` is the gap on the payload's own counter | |
| `no END line` | the page stopped before the end: a hang, a reset, a blackout or the film ended (the UART mirror, if there is one, has more) | the `NEXT` line it stopped at |
| `q1n1 fault page` | a fault page or a reset after the `END` line: not one of the payload's own loads (those return a code): INFERRED to be an SError that a load posted and q1n1 took after the payload returned (the payloads run with `DAIF` 0x3C0, OBSERVED on the unit's page) | not a finding about a word; record it |
| `recovery` | the payload wrote nothing: there is nothing to undo | boot the stick again; the runner loads the payloads afresh |
| `Gate A` | the UART engine is reachable and left configured after the hand-off: `PR=2`, `IFD=0`, `DMA=0`, every clock word `.ON` (`.HW` on the AHB clocks) and a FIFO or status word that moves with no drain; for the SPI engine the same clocks and a `PR` other than 0 and 255. **Premise, OBSERVED (the operator's own report, one unit, 2026-11-18 00:32, no photo; not a measurement of this payload): the attached Type Cover keyboard types in the Surface UEFI** (shell or setup menu not stated; touch and pen not reported: UNKNOWN). INFERRED from it, through the INFERRED path of the keyboard behind the SAM device on `uart2`: the firmware drives that link at that time (clocks, pins, wake line), so the engine is not permanently off. UNKNOWN: that any of it survives ExitBootServices and the bounce (some firmware drivers stop their device in an ExitBootServices callback): that is what the page reads | `GATED`, a gate word `.OFF` or `.ODD`, or `FAULT:6`: not reachable after the hand-off though driven before it: stop and ask |

### Reading the film

The answers the film can give, in the order to look (INFERRED from the design note and the pinned files; none is a finding until a run shows it): **Gate A**, the engine is reachable
and left configured (its premise is in the `Gate A` row above): `PR=2`, `IFD=0`, `DMA=0`, every clock word `.ON` and a FIFO count or status word that moves with no drain, for the UART
engine; the same clocks and `PR` other than 0 and 255 for the SPI engine. `GATED OFF` or `GATED ERR`, or a gate word `.OFF`: not clocked after the hand-off (stop and ask: bringing a clock
up is a write, and every write needs authorisation). `PR=255`: no protocol firmware (stop). Another protocol on the UART engine: not the UART (stop). `FAULT:6` on an engine word: the
window is not mapped at EL2. `ST`, `TXN`, `RXN` or `MIS` moving with no host action: something still drives the engine (the firmware's receive armed, DMA): settle ownership first.
`CTS=0` with the cover attached and `CTS=1` detached would say the embedded controller drives the line. `E616`, `P616`, `G616` and `R616` say whether the firmware left the UART's
interrupt enabled and where it routes. `L91` (and `N91`, `S91`) is the Surface Aggregator's wake line, `L51` the touch interrupt line.

**Film for at least 2 minutes after `PAYLOAD CALL`, and for 10 minutes if there is no `END` line**, also after `END`: boot 16 went dark about 62 s on its payload's own clock (stick log section 16 of the
Snapintosh tree), so a blackout that comes later is a result too (the cause would still be UNKNOWN); and a slow counter can hold the page at `NEXT WAIT 8 S` for the whole 2^32 - 1 read bound of
the wait, 43 s to 2 min at 10 to 30 ns a read (INFERRED), which is not yet a hang.

**Read `HZ=0X124F800` (19.2 MHz) on the film**: another value, or `DEFAULT` after it, means the wait is not 8 s of real time (a counter slower than `CNTFRQ_EL0` says stretches it),
and `GAP_MS` cannot show that, being measured on the same counter.

**Rows.** The region does not scroll: a line past its last row is mirrored to the UART but not drawn, so a page can be cut on the film although the payload finished. The region is computed at
about 89 rows, and the film of boot 29 held 73 (OBSERVED, one unit: the runner's lines, the thermal page and this page to its `END`), but no run has shown 89, and the most any earlier boot showed
is 58 with 52 legible (INFERRED to be the limit of a smaller layout): at 58 rows a chain of `tsnap` and this payload would show this page's first 16 lines and at 52 only 10, with the pin
controller, snapshot 2, the late blocks and `END` missing. If `END` is not on the film but the runner's `UPTIME` heartbeat counts after the chain, the run finished and the page was cut: run
`INPUTSNP.BIN` alone in a boot of its own (the 39-row contingency, S0c); if `UPTIME` stays at 0 S, it hung.

## Chaining it in front of the xHCI payloads

The runner calls the payloads of a manifest in **manifest order**, each once, and what a payload returns never stops the chain ([SP11-PAYLOAD.md](SP11-PAYLOAD.md#the-chain-several-payloads-in-one-boot)).
`inputsnap` is read-only, so it goes **first** and a payload that writes goes last: a payload that may stall the board goes last, and once the board resets every earlier line is gone
unless the screen is filmed within seconds. **The stick name is `INPUTSNP.BIN`, not `INPUTSNAP.BIN`**: the runner's stick names are 8.3 (so that no FAT long-name alias is in question), `inputsnap`
has nine letters, and the manifest tool refuses `inputsnap.bin` (`cannot be a stick name`; the test `test_the_stick_name_is_inputsnp_because_the_runners_names_are_8_3` pins that). The copy that
goes on the stick is the same bytes under an 8.3 name; the payload, its page prefix `PAYLOAD INPUTSNAP` and this document keep the name `inputsnap`. Build, copy, then make the stick tree (the
tool keeps the order it is given; at most five files; `INPUTSNP.BIN` and `XHCI0.BIN` are two of them):

```sh
make -f platform/uefi/Makefile payloads
cp build/uefi/payloads/inputsnap.bin build/uefi/payloads/inputsnp.bin
python3 tools/sp11_payload_manifest.py --out-dir build/stick-inputsnap build/uefi/payloads/inputsnp.bin build/uefi/payloads/xhci0.bin
```

writes `build/stick-inputsnap/SP11/PAYLOAD.MAN` and the capitalised copies `INPUTSNP.BIN` (manifest index 0, called first) and `XHCI0.BIN` (index 1, last); `xhci1.bin` is taken the same way.
The page budget of the chain, from the runner's planning table ([SP11-PAYLOAD.md](SP11-PAYLOAD.md#the-chain-several-payloads-in-one-boot)) and the two payloads' own figures (the sample page
above; [SP11-PAYLOAD-XHCI.md](SP11-PAYLOAD-XHCI.md#the-page)):

<!-- inputsnap-chain-budget -->
| Item | Nominal | At most |
| --- | --- | --- |
| `LOADED` for each of the two files and `READY` (files + 1) | 3 | 3 |
| `VERIFY`, `CALL`, `DONE` for each of the two payloads | 6 | 6 |
| `inputsnap` | 33 | 34 |
| `xhci0` or `xhci1` | 19 | 40 |
| total | 61 | 83 |
| panel region of the unit's 2880 x 1920 panel | 89 | 89 |
<!-- /inputsnap-chain-budget -->

At the worst both payloads print all their lines and the chain is 83 of the panel's 89 rows (INFERRED: "about 89", from the layout function), six to spare; nominally it is less. The six rows are
what the line cap of 34 buys: the cost, measured above, is that the widest page loses fields (`wide_cuts`), a page where everything moves keeps few drift lines (`MORE=`) and a late block is the
first thing a full page leaves out. A line past the last row is mirrored to the UART but not drawn, so if the end of `xhci0`'s page must be certain to show, run `inputsnap` **alone** in a boot
of its own. Either way this document authorises no run: a stick with `INPUTSNP.BIN` in front of `XHCI0.BIN` is another file set and manifest than any approved record's, and needs its own
record and the operator's approval of the SHA-256 of each file (one hardware client, AC power or at least 50 % battery, AGENTS.md of the Snapintosh tree).

## Safety rules, each with the seeded bug that must be refused

| Rule | How it is kept | Seeded bugs (`tools/sp11_payload_inputsnap_mutants.py`) the suites must reject, each for its own reason |
| --- | --- | --- |
| no store but to the payload's own stack | no store sink exists in the source; the IR audit demands no `inttoptr`, an alloca or parameter root for every store, memset and memcpy, and no pointer kept in memory or returned from a call into a callee; the binary check (`read_only`) proves every store from the disassembly; the host test traps any access that reaches a device window without `load32` | `store-to-window`, `store-through-args`, `writable-global`, `unguarded-load` |
| only the registers of the table, in the window and at the offset the pinned files give, from the window of its own block; never a FIFO window, gpio44-47 or gpio238 | the host test holds every load to its own list of (window, offset), written apart from the payload, and the loads of a run to exactly that list; the pinned-copy test reads each offset by name, derives the interrupt and pin words and checks every window's base against the device tree; the read primitive is called on its own with a window number, an offset past its window and an unaligned one, and must refuse before it loads | `fifo-window-read`, `tlmm-reserved-pin`, `gcc-offset-drift`, `engine-offset-drift`, `gic-offset-drift`, `pin-offset-drift`, `window-base-gcc`, `window-base-gic`, `window-base-u2`, `window-base-s10`, `window-base-tlmm`, `window-swap-engines`, `block-window-swap`, `rd32-window-unchecked`, `rd32-range-unchecked`, `rd32-alignment-unchecked` |
| every bit position, mask and flag is the pinned files' | the pinned-copy test evaluates the BIT and GENMASK macros and compares each shift, mask and window; the host test pins the decodes bit by bit and the hardware-gating flag of each clock | `field-shift-drift`, `icfgr-width-drift`, `hwcg-flag-drift` |
| a `NEXT` line before every block, in the page's order, the pin controller last of snapshot 1, and the first load of a block a word Linux reads | the model checks the last line at the first load of each block, that no lower block follows a higher, and the register each block starts with; a block whose `NEXT` cannot be printed is not read | `no-next-line`, `no-next-late-block`, `no-next-wait`, `no-next-s2`, `read-without-next`, `tlmm-before-gcc`, `first-load-no-precedent` |
| the words no pinned driver reads come after snapshot 2 and its drift report, each block under its own `NEXT`, and only if the page has room for them | the model keeps its own list of those words, rejects one read in snapshot 1 or 2 and a Linux-read word read late; the late blocks are checked on the page that has one line to spare | `late-before-s2`, `drift-after-late`, `late-read-without-room`, `s2-reads-unlisted` |
| an abort ends its window (in GCC: its group of words); nothing is retried; snapshot 2 does not visit it | the model rejects any load in a window (a GCC group) after an abort in it, and an aborted window has no `NEXT S2` line and no value in the drift report | `retry-after-fault`, `dead-window-ignored`, `gcc-dead-window-wide` |
| an engine whose clock words are not all read ON is not read, in any snapshot or late block (an AHB clock that says only `.HW` counts with its vote set; three vote words that read zero gate every engine); an unread word counts as stopped but is never called off; a hang keeps what was printed | the model keeps its own record of this snapshot's clock words and of snapshot 1's vote words and rejects any load of an engine they do not all clear, naming the word and the vote; a gated engine is one line; each line goes out before the loads of the row that starts the next; the load-level check is called on its own | `gate-removed`, `gate-fails-open`, `gate-ignores-hwcg-flag`, `gate-ignores-all-ones`, `gate-err-says-off`, `gate-roles-swapped`, `s2-gating-removed`, `late-gates-on-snapshot-1`, `s1-gated-line-lost`, `stream-read-then-print`, `hw-gate-needs-no-vote`, `hw-unread-vote-counts-as-a-vote`, `hw-clear-vote-says-unknown`, `hw-set-vote-says-unknown`, `hw-vote-bit-of-ma0-is-7`, `hw-vote-bit-of-sa0-is-6`, `hw-vote-bit-of-ma1-is-19`, `hw-vote-bit-of-sa1-is-22`, `hw-vote-word-of-ma1-is-vt0`, `hw-vote-word-of-sa1-is-vt2`, `zero-votes-open-the-gate`, `zero-rule-asks-vt0-only`, `zero-rule-ignores-vt2`, `zero-rule-uses-and`, `zero-rule-counts-unread-votes`, `s2-gate-takes-votes-from-snapshot-2`, `late-gate-takes-votes-from-the-gate-snapshot`, `read-row-gate-removed` |
| every snapshot-2 load follows its `NEXT S2` line, reads a word the snapshot-2 list names, and what GCC said is on that line | the model checks the last line at every load of snapshot 2 and its own list; the drift report compares only what was visited | `drift-counts-s2-skipped-window`, `s2-note-dropped` |
| a 64-bit register is two 32-bit loads, low then high | the model rejects a high word not read right after its low word and a low word without its high word | `wide-high-word-first` |
| at most 34 lines and 400 loads, the end line whenever the payload gets to the end | every run is checked for both caps, the ABI limits and the `END` line; smaller line and load caps are built too; the line cap is called on its own at its boundary | `line-overflow`, `closing-crowded-out`, `load-cap-ignored`, `emit-cap-off-by-one` |
| the decodes are the page's own, and a decode says `ODD` when its mode words do not hold | the golden page of the fixture; `.ON`, `.OFF`, `.HW` and `.ODD`; the abort prints its code; the mode words are flipped one at a time | `cbcr-polarity`, `fault-code-lost`, `cts-mode-unchecked`, `fifo-mode-unchecked` |
| one wait of 8 s, bounded by 2^32 - 1 reads, and a bound that is hit says so | the model counter measures the gap; a counter that does not run, runs backwards or is absent says `NO_COUNTER`; a slow counter and a smaller bound say `SPIN` | `wait-zero`, `unbounded-wait`, `spin-bound-too-small`, `spin-bound-says-dead`, `dead-counter-says-spin` |
| nothing is read below EL2 | the model sets CurrentEL; one line and no load otherwise | `el-check-dropped` |
| no system register but CurrentEL and CNTFRQ_EL0, no `smc`, no barrier | the model rejects any other; the policy checks the binary and refuses the other payloads' binaries | (the policy) |

## Tests

| Command | What it shows |
| --- | --- |
| `python3 tools/test-q1n1-sp11-payload-inputsnap.py` | `Harness`: the native host test under ASan and UBSan at the shipped caps (the suites `table`, `unit`, `decode`, `gate`, `gate2`, `drift`, `note`, `stream`, `order`, `faults`, `faults2`, `faults3`, `wide`, `storm`, `counter`, `spin`, `el`, `budget`), with smaller line and load caps (`caps`) and with a smaller wait bound; `CompiledCode`: two builds byte for byte the same, the `inputsnap` policy on the binary, the IR store audit with faulty IR it must reject, the stack depth, the manifest tool; `Mutants`: 82 seeded bugs of the payload and 1 seeded bug of this document (the outcome table without the row of `S2 SKIPPED SPIN`); `Doc`: this document and its register companion |
| `python3 tools/test-q1n1-sp11-payload-inputsnap-refs.py` | the pinned copies: every digest, every citation of both documents at its line, every offset of the register table by name, the interrupt words derived from the interrupt numbers, the pin words from the pin controller's layout, every shift and mask against the BIT and GENMASK macros, the windows, every read and write the table of "Which words Linux reads" cites, and no read of a late word in the driver files (a SKIP, never a pass, without the copies) |
| `python3 tools/test-q1n1-sp11-payload-qemu-inputsnap.py` | QEMU/EDK2 at EL2: `inputsnap` alone and after `state`, the page under QEMU ([What QEMU shows](#what-qemu-shows)) |
| `python3 tools/test-q1n1-sp11-payload-build.py` | builds every payload that has a policy; this payload's own policy is registered by `tools/sp11_payload_inputsnap_audit.py`, so that no shared table is edited |

The host test cannot show what the binary does on a core, what the registers hold, or whether a load hangs the bus; QEMU cannot show the unit's windows.

## What QEMU shows

QEMU's EDK2 shell (`virt,virtualization=on`, `-cpu max`, TCG) boots the runner with `INPUTSNP.BIN` alone and after `state`, at a real EL2 after a real ExitBootServices (EXPERIMENTAL; QEMU is
not the unit). OBSERVED there: the clock controller's window and the two engines' windows lie in the machine's flash, so the clock words are the firmware's bytes (and which engine is
gated is theirs to say: the test derives it from the words the page printed and holds the page to it), an engine window that is read aborts at its first load, the GIC window answers all ones
and the pin controller's window is a hole whose first load aborts, so that the rest of its block is `SKIP`. The page, the runner's counters, the 8 s gap on the real counter, the font and
the 34-line cap agree, nothing is retried, the late blocks come last and no file of the stick changes. The lines below are what QEMU printed, without the lines that depend on the flash
bytes (`GCC`, `U2`, `S10`, `X U2`, `X S10` and the snapshot-2 lines of an engine) and with placeholders for the frequency, the compared count and the counts of the end line; the test
compares them:

<!-- qemu-lines -->
```
PAYLOAD INPUTSNAP READ ONLY EL=2 HZ=<HZ> GAP=8 S
PAYLOAD INPUTSNAP KEY=VALUE FAULT:6=ABORT SKIP=AFTER ONE GATED=NOT READ ODD=DECODE NOT VALID
PAYLOAD INPUTSNAP NEXT GCC
PAYLOAD INPUTSNAP NEXT GIC
PAYLOAD INPUTSNAP GIC CTL=0XFFFFFFFF TYP=0XFFFFFFFF
PAYLOAD INPUTSNAP GIC E616=1 P616=1 C616=3 E834=1 P834=1 C834=3 E240=1 P240=1 C240=3
PAYLOAD INPUTSNAP NEXT U2
PAYLOAD INPUTSNAP NEXT S10
PAYLOAD INPUTSNAP NEXT TLMM
PAYLOAD INPUTSNAP TLMM F8=FAULT:6 L8=SKIP F9=SKIP L9=SKIP F10=SKIP L10=SKIP F11=SKIP L11=SKIP
PAYLOAD INPUTSNAP TLMM F91=SKIP L91=SKIP N91=SKIP S91=SKIP F40=SKIP L40=SKIP F41=SKIP L41=SKIP
PAYLOAD INPUTSNAP TLMM F42=SKIP L42=SKIP F43=SKIP L43=SKIP F51=SKIP L51=SKIP N51=SKIP S51=SKIP
PAYLOAD INPUTSNAP TLMM F48=SKIP L48=SKIP F64=SKIP L64=SKIP F2=SKIP L2=SKIP
PAYLOAD INPUTSNAP NEXT WAIT 8 S
PAYLOAD INPUTSNAP NEXT S2 GCC
PAYLOAD INPUTSNAP DRIFT NONE CMP=<N>
PAYLOAD INPUTSNAP NEXT X U2
PAYLOAD INPUTSNAP NEXT X S10
PAYLOAD INPUTSNAP NEXT X GIC
PAYLOAD INPUTSNAP X GIC G616=1 R616=0XFFFFFFFFFFFFFFFF G834=1 R834=0XFFFFFFFFFFFFFFFF G240=1
PAYLOAD INPUTSNAP X GIC R240=0XFFFFFFFFFFFFFFFF
PAYLOAD INPUTSNAP END LOADS=<L> FAULTS=<F> SKIPS=<S> BLK=<B> CUTS=<C> GAP_MS=<MS> LINES=<N>
```
<!-- /qemu-lines -->

What that proves: the binary runs at EL2 behind the runner, keeps its stores on its own stack, announces every block, waits its 8 s on the real counter, decides the gating the way the words
say, reads no more of a window that aborted and fails closed on the hole. What it does not: anything about the unit's windows (UNKNOWN; hardware NOT RUN).

## Hazards

* **H0.** A read of an engine whose clocks are stopped can hang the bus, and no guard recovers a hang. The gate is what keeps the payload from making that read; it can only be as
  good as the words it reads (a wrapper-level clock the firmware enabled by a path these words do not show is INFERRED to be possible and is not excluded).
* **H1.** The runner's `load32` catches a **synchronous** abort. An SError, and a hang, are neither caught nor printed: the panel then stops at the last line printed, which is why
  every block is announced first and every line goes out as soon as its loads are done.
* **H2.** The pin controller is read last of snapshot 1, and gpio44-47 and gpio238 are never read; which of the other pins the secure world owns is UV4.
* **H3.** Reading the GIC distributor in the non-secure view may answer zero for IGROUPR and IROUTER (UV3); the words print raw and an all-zero answer is not evidence that the
  interrupt is unrouted.
* **H4.** The film is the only channel: a panel that goes dark ends the evidence at that line. The 8 s wait is the one point where nothing is read.
* **H5.** The late blocks read words no pinned driver reads (UV7). A hang or an abort there loses only the late blocks after it; everything before is on the film already.

## Limits, and what remains before a run

The design note asked for "DIFF flags" in snapshot 2; this payload reports what moved as the drift lines `DG`, `DU` and `DT` (`KEY=OLD-NEW`) and the `DRIFT` summary: that is this
document's interpretation of the wording (there is no pair of columns here, as in the payload this one follows, so no `/` and no `DIFF` token).

Before a run: its own record and the operator's approval of the SHA-256; one hardware client; AC power; the Type Cover handled as the operator decides. **run A** with the cover
attached, pressing keys inside the 8 s window; **run B** with the cover detached, otherwise the same: the two films are compared. The Type Cover check in the UEFI menu (does the attached
cover type there, does touch work there) was asked of the operator: the operator's own report of 2026-11-18 00:32 is that the attached Type Cover keyboard types in the Surface UEFI
(OBSERVED as a report, one unit, no photo; shell or setup menu not stated; touch and pen not reported: UNKNOWN). That is the premise of Gate A and no more: it does not show that the state
survives ExitBootServices and the bounce, which is what the page reads. This document authorises none of it.

**What could not be verified.** UV1: the unit-specific facts of the design note: the bus, base address, interrupt and pins of each input device are decoded from the unit's own dumped ACPI tables (OBSERVED; no table bytes are in this tree) and agree with `hamoa.dtsi` and `x1-microsoft-denali.dtsi` where those say anything; no pinned file holds them. UV2: the protocol number 9 of the SPI engine (a third party reports it for QSPI; `geni-se.h` has no QSPI value, so `PR` there is read as "not 0, 1, 2, 3, 4, 5 or 255"). UV3: how the GICD registers answer a non-secure read when `GICD_CTLR.DS` is clear (IGROUPR and IROUTER may read as zero: the GIC architecture, not a pinned file; the words print raw and `GICD_CTLR` is OBSERVED as `0x10` in boots 3, 12 and 14). UV4: whether TLMM words of pins that firmware gave to the secure world read normally at EL2 (never read on the unit; an abort prints `FAULT:6` and ends the block). UV5: the meaning of the bits of `GENI_CLK_CTRL_RO`, `SE_GENI_CLK_SEL`, the two serial clock configuration words, `SE_HW_PARAM_0` and `SE_HW_PARAM_1` (printed raw; `geni-se.h` defines some of their fields and the printed number is the whole word). UV6: that a read of an engine whose clocks all read ON cannot hang (INFERRED from the earlier survey payload's review: only an access to an engine whose clock is stopped is documented to; no guard recovers a hang or an SError). UV7: that no Linux driver reads the words of the late blocks: the scan covers the pinned UART, SPI, GENI core and interrupt-controller files only (the I2C, I3C and QSPI drivers, and firmware, may read them), and a word read by none of them is not thereby safe to read: it is read last, which is all the order claims.
