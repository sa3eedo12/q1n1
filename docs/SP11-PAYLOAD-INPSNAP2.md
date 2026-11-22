<!-- SPDX-License-Identifier: MIT -->
# Payload `inpsnap2`: a read-only look at what the keyboard link's UART clock needs

**Status: EXPERIMENTAL; hardware NOT RUN.** `payloads/inpsnap2.c` (stick file `INPSNAP2.BIN`; the name has eight letters, so the stick's name is the source's stem) is stage I0 of the input plan: the read-only
survey of the words that decide how the Type Cover link's UART engine (QUP wrapper 0, engine 2, the Surface Aggregator's serial engine at 0x00b88000, INTID 616) could be clocked later. Boot 29 (`inputsnap`) found
that engine's clock off at hand-off. Turning it on is a different stage (I1a) with its own review; it needs words nobody has read on the unit (all but six of the 44, below): whether the engine's root clock generator is a DFS clock (the flag
decides whether any word of the generator may ever be written), the eight DFS levels' words, GPLL0's state, the divider below the generator and the wrapper's version. This payload reads those words, at EL2, with plain
32-bit loads through the runner's guarded load, once each, and turns nothing on. It stores nothing but to its own stack: no write to any device, no SMC, no HVC, no barrier, no tick, no counter, no wait, no second
snapshot. The only system register it reads is CurrentEL. An independent review (2026-11-22) found the binary named in the operator's note safe for one read-only run: no blocker, no major finding, five minor ones, applied in this version of the document and of the host tools; it covers that binary only. The note and the approval of the run are separate from it (section 8).

**What has never been read on the unit.** No word of any QUP wrapper has ever been read there, so **the first read of the wrapper's version word (0x00bc0004) is of UNKNOWN risk** (section 4): it may answer,
abort (the guard shows `FAULT:6`), hang the bus or raise an SError (the guard does not catch it). It is the last load of the page and is made only behind the wrapper's gate. Of the other 43 words, five were read
in boot 29 (`MA0`, `SA0`, `CR0`, `SE0`, `VT0`: OBSERVED, one unit), one in boot 30 (`GV`, GPLL0's vote word, which `gpusnap` calls `GP0V`: `0X201`, OBSERVED, one unit) and 37 are first reads in a window that
boots 29 to 31 read other words of (UV2).

Labels (Snapintosh `AGENTS.md`): **VERIFIED** read in a pinned file or shown by a host run, never a statement about the unit; **OBSERVED** a run on the unit (boots 29 and 30 are the only ones cited; none exists for this payload);
**INFERRED**; **EXPERIMENTAL** code that exists and has not run; **UNIMPLEMENTED**; **UNKNOWN**. A SKIP is not a pass. Citations are `prefix:line` into the pinned Linux copies ([evidence document](SP11-PAYLOAD-INPSNAP2-EVIDENCE.md),
section A): `dt` hamoa.dtsi, `gcc` gcc-x1e80100.c, `cbc` clk-branch.c, `cbh` clk-branch.h, `cmn` common.c, `rcg` clk-rcg2.c, `pll` clk-alpha-pll.c, `gse` qcom-geni-se.c, `gsh` geni-se.h.

## 1. What it reads

Two windows. Every base and size is the device tree's (VERIFIED as read there; that the unit has the same windows is INFERRED).

| Window | Base | Size | Pinned source |
| --- | --- | --- | --- |
| GCC (the clock controller) | 0x00100000 | 0x200000 | `dt:758-760` |
| QUP wrapper 0 | 0x00bc0000 | 0x2000 | `dt:2141-2148` |

Engine 2 itself (`uart2`, 0x00b88000, `dt:2337-2343`) lies below the wrapper and is not read: this payload reads the engine's clock, the generator above it and the wrapper, never the engine.

44 rows in five blocks, in page order; every row is read at most once and nothing is retried. The 44 are the 41 words of the host plan's I0 survey (`python3 tools/geni_uart_plan.py reads` of the Snapintosh tree: 40 clock
controller words and the wrapper's version) and the three clock words the wrapper's gate needs (`MA0`, `SA0`, `CR0`: the word `inputsnap` v1 already reads). The test `tools/test-q1n1-sp11-payload-inpsnap2-refs.py`
(class `Plan`) derives the payload's table from its header and compares it with the plan's list, word for word, so that neither can drift from the other.

| Block | Rows | What for |
| --- | --- | --- |
| GATE | `MA0` `SA0` `CR0` `SE0` `VT0` `GV` (6) | the three clock words of the wrapper's gate (wrapper 0's two AHB clocks and its core clock), the engine's own clock word, the apps' vote word (bit 12 is the engine) and GPLL0's vote word |
| RCG | `DFS` `DIV` `CMD` `CFG` `M` `N` `D` (7) | the DFS flag of the engine's root clock generator first, then the read-only divider below it and the generator's own command, configuration, M, N and D words |
| PLL | `MODE` `OP` `ST` `L` `AL` `USR` (6) | GPLL0: mode (lock, active, output enable), operating mode, status, L, alpha, user control (the OUT_EVEN post divider) |
| LVL | `LC0`-`LC7` `LM0`-`LM7` `LN0`-`LN7` (24) | the eight DFS levels' configuration, M and N words |
| QUP | `VER` (1) | the wrapper's version word |

**Order, which is the order of what one abort or hang costs.** The clock controller's 43 words are read unconditionally, block by block (boots 29 to 31 read other words of the window: OBSERVED to answer; that these words
answer is UV2). The wrapper's one word is last and only behind proof that the wrapper's clocks run (`wrapper_gate()`, section 4.2). Every block is announced by a `NEXT <block>` line before its first load and is not read at
all if that line cannot be printed, and every data line is read whole and printed before the first load of the next, so a hang keeps every line before the one it hit and the last line on the panel names the block. The
first all-ones word ends the page (a bus fault suspicion: print what was read, read no more). The first abort in a block ends the reads of that block; the other blocks go on.

## 2. The page

At most 24 lines of at most 100 characters, the payload's own prefix `PAYLOAD INPSNAP2 ` included (the ABI allows 40 lines and 4096 loads; this payload keeps to 24 lines and 44 loads). A nominal page is 21 lines and 44 loads
(`tools/test-q1n1-sp11-payload-inpsnap2.c`, `--numbers`):

<!-- numbers -->
rows 44
loads_max 44
page_lines_max 21
line_cap 24
load_cap 44
unit_lines 21
unit_loads 44
gateoff_lines 21
gateoff_loads 43
stop_lines 8
stop_loads 8
ones_lines 5
ones_loads 1
<!-- /numbers -->

The sample below is the page of the host model's made-up fixture, **not the unit's page**. What the unit showed (boot 29, OBSERVED) is `MA0=0.ON SA0=0.ON CR0=0X4000.ON SE0=0X80004000.OFF VT0=0X810223D0`; every other
value is the fixture's. The check `K=` of each line is the CRC-16/CCITT-FALSE of five bytes a word (the word's state, then its value least significant byte first) and was confirmed against Python's `binascii.crc_hqx`
([evidence document](SP11-PAYLOAD-INPSNAP2-EVIDENCE.md), section D shows the gated, stop and abort pages).

<!-- page -->
```
PAYLOAD INPSNAP2 READ ONLY EL=2 STAGE=I0 CAP=44/24
PAYLOAD INPSNAP2 KEY=VALUE .ON .OFF .HW .ODD=CLOCK FAULT:6=ABORT SKIP=NOT READ K=LINE CRC16
PAYLOAD INPSNAP2 NEXT GATE
PAYLOAD INPSNAP2 GATE MA0=0.ON SA0=0.ON CR0=0X4000.ON K=3886
PAYLOAD INPSNAP2 GATE SE0=0X80004000.OFF VT0=0X810223D0 GV=1 K=710E
PAYLOAD INPSNAP2 NEXT RCG
PAYLOAD INPSNAP2 RCG DFS=0 DIV=0 CMD=0 CFG=0X2601 K=EA31
PAYLOAD INPSNAP2 RCG M=0X10 N=0XFFC4 D=0XFFB4 K=FF54
PAYLOAD INPSNAP2 NEXT PLL
PAYLOAD INPSNAP2 PLL MODE=0XC0000005 OP=1 ST=0 K=85B3
PAYLOAD INPSNAP2 PLL L=0X1F AL=0X4000 USR=0X401 K=2415
PAYLOAD INPSNAP2 NEXT LVL
PAYLOAD INPSNAP2 LVL LC0=0X2601 LC1=0X2602 LC2=0X2603 LC3=0X2604 K=FF76
PAYLOAD INPSNAP2 LVL LC4=0X2605 LC5=0X2606 LC6=0X2607 LC7=0X2608 K=9911
PAYLOAD INPSNAP2 LVL LM0=0X10 LM1=0X11 LM2=0X12 LM3=0X13 K=30CA
PAYLOAD INPSNAP2 LVL LM4=0X14 LM5=0X15 LM6=0X16 LM7=0X17 K=D36E
PAYLOAD INPSNAP2 LVL LN0=0XFFC4 LN1=0XFFC3 LN2=0XFFC2 LN3=0XFFC1 K=F5F7
PAYLOAD INPSNAP2 LVL LN4=0XFFC0 LN5=0XFFBF LN6=0XFFBE LN7=0XFFBD K=C82D
PAYLOAD INPSNAP2 NEXT QUP
PAYLOAD INPSNAP2 QUP VER=0X20050000 K=60CA
PAYLOAD INPSNAP2 END LOADS=44 FAULTS=0 SKIPS=0 BLK=0 CUTS=0 LINES=21 STOP=NONE
```
<!-- /page -->

A value below 10 is one digit, a larger one `0X` and the fewest upper-case hex digits (the runner's own formatter). A branch clock word carries a verdict after its value: `.ON` (CLK_OFF, bit 31, clear, or the NoC FSM
status, bits 30:28, equal to 2: how Linux reads a branch that is being enabled, `cbh:63-65`, `cbc:43-60`; a voted branch's CLK_ENABLE bit stays clear while it runs, so a word of 0 is a running clock), `.OFF`, `.HW`
(CLK_OFF set, no FSM verdict, and the clock declares a hardware gating bit with HW_CTL, bit 1, set: Linux does not wait for the halt bit of a hardware-gated branch, `cbc:17-27`, `cbc:62-74`; only the two AHB clocks have
it) or `.ODD` (all ones, what a failed read returns, which no clock word is).

### What each line says

- `READ ONLY EL=2 STAGE=I0 CAP=44/24`: the payload's own statement: it is read-only, it runs at EL2, it is stage I0, and its caps are 44 loads and 24 lines. `KEY=VALUE ...`: the legend.
- `NEXT <block>`: printed before the block's first load. The last `NEXT` line on the panel names what hung.
- A data line: the head of its block and one to four `KEY=VALUE` words, then ` K=` and four hex digits: the check of the line. A transcription of the film is checked against it
  (`tools/sp11_inpsnap2_parse.py` of the Snapintosh tree, which turns the page into the words the host plan consumes and refuses a page that does not add up; its `--partial` flag reads a page that stops without its `END` line after
  a hang, line by line with the same checks and no counters, and the plan then stops by itself on the first word that is missing).
- `END LOADS=<n> FAULTS=<n> SKIPS=<n> BLK=<mask> CUTS=<n> LINES=<n> STOP=<key|NONE>`: the loads made, the aborts, the words not read (after an abort in the block or an all-ones word), the blocks that were not read
  whole (bit 0 GATE to bit 4 QUP), the lines cut for want of room, the lines printed (the end line included) and the key of the first all-ones word.

| Token | What it says |
| --- | --- |
| `KEY=VALUE` | the word at the row's address as the load returned it, number format above; no word is shown by anything but its own load |
| `.ON` | a branch clock word whose clock runs: CLK_OFF clear or FSM status 2 |
| `.OFF` | a branch clock word that says stopped. On the engine's own clock `SE0` that is what boot 29 found (OBSERVED) and what this survey was made for; on a wrapper clock it gates the wrapper |
| `.HW` | an AHB clock in hardware gating mode with no halt verdict: the vote bit in `VT0` (6 for `MA0`, 7 for `SA0`) decides whether the wrapper's gate counts it as running |
| `.ODD` | all ones: a failed read, never a clock word. It ends the page (`STOP=<key>`) |
| `FAULT:6` | the load aborted (the runner's guard returned the code; the code is printed). The rest of the block is `SKIP`; the other blocks are read. UNKNOWN on the unit |
| `SKIP` | the word was not read: after an abort in its block or after an all-ones word |
| `BUDGET` | the payload's own load cap was spent (never at the shipped caps: 44 rows, 44 loads) |
| `NA` | the row has no state: a defect of the table, never at the shipped table (the host test calls the printer on it) |
| `K=` | the CRC-16/CCITT-FALSE of the line's words, four hex digits |
| `NEXT <block>` | the announcement of a block: `GATE`, `RCG`, `PLL`, `LVL` or `QUP` |
| `QUP GATED OFF` | the wrapper's version word was not read because a clock word that read says a wrapper clock is stopped (or an AHB clock in hardware gating mode has no vote) |
| `QUP GATED ERR` | the wrapper's version word was not read because what its gate needs did not read, or cannot be trusted: an all-ones word, a vote word that read 0 (a window of zeros shows every branch as running) or did not read |
| `END` | the end line, with `LOADS`, `FAULTS`, `SKIPS`, `BLK`, `CUTS`, `LINES` and `STOP` |
| `BLK` | the mask of the blocks that were not read whole: bit 0 GATE, 1 RCG, 2 PLL, 3 LVL, 4 QUP; 0 for a complete page; after a stop the stop's block and every later one |
| `CUTS` | the lines (or whole blocks) cut for want of room: never at the shipped caps |
| `STOP=<key>` | the key of the first all-ones word: nothing after it was read and nothing after its line was printed. `STOP=NONE` for a page that did not stop |
| `SKIPPED_NOT_AT_EL2` | the payload runs below EL2 and read nothing |
| `REFUSED_NO_LOAD32` | the runner gave no guarded load: nothing is read (the runner returns its bad-arguments code) |
| `no END line` | the payload hung or the panel's rows ran out: read the last `NEXT` line (section 4.2) and the note |
| `q1n1 fault page` | the runner's own exception page after `END`: it names the faulting address; film it, do not retry |
| `runner VERIFY refusal` | the runner refused the file (its digest or its policy): nothing of the payload ran |

## 3. What each decision of the plan needs

The plan (the input plan's section on the UART clock, with the host tool `tools/geni_uart_plan.py` of the Snapintosh tree) decides from these words; the page shows the words and decides nothing. A decision made from a
word that is `SKIP`, `FAULT:6`, `NA` or `BUDGET`, or whose line was not printed, is UNKNOWN: the host plan stops there (`PlanError`).

| Decision | Words | Reading (VERIFIED in the pinned file; the unit's value UNKNOWN until the film) |
| --- | --- | --- |
| a DFS clock or a plain one: whether any word of the generator may ever be written | `DFS` bit 0 | `clk_rcg2_enable_dfs` reads `cmd + 0x14` and tests bit 0 (`rcg:1744-1766`); `DEFINE_RCG_DFS(gcc_qupv3_wrap0_s2_clk_src)` registers the generator as a candidate (`gcc:7409-7412`, `cmn:394-400`). DFS: no generator row is ever written; plain: the six-row sequence |
| the current DFS level | `DFS` bits 4:1 | `level &= GENMASK(4, 1); level >>= 1` (`rcg:1688-1731`) |
| the eight levels' rates | `LC0`-`LC7`, `LM0`-`LM7`, `LN0`-`LN7` | `clk_rcg2_dfs_populate_freq`: `cmd + 0x1c + 4 l`, `0x5c + 4 l`, `0x9c + 4 l`, N stored inverted (`rcg:54-60`, `rcg:1607-1650`) |
| the generator's rate now (already 64 MHz?) | `CMD`, `CFG`, `M`, `N`, `D`, `DIV` | `clk_rcg2_recalc_rate` reads CFG, M, N; the table row of 64 MHz is GPLL0 OUT_EVEN with M/N 16/75 (`rcg:26-47`, `rcg:193-227`, `gcc:1142-1153`, `gcc:1165-1172`) |
| the divider below the generator is 0 (divide by 1) | `DIV` bits 3:0 | `gcc_qupv3_wrap0_s2_div_clk_src`: `.reg = 0x42284`, shift 0, width 4, read-only ops (`gcc:2237-2250`) |
| GPLL0 locked, at 600 MHz and voted | `MODE` bit 31 (lock), bit 30 (active), `OP`, `ST`, `L`, `AL`, `USR`, `GV` bit 0 | Lucid-OLE layout, GPLL0 at offset 0 with the fixed ops, vote in `0x52030` bit 0 (`gcc:113-127`, `pll:16-34`, `pll:187-202`, `pll:719-750`; OUT_EVEN's divider at bit 10, `gcc:130-150`) |
| the wrapper's version is at least 2.5 | `VER` bits 31:28 major, 27:16 minor | `geni_se_get_qup_hw_version` reads `base + 4` (`gse:188`, `gse:299-310`, `gsh:336-344`) |
| the engine's clock is off and not voted (what boot 29 found) | `SE0`, `VT0` bit 12 | `gcc_qupv3_wrap0_s2_clk`: halt `0x42274`, voted, enable bit 12 of `0x52020` (`gcc:4434-4450`) |

## 4. Hazards, and what the order is for

### 4.1 It stores nothing

Two checks hold the sentence "it stores only to its own stack" to the compiled code, not to the source, as to the **base** of every store: the IR audit (`tools/sp11_payload_inpsnap2_audit.py`: no integer is ever turned into a pointer, the root of every store,
memset, memcpy or memmove destination is an `alloca` of the function or a pointer parameter whose callers pass the same, no pointer is kept in memory, no writable global, no atomic, no libcall) and the binary check of the
`inpsnap2` policy (the instruction allow-list: one system register, CurrentEL; no SMC, no barrier; and the `read_only` memory discipline of `tools/sp11_payload_memcheck.py`, which proves from the disassembly that
every store is through the stack and every load through the stack, the image, the arguments or a pointer they hold). **Neither proves the offset**: a store inside the stack at a wrong offset, even one past its top, passes both.
The host test's address sanitizer runs on every run, but it sees an out-of-bounds store only where the access touches poisoned memory (the redzone of a stack object), so a wrong offset inside a frame is invisible to it
too: a store 160 bytes past the context, seeded in the independent review, passed all three and is not among the 423 seeded bugs. What controls the offsets of the shipped binary is: the disassembly (the review read its
97 stores: all at fixed offsets from the stack pointer or from the context, line or value pointer, but for the loop that zeroes the context); the stack check (the deepest chain of frames is 912 bytes of the 49,152 the runner
leaves); and two emulations of the real linked binary with every write trapped, the author's (1,733 runs) and the reviewer's (5,556 runs), which found no write outside the stack (the deepest 912 bytes). The emulations are not tests
of this tree: a change that adds a store needs them run again (or an offset check added to the binary check) before its binary is trusted. The only code that touches a device is the runner's
`load32` op, called through a function pointer the payload copied from its arguments. The policy is the entry `POLICIES['inpsnap2']` of the shared `tools/sp11_payload_testlib.py`, after gpusnap2's, so that the generic payload suites cover this file;
the audit module registers the same policy at import for its own tools, and a test holds the two equal.

### 4.2 The first read of the wrapper, and what the order costs

The 43 clock controller words come first, announced block by block; the wrapper's word comes last, behind `wrapper_gate()`:

- the three wrapper clock words (`MA0`, `SA0`, `CR0`: wrapper 0's two AHB clocks and its core clock, the clocks its device-tree node names, `dt:2141-2148`, plus the core clock) must each have read and say running; a word that
  did not read, or read as all ones, is unknown and never stopped; an AHB clock that says only `.HW` counts as running only if its vote bit is set in `VT0` (the vote word read and the bit set: running; the bit clear:
  stopped; the word not read: unknown), the review of `inputsnap` v1 (finding 1);
- the vote word `VT0` must have read and be neither zero nor all ones: a window of zeros shows every branch as running, so a word of zeros is no evidence (the same review, finding 4). This is stricter than
  `inputsnap` v1.1's rule (three vote words) because this payload reads one wrapper's vote word;
- stopped wins over unknown (`QUP GATED OFF` before `QUP GATED ERR`); anything else and the version word is read.

What a stop at the version word is: a `FAULT:6` is a line (`QUP VER=FAULT:6`) and the page ends normally; a hang, a reset, a dark panel or a q1n1 exception page ends the boot at the last `NEXT QUP` line, with every line
before it on the panel (the host parser reads such a page only with `--partial`). All of them are acceptable first-run results (nothing is written; power-cycle, do not retry, send the film). **The guard has never fired on the unit**, an SError is not caught by it, and nothing
recovers a hung bus: the safety argument is the gates, the order and the bounds, not the guard. A first read in the wrapper that is skipped by the gate is not a result either: it is the question for the next run.

### 4.3 Read side effects

None of the 44 words is a FIFO, a clear-on-read or a read-to-acknowledge register on any pinned evidence: Linux reads each of them as a plain status or configuration word with `regmap_read` or `readl` (the clock words
in `cbc`, the generator's in `rcg`, the PLL's in `pll`, the version in `gse`). That is INFERRED for the unit (UV4). Not read, by construction: any engine register (the engine's FIFO ports pop bytes), the wrapper's
other words, any vote word but `0x52020` and `0x52030`.

### 4.4 The stop rule and the bounds

The first word that reads all ones ends the page after its line (later words of the line print `SKIP`, no later line or block is printed, `END` names the key): an all-ones word is what a failed read returns and no
register of this table holds it. At most 44 loads and 24 lines whatever the hardware says: every row once, every line a fixed list of at most four words; a line that has no room is not read (nothing is read that cannot be
shown), a block whose `NEXT` line cannot be printed is not read, and the end line keeps its own slot. The frame is far below the 48 KiB the ABI leaves (the test asserts it).

## 5. The chain budget

The runner prints `files + 1` lines of its own once and three per payload (`VERIFY`, `CALL`, `DONE`); the panel's region holds about 89 rows on the unit's panel (computed; never seen), and the most ever seen drawn is 73
(boot 29: 9 runner rows, `tsnap` 34, `inputsnap` 30; OBSERVED). **`inpsnap2` runs alone in its boot**: TSNAP v1.1 and GPUSNAP2 are two boots of their own too (their review: a chain of the two is 77 rows against 73
seen), and a three-payload chain would not fit. `inpsnap2` prints at most 24 lines (21 nominal):

<!-- inpsnap2-chain-budget -->
| Chain | Rows (nominal) | Rows (at most) | Against 73 seen |
| --- | --- | --- | --- |
| `inpsnap2` alone | (1 + 1) + 3 + 21 = 26 | (1 + 1) + 3 + 24 = 29 | fits, 44 to spare |
| `tsnap` v1.1 (34), then `inpsnap2` | (2 + 1) + 2 x 3 + 34 + 21 = 64 | (2 + 1) + 2 x 3 + 34 + 24 = 67 | fits, 6 to spare (not a plan) |
| `gpusnap2` (34), then `inpsnap2` | (2 + 1) + 2 x 3 + 34 + 21 = 64 | (2 + 1) + 2 x 3 + 34 + 24 = 67 | fits, 6 to spare (not a plan) |
| `tsnap` v1.1, `gpusnap2`, then `inpsnap2` | (3 + 1) + 3 x 3 + 34 + 34 + 21 = 102 | (3 + 1) + 3 x 3 + 34 + 34 + 24 = 105 | no: more rows than 89 |
<!-- /inpsnap2-chain-budget -->

A hang or a reset takes every earlier line of the same chain with it ([SP11-PAYLOAD.md](SP11-PAYLOAD.md#the-chain-several-payloads-in-one-boot)); the run is alone.

## 6. Tests

All host and QEMU only: no suite touches the unit. Environment as for the other SP11 payload suites (`tools/sp11_payload_testlib.py` finds the LLVM tools).

| Command | What it shows | What it does not show |
| --- | --- | --- |
| `python3 tools/test-q1n1-sp11-payload-inpsnap2.py` | the host program (suites below) under ASan and UBSan, at the shipped caps and with smaller line and load caps; the IR audit on the real source and on 13 hand-written faulty texts; the `inpsnap2` policy on the linked binary, and the shared table's entry against the audit module's policy; the stack depth; two builds that are byte for byte the same; the Makefile's build; the manifest tool on a chain; the 423 seeded bugs, each by the stage it names for the reason it names | anything about the unit |
| `python3 tools/test-q1n1-sp11-payload-inpsnap2-doc.py` | both documents against the header, the host model's page and numbers, the outcome table (a row for every string the payload can print), the chain budget arithmetic, the register table, the seeded-bug list and the unverified list | that a statement is true of the unit |
| `INPSNAP2_REFS_DIR=.. SNAPINTOSH_DIR=.. python3 tools/test-q1n1-sp11-payload-inpsnap2-refs.py` | every `prefix:line` of the documents and every row of the table read back BY NAME from the pinned copies (a clock word from its branch struct, the generator from its struct and the DFS macros, GPLL0 from the alpha-PLL layout it picks, the wrapper from the geni driver); the digests; the payload's table against the host plan's survey list; without the copies the ledger checks run and the rest SKIPs | anything about the unit |
| `python3 tools/test-q1n1-sp11-payload-qemu-inpsnap2.py` | the binary behind the runner at EL2 under QEMU/EDK2, alone and after `state`: the page's structure and checks, the gate re-derived by the test's own rules, the runner's counters; with `SNAPINTOSH_DIR` set, the page the real binary printed read by the host parser | any value of the unit (QEMU's flash is the clock controller's window) |

The host program's suites (`tools/test-q1n1-sp11-payload-inpsnap2.c`, `-model.h`, `-suites.inc`): `table` (the header's windows, blocks, lines, rows and flags against the harness's own list, row by row), `unit` (the page above,
line by line, every load once and in order), `decode` (the number format, the verdict of every branch clock word on every row that has one, the abort token), `crc` (the check against its published value and against a
table-driven implementation), `gate` (every clock word, vote bit and vote word of the wrapper's gate, `QUP GATED OFF` and `QUP GATED ERR`), `stop` (an all-ones word at every row in turn), `faults` (an abort at every row in
turn and in every window), `hang` (a hang at every load of several fixtures: the page so far is exactly the lines the reference prints before that load), `random` (6,000 fixtures against the reference and the rules),
`units` (the read primitive at its edges, the line cap, the clock verdict, the gate against an exhaustive 11 x 11 x 11 x 12 matrix, the number helpers at the end of a line) and `el` (not at EL2, no `load32`, bad
arguments). The model holds its **own** list of rows, its own reference interpreter of the page (a table-driven CRC and formatter) and its own rules for every load and line (alignment, one read per row, order, NEXT before
a block, a line read whole before it is printed, nothing after a stop or an abort); a wrong table or rule in the payload is a difference, not an echo.

The seeded bugs (section C of the evidence document lists every one): 423 in all, 389 refused by the host test at the shipped caps, 5 at smaller caps, 8 by the compiler's static assertions, 8 by the IR audit, 12 by the
binary policy and 1 by the stack check. About two thirds are generated from the header's text, one per row and kind (offset, key, block, window, flag, vote bit) and one per line and field. Each is an exact once-only
replacement; a needle that is not in the text exactly once is an error, never a pass. Defences with no seeded bug of their own: a second line of defence that a first one makes unreachable at the shipped table
(a line's own `emit` check behind its room test), and the mutations that change nothing observable (the width of the CRC mask: only its low sixteen bits are ever shown). The host test calls the redundant defences on their
own (`rd_at`, `read_row`, `emit`, `table_line`, `gcc_block`, `qup_block`, `put_row`, `wrapper_gate`).

QEMU shows structure only: the `virt` machine has neither window (both lie in its flash, which answers with the firmware's bytes), so every word is the flash's; the test re-derives the gate and the checks from
the words the page printed. It does **not** show a word of the unit, an abort or the guard on Oryon ([evidence document](SP11-PAYLOAD-INPSNAP2-EVIDENCE.md), section E).

## 7. What it answers, and what it does not

It answers, per word and with the unit's own values, the questions of section 3: DFS or plain, the levels, GPLL0, the divider, the generator's present setting, the engine's clock and vote, the wrapper's version, **if the
words read**. It does not answer: whether the unit's firmware keeps those words stable (it reads once), whether a write would take (nothing is written), whether the engine's registers answer once its clock is on (they are not
read: I1a), anything about the touch SPI engine, and anything the panel did not show. The generator's flag in particular says only which sequence the next stage may use; it authorises nothing.

## 8. The operator's note (nothing here authorises a run)

The note outside this tree says what to run, how to film it and what each outcome means; no document of this tree authorises a run. The first run is **alone** in its boot, on AC power or at least 50 % battery, with one
hardware client, the loader and runner EFI of boots 19 and 29 to 31, and no source edit between prepare and boot. The note lists the SHA-256 of the file and of the ELF and the runner's `LOADED` line to check first.

## 9. What could not be verified

**UV1.** Whether any word of QUP wrapper 0 (0x00bc0000, the version word at +4) can be read at EL2 on this unit: no word of any QUP wrapper has ever been read there (boot 29 found the engine clocks off and read none),
so whether a read answers, aborts (the guard turns that into `FAULT:6`), hangs the bus or raises an SError (neither is caught) is UNKNOWN.

**UV2.** Whether the first reads of the clock controller words this payload adds (the divider, the root clock generator's words and its DFS flag, the eight levels and GPLL0's own six words) answer: the window is
the one boots 29 to 31 read other words of, which is the precedent and not the proof.

**UV3.** That a running wrapper 0 AHB and core clock (the three words of the wrapper gate) is enough for the wrapper's registers to answer: Linux turns the same clocks on before it touches the wrapper
(`dt:2141-2148`), which is INFERRED to be the condition, never observed on this unit.

**UV4.** That none of the words read has a side effect on the unit: no pinned file reads any of them as a FIFO, a clear-on-read or a read-to-acknowledge word (Linux reads every one as a plain status or
configuration word), which is INFERRED for this unit, never observed.

**UV5.** What the unit's words hold: the DFS flag, the eight levels, the divider, the root clock generator's words, GPLL0, the votes and the wrapper version are all unread on this unit and nothing in this tree says
what they are; the page shows them, the plan's decisions are made from the film later.

**UV6.** That the wrapper version word is at +4 on this unit's wrapper: Linux says so for the QUP wrapper in general (`gse:188`), INFERRED for the X1E80100's wrapper 0.
