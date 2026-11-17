<!-- SPDX-License-Identifier: MIT -->
# SP11 payload `xhci` (S1, authorisation point A1): an xHC reset and No-Op DMA checkpoint, with a read-only plug watch

`payloads/xhci*.c` is one payload of the stick payload runner described in [SP11-PAYLOAD.md](SP11-PAYLOAD.md): the manifest and the
stick files, the chain, ABI v1 and the line catalogue are defined there and not repeated. It is stage S1 of the SP11 stick study
(`docs/SP11-STICK-LOG.md` sections 4.7 and 6 of the Snapintosh tree) and the first payload that **writes** to an xHC at EL2. The
operator approved authorisation point A1 for one supervised test on 2026-11-17 at 02:10; A2 (the first sector write to the stick) is NOT
granted, and this payload never touches a disk. The runbook, the outcome tree and the authorisation record are in the Snapintosh tree
(`docs/SP11-XHCI-S1.md`, `tools/sp11_xhci_s1_record.py`); this document is the payload's design and its tests. Evidence labels as
there: VERIFIED (a pinned source or q1n1's own driver says so, or a host test ran), OBSERVED (the unit or QEMU showed it), INFERRED,
EXPERIMENTAL, UNIMPLEMENTED, UNKNOWN. **EXPERIMENTAL. Hardware status: NOT RUN.** Nothing here ran on a Surface Pro.

## What it answers

Can the xHC of `usb_1_ss1` (or, with the other file, `usb_1_ss0`) read a Command TRB from RAM that the payload owns and write a Command
Completion Event back? That is the SC2 question of the stick study (the apps SMMU's streams `0x1420` and `0x1460` translate into context
bank 3, nested with stage 1 off: OBSERVED in S0b; what stage 2 maps is UNKNOWN) and the G12 / M6b checkpoint of the host-link study. It
asks it of up to four arenas, in a fixed order, and says for each what the SMMU's fault registers and the DWC3's bus-error address and valid bit did. It also watches, read only and
before the first write, the PORTSC of both controllers for 30 s while the operator connects the Mac's USB-C cable, which tells which
controller serves the connector in use and whether any link appears at all.

## Build

One source, several parts, two files. The Makefile (`platform/uefi/Makefile`, target `payloads`) compiles the parts
`xhci xhci-io xhci-text xhci-map xhci-ctl xhci-smmu xhci-watch` once per controller (`-DXHCI_S1_CONTROLLER=0|1`) into
`$(OUT)/payloads/xhci0/` and `xhci1/`, links each set with `payloads/start.S` and `payloads/payload.ld`, checks the ELF with
`tools/sp11_payload_elfcheck.py` and flattens it: `xhci0.bin` is `usb_1_ss0` (window `0x0a600000`, stream `0x1420`), `xhci1.bin` is
`usb_1_ss1` (`0x0a800000`, `0x1460`). The stick holds them as `XHCI0.BIN` and `XHCI1.BIN`, so the manifest names the controller. There is
no `xhci.bin`. The two binaries are planned only where `payloads/xhci.c` is, as every other payload is found by wildcard, so that a tree without
the sources builds the other payloads as it always did. The default build plans no file of this payload and every other payload is built byte for
byte the same with and without these sources (`XhciDefaults` of the test below compares the tree with a copy of itself without `payloads/xhci*`, so
it holds at every commit).

| Part | Holds |
| --- | --- |
| `xhci.c` | The entry, the pre-flight reads, the refusals, the attempt line |
| `xhci-io.c` | The only two instructions that store through a pointer that is not the payload's own memory (`mmio_store32`, `ram_store32`), the cache and barrier instructions, the counter, `rd32`/`rd64` through the runner's guarded load, the gates that every store and every cache operation passes (`xhc_store`, `ram_put`, `arena_range`) |
| `xhci-text.c` | The template formatter and the line budget |
| `xhci-map.c` | The UEFI memory map, the four arenas, building and zeroing an arena |
| `xhci-ctl.c` | The announcement, reset, program, run, No Op, halt and the attempt |
| `xhci-smmu.c` | The SMMU stream scan and the fault registers (reads only) |
| `xhci-watch.c` | The plug watch (reads only) |
| `xhci-priv.h`, `xhci-regs.h` | The private structures; the windows, registers, groups, budgets and the vocabulary of the page |

Compile-time overrides exist for the host test and are never set for a shipped file: `XHCI_S1_LINE_CAP` and `XHCI_S1_LOAD_CAP` (a "tight"
build, to run the branches that cut lines or stop on the load budget), and the windows, the DWC3 id, the SMMU base and the stream id (the
QEMU test aims the payload at a `qemu-xhci`, which has no DWC3 core and no SMMU: a DWC3 id of 0 and an SMMU base of 0 skip them).

## The sequence

Each write group is announced by a `NEXT <group> AFTER 8 S` line and eight seconds on the runner's counter before its first store, so
that a hang or a reset leaves the group that was running as the last line. Every attempt announces every one of its groups again, RESET
included: no store is made that is not preceded by its own NEXT line and its own eight seconds. A refusal prints `VERDICT REFUSED=<name>`
and returns 0 with nothing written.

1. **Pre-flight, reads only.** The identity (GSNPSID `0x33313130`, CAPLENGTH `0x20`, HCIVERSION `0x110`), HCSPARAMS1 and 2 (the scratchpad
   count is the high and low fields of HCSPARAMS2), HCCPARAMS1 (AC64, the context size), DBOFF, RTSOFF, PAGESIZE, USBCMD, USBSTS, CRCR,
   DCBAAP, CONFIG and the PORTSC of ports 1 and 2 of both controllers; the SMMU stream match and S2CR entry of the controller's stream,
   its context bank, and the BEFORE values of the global fault registers and the bank's FSR, FAR and FSYNR0; the DWC3 GSTS. It refuses
   by name on any mismatch, on HCE, HSE, CNR (after a bounded wait) or a running controller (RS set or HCH clear), on a DBOFF or RTSOFF with
   reserved low bits (DBOFF is dword aligned and RTSOFF 32-byte aligned: both are used as printed, never masked), on an offset outside the
   window, on a doorbell or an interrupter that would put a register of the record at or above `0xc100` (the DWC3 global registers: every
   store of the payload stays below), on more scratchpads than 32 and on an unreadable SMMU register. DBOFF and RTSOFF are printed; the unit's
   are not recorded (`0x2000` and `0x1000` are what q1n1's simulator and QEMU use: INFERRED). They are printed only when the reads and checks of
   the target's own words pass: a refusal there (`READ_FAULT`, `NOT_XHCI`, `CAPLENGTH`, `HCIVERSION`, `DWC3_ID`, `OFFSET`) is the `VERDICT REFUSED=...`
   line alone, with no `U<c>` line. On `OFFSET` the `VALUE` is the DBOFF or RTSOFF that has reserved low bits; or DBOFF, whichever of the two is
   at fault, for a window failure; or the offset from the window base of the first register of the table below (in its order) that would lie at
   or above `0xc100` (an RTSOFF of `0xc0e0` puts ERSTSZ at `0xc108`: `VALUE=0XC108`).
2. **The plug watch, reads only.** 30 s, a sample of the four PORTSC every 250 ms, one `CHG` line per change (the first four), a countdown
   at 20 and 10 s, and `WATCH DONE CHANGED=<ports or NONE> N=<n>`. A port that cannot be read ends the sampling of its controller, and a
   counter that stands still or runs backwards ends the watch (the run then ends at its first wait, like any counter that does not run).
3. **The attempts.** One per arena that can be used, in the order of the next section, at most four. The first that completes ends the
   run, and so does a bad completion (a wrong code, pointer or cycle, or a `REDIRECT`): a controller that answers wrongly is not given a
   fresh DMA into another arena in the same boot. At the RUN or NOOP stage a silence (`EVENT`), a Host System Error or Host Controller Error (`HSE`, `HCE`), or a controller that
   does not start (`HCH`), with or without a change of the SMMU's fault registers and the DWC3's bus-error address and valid bit, goes on to the next arena: that is the experiment. A failure
   at the RESET or PROGRAM stage ends the run, an `HSE` or `HCE` that the reset itself ends with included: it is the controller's answer and not the
   arena's. Each attempt is ARENA (zero and build), RESET, PROGRAM, RUN and NOOP, each
   announced and waited for again whatever came before, then, whatever happened, the halt, and the arena is zeroed again only if the
   controller is confirmed halted. The controller is left halted but still programmed: its DCBAAP, CRCR, ERSTBA and ERDP keep pointing into
   the arena, which is zero again (arena 2 is the runner's stack); no store beyond the thirteen is made to undo it.
4. **The ending.** A `VERDICT` line and an `END HALTED=<YES|NO|UNKNOWN> WRITES=<n> LOADS=<n>` line (with ` STORE_REFUSED` or ` LINES_CUT` when
   it applies), then `return 0`. The payload returns 1 only for a bad ABI argument block.

| Stage | Stores | Bounded wait | Stops with |
| --- | --- | --- | --- |
| ARENA | words of the arena only | none | `STORE`, `LINES`, `CLOCK` |
| RESET | USBCMD with HCRST (after a halt if the controller was found running) | halt 50 ms; HCRST clear 1 s; CNR clear 1 s (polled every 1 ms for the first 100 ms, every 10 ms after) | `HALT`, `HCRST`, `CNR`, `HCH`, `HCE`, `HSE` |
| PROGRAM | CONFIG, DCBAAP, CRCR (with RCS), ERSTSZ, ERDP, ERSTBA (last); all but CRCR are read back | none | `NOT_HELD` |
| RUN | USBCMD with RS | HCH clear 50 ms | `HCH`, `HCE`, `HSE` |
| NOOP | the No Op TRB (cycle bit last, then cleaned), doorbell 0, then ERDP with EHB and IMAN (IP) | Completion Event 200 ms, polled every 1 ms throughout | `EVENT`, `CYCLE`, `REDIRECT`, `CODE`, `POINTER`, `HSE`, `HCE` |

The order is xHCI 1.2 section 4.2 (INFERRED: cited from memory) and q1n1's `platform/uefi/xhci.c` `xhci_init` (VERIFIED by reading): halt, HCRST, wait for
HCRST and CNR, CONFIG, DCBAAP, CRCR, ERSTSZ, ERDP, ERSTBA, RS. ERSTBA is last because writing it makes the xHC load the segment table. The
scratchpad array goes in DCBAA[0] when HCSPARAMS2 asks for buffers (section 4.20). A 64-bit register is two 32-bit stores, the low word first.
The No Op is type 23, the event must be type 33 with completion code 1, the TRB's own address and the expected cycle (sections 4.6.2, 6.4.2.2
and 4.9.4); a Port Status Change event, which a running controller may post, is counted (`PSC=`) and skipped. Whether the xHC is coherent
with the CPU caches is UNKNOWN, so the payload cleans (DC CVAC, then DSB SY) what the CPU wrote for the xHC and cleans and invalidates
(DC CIVAC) the event TRB it reads; a step of 16 bytes reaches every line whatever the line size is.

## What it writes

Thirteen registers, the whole list (`reg_map` and `reg_groups` of `xhci-regs.h`; the authorisation record lists the same), and the words of
one arena. `op` is the base plus CAPLENGTH, `ir0` is the base plus RTSOFF plus `0x20`, `db` is the base plus DBOFF.

| Register | Block | Offset | Group |
| --- | --- | --- | --- |
| USBCMD | op | 0x00 | RESET (HCRST), RUN (RS), and the halt (RS clear) |
| CRCR_LO, CRCR_HI | op | 0x18, 0x1c | PROGRAM |
| DCBAAP_LO, DCBAAP_HI | op | 0x30, 0x34 | PROGRAM |
| CONFIG | op | 0x38 | PROGRAM |
| ERSTSZ | ir0 | 0x08 | PROGRAM |
| ERSTBA_LO, ERSTBA_HI | ir0 | 0x10, 0x14 | PROGRAM |
| ERDP_LO, ERDP_HI | ir0 | 0x18, 0x1c | PROGRAM, NOOP |
| IMAN | ir0 | 0x00 | NOOP |
| DB0 | db | 0x00 | NOOP |

A nominal run makes 17 stores. Nothing else is written: not USBSTS (even its write-1-to-clear bits), not a PORTSC, not IMOD, not the other
controller, not any DWC3, glue, SMMU, clock, GDSC, PHY, repeater, retimer, I2C, SPMI, GPIO or UCSI register, and no SMC or HVC.

**The audit.** The compiled code has exactly two stores through a pointer that is not rooted in the payload's own stack, context or line buffers:
`mmio_store32` and `ram_store32` in `xhci-io.c`, each one `str w1, [x0]`. Every other store of the binary (a few hundred: the compiler decides
how many) has its base in those buffers, and the test follows the pointer of every store, memset, memcpy and call in the LLVM IR of every part to its root
(`tools/test-q1n1-sp11-payload-xhci-compiled.py`) instead of counting them. It proves the base of a store and not its offset: a store at a run-time
offset from one of those buffers (a buffer too small, an index gone wild) has a good base and passes, and a test shows a digit buffer that is too small
passing it. The offsets are checked on the paths the host tests run: the native harness audits every register store and every RAM store of its model, and
AddressSanitizer and UBSan run with every case (the mutant `a-digit-buffer-that-is-too-small` is one that only they catch). `mmio_store32` is called only from `xhc_store`, which is called only
from `store`, and `ram_store32` only from `ram_put` (a `noinline` gate: inlined into `ram_put64` it would break the audit), which is called only
from `ram_put64`, `arena_build`, `arena_zero` and `xhc_noop`. The gate `xhc_store` knows the thirteen registers and the group open: a register
outside the list, a bit the group does not allow (USBCMD changes only RS and HCRST, never both, and its group is its value's; IMAN only clears
IP; the doorbell only rings doorbell 0), a group not announced, an offset that is not word aligned or lies at or above `0xc100` (the DWC3 global
registers, whatever DBOFF and RTSOFF say), or a controller whose window already faulted on a read is refused (`STORE_REFUSED` on the END line).
`ram_put` refuses a store when the ARENA group is not open, to an unaligned address, or outside the arena of the attempt (one unsigned
difference, so that no address wraps in, and an arena of no pages admits nothing). Every cache instruction has a gate of its own: `clean_range`
and `events_take` check each 16-byte step with `arena_range` before the DC CVAC or DC CIVAC, so that no cache operation reaches memory that is not
the arena's (a refusal is `STORE_REFUSED` too). The `gates` suite of the native test calls the gates directly with every input they must refuse,
and every rule of every gate has a mutant that only that suite can catch. The tests hold the source and the binary to these rules (below).

**The arena.** The first page holds the structures (64-byte aligned, none across a 64 KiB boundary: Table 6-1), the following pages are the
scratchpad buffers (one page each). Offsets in the first page: DCBAA at `0x000` (up to 71 slots fit; the unit has 64), the scratchpad array at
`0x240`, the command ring of 16 TRBs closed by a Link TRB at `0x400`, the one-entry segment table at `0x500`, the event ring of 64 TRBs at `0x600`.
The arena is zeroed when built and again after a confirmed halt.

## The arenas

The order is fixed and each is a complete attempt from RESET on; an arena that cannot be used is named with its reason in the `ARENAS` line.

| # | Name | Where | Why this one, in this place | Reason it is skipped |
| --- | --- | --- | --- | --- |
| 1 | `FW` | `0xCF412000`, four pages, `usb_1_ss0` only | The firmware's own xHCI memory as S0 found it (OBSERVED): memory the stream demonstrably reached before ExitBootServices | `N_A` for ss1, `NO_MAP`, `NOT_FREE` (the memory map must call the range boot-services data or conventional), `TOO_BIG` |
| 2 | `STACK` | inside the runner's payload stack, from its second page, at most 9 pages | The only RAM the runner declared and the payload owns; the guard words and the last 24 KiB (the payload's frames and the runner's ops) are kept; not the image, whose pages may be mapped read-only | `SMALL_STACK`, `TOO_BIG` |
| 3 | `LOW` | the top of the highest block of conventional memory ending at or below 4 GiB | Where the runner puts its big files (OBSERVED); reachable by a controller that takes only 32-bit addresses | `NO_MAP`, `NOT_FREE` |
| 4 | `HIGH` | the first pages of the 30 GiB bank at `0x880000000`, only with HCCPARAMS1.AC64 | EL2 maps it write-back, `AT S1E2W` accepted every probe of it and 13 of 13 digests of data copied into it read back (OBSERVED: `docs/SP11-MONITOR-PORT.md` and `docs/SP11-STICK-WRAPPER.md` of the Snapintosh tree); only whether the xHC's DMA reaches it is UNKNOWN (SC2), so it is the last | `NO_AC64`, `NO_MAP`, `NOT_FREE` |

Only arena 2 is RAM the runner owns and declared to the payload. Arenas 1, 3 and 4 are RAM that the memory map calls free, and they are the
fallbacks after an attempt whose DMA may have gone astray (hazard (c) of the record).

## The page

At most 40 lines of 100 characters per call (the runner's limits), the payload stopping at 3800 of the 4096 loads. Two lines are kept for the
VERDICT and END lines, and a write group is opened only by an announcement that was printed (`LINES` otherwise). Every eligible attempt keeps six
lines, its five announcements and its result line: the watch's optional lines (`CHG` and the countdown) may not take those of any eligible attempt,
an SMMU report of an attempt (`SMMU1`) is printed only where the attempts still to come keep theirs (a report that is not printed is a cut line,
`LINES_CUT` on the END line), and a later attempt starts only if its six lines and the closing two still fit. So only optional lines give way, never the
first line of an `R<k>` result, the VERDICT or the END line. A result of 100 characters or more takes a second line (it starts with `R<k>`), which no
budget reserves: an attempt that starts with 32 lines on the page, the most with which one starts, loses it, END says `LINES_CUT` and the `R<k>` line ends
before its `STS=` field (the `edges` suite: a bad completion in the last attempt of `XHCI0.BIN`, a quiet watch and three failed attempts with their
reports; with three arenas the line fits). How many `SMMU1` reports are on the page, in the host model, whose results are one line each and whose global
fault status is 0 before and after every attempt (S0b read 0 before any attempt: OBSERVED), so that a report is one line: on the controller with three
arenas every report, whatever the number of port changes in the watch (it prints at most four `CHG` lines), and `LINES_CUT`
never; on the controller with four arenas, when all four arenas are refused with a change of the SMMU's fault registers and the DWC3's bus-error address and valid bit, 3, 2, 1 or 0 of the four after 0, 1, 2
or 3 or more `CHG` lines, and `LINES_CUT` every time; a success after earlier attempts that failed with a change says `LINES_CUT` too, at arena 4 from
one `CHG` line on, at arena 3 from two, at arena 2 from three, never at arena 1. So `NOOP_OK` may be followed by an END line with `LINES_CUT` on
`XHCI0.BIN`: what was dropped are `SMMU1` reports of the failed attempts, whose `R<k>` lines (`SMMU=CHANGED`) are still there, and the result is
whole. The model overwrites FAR at every fault, so it assumes that every failed attempt changes the SMMU's fault registers and the DWC3's bus-error address and valid bit; the SMMU records only the first
fault of a context bank until its FSR is cleared, which A1 never does (INFERRED from ARM IHI 0062, not re-read), so `SMMU=SAME` does not prove that an
attempt did not fault, an `SMMU1` FAR or FSYNR0 may belong to an earlier fault, and later attempts may read `SAME`. With a global fault status that is not 0
already at the pre-flight (not observed) a report is two lines and more give way: the controller with three arenas says `LINES_CUT` only when
all three arenas fail and the watch printed three or more `CHG` lines, the one with four after a success at arena 3 or 4 always and at arena 2 from one
`CHG` line on. The `edges` suite of the native test pins all of it. Every
line starts with `PAYLOAD XHCI `:

| Line | Meaning |
| --- | --- |
| `U<c> ID=.. CAPL=.. VER=.. HCS1=.. HCS2=.. HCC1=..` | The identity and the capability words of the target (`U1` for `XHCI1.BIN`) |
| `U<c> SCRATCH=<n> PAGESZ=.. AC64=.. CSZ=.. DBOFF=.. RTSOFF=..` | The decoded fields |
| `U<c> CMD=.. STS=<raw:names> CRCR=.. DCBAAP=.. CFG=..` | The state before anything is written |
| `SMMU STREAM=.. SMR=<n> TRANS\|BYPASS\|FAULT CB=<n> NCB=..` | The stream's match register, type and context bank |
| `SMMU0 GFSR=.. FSR=.. FAR=.. FSYNR0=..`, `SMMU1 R<k> GFSR=.. FSR=.. FAR=.. FSYNR0=..` | The fault registers before anything is written (`SMMU0`), and after attempt k when the SMMU's fault registers or the DWC3's bus-error address or valid bit changed since the end of the one before (`SMMU1 R<k>`) |
| `ARENAS <n>=<OK or the reason> ...` | Which arenas can be tried |
| `WATCH 30 S: CONNECT THE MAC USB-C CABLE TO THE FREE PORT NOW`, `BASE ..`, `CHG T=<s> <port> FROM .. TO ..`, `WATCH 20 S LEFT`, `WATCH 10 S LEFT`, `WATCH DONE CHANGED=.. N=..` | The plug watch |
| `NEXT ARENA <n> <name> <address> PAGES <p> AFTER 8 S`, `NEXT RESET`, `NEXT PROGRAM`, `NEXT RUN`, `NEXT NOOP` (each `AFTER 8 S`) | A write group is about to open |
| `R<k> ARENA=<n> <verdict> STAGE=<stage> [WHY=..] [CC=..] STS=.. EV=<n> [PSC=<n>] SMMU=SAME\|CHANGED\|UNREAD` | The result of attempt k: STS is the last USBSTS read, after the halt (EINT stays set once an event was posted: it is write-1-to-clear and the payload never writes USBSTS); SMMU compares the SMMU's fault registers and the DWC3's bus-error address and valid bit with those at the end of the attempt before (the first with `SMMU0`), and `SAME` does not prove that the attempt did not fault (the SMMU keeps the first fault until its FSR is cleared: the paragraph above); a result of 100 characters or more takes a second line, which starts with `R<k>` |
| `VERDICT NOOP_OK ARENA=<n>`, `VERDICT <verdict> STAGE=.. [WHY=..]`, `VERDICT REFUSED=<name> [<key>=<value>]` | The answer |
| `END HALTED=.. WRITES=.. LOADS=..` | The ending; absent after a refusal |

A nominal page is 19 lines (the host model's values: INFERRED for the unit). The panel holds about 89 lines.

## Verdicts, reasons and refusals

* **Verdicts:** `NOOP_OK`, `NOOP_TIMEOUT`, `NOOP_HSE`, `NOOP_BAD_COMPLETION`, `REFUSED`.
* **Stages:** `ARENA`, `RESET`, `PROGRAM`, `RUN`, `NOOP` (`STG_HALT` is defined and never set).
* **Reasons (`WHY=`):** `HALT`, `HCRST`, `CNR`, `HCH`, `NOT_HELD`, `EVENT`, `READ`, `CLOCK`, `STORE`, `HSE`, `HCE`, `CODE`, `POINTER`, `CYCLE`, `BUDGET`, `LINES`, `REDIRECT`.
  At the RUN or NOOP stage a reason about the arena (nothing came: `EVENT`; a Host System Error or Host Controller Error: `HSE`, `HCE`; the controller did not start: `HCH`) is its answer
  and the next arena is tried, with or without a change of the SMMU's fault registers and the DWC3's bus-error address and valid bit: that is the SC2
  experiment. At the RESET and PROGRAM stages every failure ends the run, an `HSE` or `HCE` that the reset
  itself ends with included. A bad completion (`CODE`, `POINTER`, `CYCLE`: an event that is not a success, not ours, or with the
  wrong cycle bit; `REDIRECT`) ends the run, as does a reason about the controller (it would not reset or hold its registers) or about the payload (the
  clock, a refused store, a failed read, a budget). `REDIRECT` is the controller saying it posted an event (USBSTS.EINT set when the doorbell had been
  rung with it clear) while the ring holds none: the event was written somewhere else, or our reads do not see it (INFERRED: it is the only signal the
  payload has). With EINT already set before the doorbell (a port status event, say) a redirect cannot be told from silence and reads as `EVENT`.
* **Refusals:** `NO_COUNTER`, `NO_LOAD32`, `COUNTER_STUCK`, `READ_FAULT` (with `AT=<register>`), `NOT_XHCI`, `CAPLENGTH`, `HCIVERSION`, `DWC3_ID`, `OFFSET`, `HCE`,
  `HSE`, `CNR`, `RUNNING`, `PAGESIZE`, `SMMU_UNREADABLE`, `SCRATCHPADS`, `NO_ARENA`; and `SKIPPED_NOT_AT_EL2`, a line and not a verdict.

## Tests

All host only; every check has a deliberately faulty case that fails it. `python3 -B tools/test-q1n1-sp11-payload-xhci.py [Class ...]`
(`make -f platform/uefi/Makefile OUT=<dir> payloads` first), one suite at a time:

| Class | What it holds |
| --- | --- |
| `XhciSource` | The source and the header: the register table, the groups, the two store sinks and their callers, the cache instructions behind the arena gate, the allowed instructions, the budgets, the files' sizes |
| `XhciBinary` | `llvm-objdump` of both files: exactly two store sinks, their callers and those of the gates and the cache helpers, no forbidden instruction, the size cap, the ELF check, a faulty binary for each rule |
| `XhciNative` | The native harness `tools/test-q1n1-sp11-payload-xhci{,-cases,-gates}.c`: a model of the runner, a simulated xHC with SMMU and DWC3, and nine suites (nominal, scratch, refuse, faults, fallback, watch, edges, gates, fuzz) for both controllers, with an audit of every store (a register not in the list, a group not open, RAM outside the arena, RAM written while the controller may run other than the No Op TRB, a cache operation not followed by DSB or outside the arena) and of every line (font, width, budget); the `gates` suite calls `store`, `ram_put`, `arena_range` and `clean_range` directly with every input they must refuse |
| `XhciMutants` | The seeded mistakes of `tools/sp11_payload_xhci_mutants.py`: wrong order (ERSTBA before ERSTSZ), no scratchpad, no cache maintenance, a cache operation outside the arena, a wait without a bound, a write before its NEXT line, a store to the SMMU, a bad completion that moves on, a stale SMMU baseline, a counter set back that ends a wait at once, a bus error address that is not compared, an HSE or HCE at the reset that is not noticed, a digit buffer that is too small (only the sanitizers see it), and others; one for each rule of every gate, with every caller as it is; each must fail a suite (the gate mutants, the `gates` suite; the new ones, `edges` or `faults`) |
| `XhciStick` | `make payloads` builds exactly `xhci0.bin` and `xhci1.bin`, the same bytes as the test's own build, and the runner's manifest tool lists each one by its file name |
| `XhciDefaults` | That this payload leaves everything else as it is, at any commit: its checks (`tools/sp11_payload_xhci_defaults.py`) compare the tree with a copy of itself without `payloads/xhci*` and never with an earlier commit. The default build (`make -n`) plans no file of this payload; `make -n payloads` plans `xhci0.bin` and `xhci1.bin` and no other binary named for xhci; the copy without the sources plans the same commands but for the xHCI lines and builds every other payload byte for byte as the full tree does, the full tree having exactly the two extra binaries; the shared machinery (`sp11_payload_testlib.py`, `test-q1n1-sp11-payload.py`, `sp11_payload_manifest.py`, `payload-util.h`) names no xhci; `make clean` removes the objects of the directories `xhci0` and `xhci1`. One seeded bug for each: an unconditional Makefile rule, a plan or a flag that changes with the sources, a payload source that changes with the headers, an xhci mention in a shared file, a clean that leaves the objects |

`tools/test-q1n1-sp11-payload-xhci-compiled.py` audits the compiled code further: `XhciProvenance` follows the pointer of every store, memset, memcpy
and call in the LLVM IR of every part to its root (only the two sinks store through an integer made a pointer; faulty IR texts and three faulty source
trees must be refused; it proves bases and not offsets, and a digit buffer that is too small passes it), and `XhciDepth` holds the payload's own frames (frame sizes from `-fstack-size-section`, the call graph of the linked ELF: about
1.6 KiB) plus the 16 KiB the ABI leaves to the runner's ops inside the 24 KiB it keeps below arena 2.

`python3 -B tools/test-q1n1-xhci.py` is the original native xHCI simulator, extended only with hooks the payload test needs; its own checks are unchanged.
`python3 -B tools/test-q1n1-sp11-payload-qemu-xhci.py` runs `xhci1.bin` built for QEMU as the second payload of a probe boot against a `qemu-xhci`.
`python3 -B tools/test-q1n1-sp11-payload-xhci-doc.py` holds this document to the source.

## QEMU

QEMU's `qemu-xhci` is an independently written xHC, so a pass is the strongest host evidence that the register sequence works. The machine is
`virt,virtualization=on,gic-version=3 -cpu max -device qemu-xhci`; the xHC is at PCI 00:01.0 with BAR0 at `0x8000004000` (64-bit). OBSERVED:
firmware's XhciDxe restores the PCI attributes before the payload runs (command register 0, BAR reads all ones), so a fixture payload
(`tools/testdata/sp11-payload-fixture-xhciq.c`) reads the ECAM high window, enables memory space and bus mastering if the id is `1B36:000D`, and
the payload then runs as the second of the chain. The run reaches `NOOP_OK`, `HALTED=YES`, 17 stores, with `STS=0X9:HCH.EINT`; the waits
are at least 7 s per group and the watch takes about 30 s. Seeded variants (no doorbell, no ERST, no ERST size) fail with the verdicts the model gives.
What QEMU cannot show: it ignores CRCR.RCS (a seeded fault that clears it is accepted by QEMU and caught by the host model), it has no DWC3 core
and no SMMU, and its DMA is coherent. The low ECAM window `0x3f000000` is not mapped at EL2 there (a load faults, a store hangs), so the high
window is used.

## Limits

EXPERIMENTAL; hardware NOT RUN. A pass here says nothing about: the apps SMMU's stage 2 for the streams, the coherence of the xHC with the
caches, the state of the PHY, repeater, retimer and Type-C path, the xHC's behaviour under HCRST, CRCR, ERSTBA and the doorbell on the unit, or
what the Mac shows when the cable is connected. The xHCI section numbers are cited from memory and were not re-read. The payload leaves the
controller halted but still programmed (its DCBAAP, CRCR, ERSTBA and ERDP point into the arena, which is zero again, and arena 2 is the runner's
stack), with USBSTS.EINT possibly set (not written), and zeroes its arena only after confirming the halt. Its stores are not guarded: a permission
fault or an SError on a store is an exception at EL2 (a fault page or a hang), and the reads of S0 prove readability only.
