<!-- SPDX-License-Identifier: MIT -->
# SP11 payload runner: what the unit showed (boots 4, 5, 7, 8, 9 and 11, the restart probe and the restart control)

The stick payload runner of [SP11-PAYLOAD.md](SP11-PAYLOAD.md) and eight of its nine payloads ran on the Surface Pro 11
(Snapdragon X1E80100): `psci`, `usbsmmu` and `timer` in boot 4 and `psci` and `usbsmmu` in boot 5 (2026-11-14), and `cpuon`,
alone, in boot 7 (2026-11-15), each from the boot stick plugged in directly (no hub). Later boots of the same stick ran `cpuon`
twice more ([the restart probe](#the-restart-probe), 2026-11-15), `psci` alone twice ([the restart control](#the-restart-control),
2026-11-16), in boots 8 and 9 (2026-11-16) `hashbig` and `el2mem` with a 144 MiB data file
([the `memhash` plan](#payloads-hashbig-and-el2mem-boots-8-and-9)) and, in boot 11 (2026-11-16), `cnthctl` and `el1trap`, which write
registers, in one boot ([below](#payloads-cnthctl-and-el1trap-boot-11)). This document records what the photographs and videos of those
boots showed, and what they did not. Boot 6 was not a payload boot (an EL2 test image) and is not recorded here.
The line formats are in [the line catalogue](SP11-PAYLOAD.md#line-catalogue); what each payload reads, and what its answers would
mean for the port, is in its own document: [`psci`](SP11-PAYLOAD-PSCI.md), [`timer`](SP11-PAYLOAD-TIMER.md),
[`usbsmmu`](SP11-PAYLOAD-USBSMMU.md), [`cpuon`](SP11-PAYLOAD-CPUON.md), [`hashbig`](SP11-PAYLOAD-HASHBIG.md),
[`el2mem`](SP11-PAYLOAD-EL2MEM.md), [`cnthctl`](SP11-PAYLOAD-CNTHCTL.md) and [`el1trap`](SP11-PAYLOAD-EL1TRAP.md). The `state` payload has not
run on the unit: NOT RUN.

Evidence labels as there: VERIFIED, OBSERVED, INFERRED, EXPERIMENTAL, UNIMPLEMENTED, UNKNOWN.
**One unit, at most four boots of any payload: nothing here is a distribution**; another unit, or another boot of this one, may
differ. OBSERVED means a photograph or a video showed it, read by hand from enlarged crops or frames (the unit has no UART and no
log); "operator report" marks what the operator said and no photograph shows.

## The boots

Boot 3 was not a payload boot; it is here because two results below lean on it.

| | Boot 3 (context) | Boot 4 | Boot 5 | Boot 7 |
| --- | --- | --- | --- | --- |
| Image | the X2 EL2 tests v2, declared variant, build `E5BF1A6BD94C` (image sha256 `6b68cab6...aaad`) | `q1n1-payload.efi` (sha256 `c20579093ec7...`), q1n1 build `A9F00F9CCBB5` (commit a9f00f9) | the same image | the same image, started with `--el2` as step 2 of an autorun plan, under slbounce's `SLBOUNCE-DEVHE-MARK.EFI` |
| Stick | plugged in directly: the UEFI path was `Pci(0x80,0x0)/USB(0x1,0x0)`, one USB node, where the hub run S0 had two | plugged in directly | plugged in directly | plugged in directly (`Pci(0x80,0x0)/USB(0x1,0x0)` again) |
| Chain | none | `PSCI.BIN` (`d391a9c8...`), `USBSMMU.BIN` (`9f0260dc...`), `TIMER.BIN` (`68cace99...`); `PAYLOAD.MAN` 920 B (`3f99a4d0...`) | `PSCI.BIN`, `USBSMMU.BIN`; `PAYLOAD.MAN` 624 B (`9d6f731b...`) | `CPUON.BIN` alone (`3b4bfda7...`, 18,056 B); `PAYLOAD.MAN` of one entry |
| Before the bounce | not applicable | all three payloads loaded and hashed, six declared ranges accepted (every `contained=yes`), `PAYLOAD READY FILES=3 RANGES=6 CODE=3` | `PAYLOAD READY FILES=2 RANGES=5 CODE=2`, every declared range `contained=yes` | `PAYLOAD READY FILES=1 RANGES=4 CODE=1`, the payload loaded and hashed, every declared range contained |
| After it | the last test, T06, never returned and the board rebooted by itself (operator report) | EL2 reached; two photographs cut the right-hand column off; the board rebooted by itself before a third photograph and afterwards booted something other than the stick (operator report) | the page stayed up (`UPTIME 3 S` in one photograph, `UPTIME 10 S` in another) and both payloads returned | EL2 reached; the chain returned (`RETURN=0X0`, `UPTIME 16 S` in the last photograph) and the board restarted by itself after that photograph (operator report; seconds after it is INFERRED; the cause is UNKNOWN) |

## What the runner showed

OBSERVED in the boots named, unless a line says otherwise.

* **The bounce was taken and q1n1's page was drawn at EL2** in all three boots: `ENTRY EL 1`, `CURRENT EL 2`. In boots 8, 9 and 11
  every payload read `CURRENTEL=0X8` (EL2) on its first lines.
* **`EfiLoaderCode` memory executes at EL2.** Both payloads of boot 5, `cpuon` of boot 7 and of the probe's step 3, `hashbig` and
  `el2mem` of boots 8 and 9, and `cnthctl` and `el1trap` of boot 11 were allocated as `EfiLoaderCode` and ran there, with no fault
  page. That answers the first of the
  [open questions](SP11-PAYLOAD.md#open-questions-for-the-operator). No `EfiLoaderData` payload was tried (`BIG.DAT` was read, never
  executed), so whether the unit maps that no-execute stays UNKNOWN.
* **The ABI v1 ops the payloads used work.** `puts`: every line reached the panel. `load32`: `usbsmmu` made 213 guarded loads and
  `el2mem` four, `FAULTS=0 REFUSED=0`. Each payload of boots 5, 7, 8, 9 and 11 returned to the runner (`RETURN=0X0 STACK=OK`, guard
  words intact, `DROPPED=0`).
* **The second hash at EL2 passes.** Right before each call the runner re-hashed the preload table and the payload where the
  bounce left it (`PAYLOAD VERIFY=OK`): the files at `0xCEC90000` (`psci`) and `0xCEA89000` (`usbsmmu`) were intact (boot 5),
  and so was `cpuon` at `0xCEA8B000` (boot 7), `0xCE5E5000` (step 2: it was called, which the runner does only after a passed second
  hash) and `0xCE60A000` (step 3), `hashbig` at `0xCEA8D000` and `el2mem` at `0xCEA88000` (boots 8 and 9), and `cnthctl` at `0xCEA8D000` and
  `el1trap` at `0xCEA88000` (boot 11). The memory map at
  EL2 had 235 entries (boot 5) and 234 (boot 8). A 144 MiB data file, which the runner hashes only before the bounce, arrived
  intact: `hashbig`'s digest at EL2 equals the runner's ([below](#payloads-hashbig-and-el2mem-boots-8-and-9)).
* **The panel.** The layout function (a copy of the survey's `stk_layout`, pinned by a host test) places the region right of
  q1n1's page: for the unit's 2880 x 1920 panel, as the host tests model it, its first row is row 16, the first below the
  emblem, and it has 89 rows. That is computed from the function (VERIFIED as a computation), not measured. What the unit
  showed: 58 lines in the right-hand panel in boot 4 (counted from the geometry of a photograph that cut the column off; the
  text was not captured), all 41 lines of boot 5 (read in full), all 45 of boot 7 (read with some blur) and of step 3 (read
  crisp from a video), all 36 of boots 8 and 9 and all 37 of boot 11 (read from videos). So that payload lines reach the right-hand column is
  OBSERVED, and 58 is the most it was seen to hold; the 89 rows are not.
* **The heartbeat** (`UPTIME`) counts from before the chain, not from its end: `start` is read before the runner is called
  (`platform/uefi/main.c`, line 1626 against 1641), and the loop at lines 1645 to 1655 first draws `(counter - start) / frequency`
  once the chain has returned; until then the page shows the 0 S drawn before the chain. It read 0 S in both photographs of
  boot 4 (the chain did not return: INFERRED, below) and in the photographs taken during the chains of boot 7 and of step 2 of
  [the restart probe](#the-restart-probe); after chains that returned, 3 S and 10 S in boot 5, 16 S in boot 7 (the first heartbeat
  after the chain's two eight-second waits) and 224 S and 268 S in [the restart control](#the-restart-control). Step 3's video
  shows it advancing to about 36 S, the videos of boots 8 and 9 show `UPTIME 101 S` (110 s into the video) and `42 S` (54 s in), and
  boot 11's shows `33 S` (42 s in) and `49 S` (58 s).
* **q1n1's own page, left column** (boots 4 and 5; boot 7's page showed the same `HCR_EL2`, `SCTLR_EL2`, `TTBR0_EL2`, `MAIR_EL2`,
  `CNTFRQ_EL0` and `MPIDR_EL1` and boot 8's the same `MIDR`, `HCR_EL2`, `SCTLR_EL2`, `TCR_EL2`, `TTBR0_EL2` and `MAIR_EL2`; its
  lines, not a payload's): `ENTRY EL 1`, `CURRENT EL 2`, `MIDR` `0x512F0011`,
  SPCR UART `0x894000` (type `0x13`, GSI `0x182`, baud code 7) with `UART TX disabled or unavailable`, `HCR_EL2` `0x88000010`
  (E2H 0, TGE 1, VM 0, RW 1), `SCTLR_EL2` `0x0000100030C5183D` (M 1, C 1, I 1, WXN 0, EE 0), `TCR_EL2` `0x80843514`,
  `TTBR0_EL2` `0xA7F2E000`, `MAIR_EL2` `0xFFBB4400`, `CPTR_EL2` `0x22FF`, `CNTHCTL_EL2` `0x3`, `CNTFRQ_EL0` `0x124F800`,
  `MPIDR_EL1` `0x80000000`, `DAIF` `0x3C0`, `SPSEL` 1.

## The page of boot 5, verbatim

The right-hand panel, 41 lines, as photographed (the page font has capitals only): the runner's notes, then each payload between
its `VERIFY`, `CALL` and `DONE` lines.

<!-- boot5-panel -->
```
PAYLOAD LOADED INDEX=0 BASE=0XCEC90000 BYTES=4285 SHA=D391A9C8CBEECD00 TYPE=1
PAYLOAD LOADED INDEX=1 BASE=0XCEA89000 BYTES=17936 SHA=9F0260DC5B2F910F TYPE=1
PAYLOAD READY FILES=2 RANGES=5 CODE=2
PAYLOAD VERIFY=OK
PAYLOAD CALL 0 D391A9C8CBEECD00
PAYLOAD PSCI MPIDR_EL1=0X80000000
PAYLOAD PSCI NEXT VERSION
PAYLOAD PSCI VERSION PSCI_VERSION=0X10001:V1.1
PAYLOAD PSCI VERSION MIGRATE_INFO_TYPE=0XFFFFFFFFFFFFFFFF:NOT_SUPPORTED(-1)
PAYLOAD PSCI NEXT FEATURES
PAYLOAD PSCI FEATURES CPU_SUSPEND=0X3 CPU_OFF=0X0 CPU_ON=0X0 AFFINITY_INFO=0X0
PAYLOAD PSCI FEATURES MIGRATE_INFO_TYPE=0XFFFFFFFFFFFFFFFF:NOT_SUPPORTED(-1) SYSTEM_OFF=0X0
PAYLOAD PSCI FEATURES SYSTEM_RESET=0X0 PSCI_FEATURES=0X0 SYSTEM_SUSPEND=0X0
PAYLOAD PSCI FEATURES SYSTEM_RESET2=0XFFFFFFFFFFFFFFFF:NOT_SUPPORTED(-1)
PAYLOAD PSCI NEXT AFFINITY
PAYLOAD PSCI AFFINITY 0X0=0X0:ON 0X100=0X1:OFF 0X200=0X1:OFF 0X300=0X1:OFF 0X10000=0X1:OFF
PAYLOAD PSCI AFFINITY 0X10100=0X1:OFF 0X10200=0X1:OFF 0X10300=0X1:OFF 0X20000=0X1:OFF
PAYLOAD PSCI AFFINITY 0X20100=0X1:OFF 0X20200=0X1:OFF 0X20300=0X1:OFF
PAYLOAD PSCI NEXT SMCCC
PAYLOAD PSCI SMCCC SMCCC_VERSION=0X10001:V1.1
PAYLOAD DONE INDEX=0 RETURN=0X0 STACK=OK LOADS=0 FAULTS=0 REFUSED=0 LINES=15 DROPPED=0
PAYLOAD VERIFY=OK
PAYLOAD CALL 1 9F0260DC5B2F910F
PAYLOAD USBSMMU NEXT U0
PAYLOAD USBSMMU U0 IDLE CAPL=0X20 CMD=0X0 STS=0X11:HCH.PCD DCBAAP=0X0 P1=0X20002A0:RXDET
PAYLOAD USBSMMU U1 IDLE CAPL=0X20 CMD=0X0 STS=0X1:HCH DCBAAP=0X0 P1=0X20002A0:RXDET
PAYLOAD USBSMMU DWC3 ID=0X33313130 GCTL=0X101005 GSTS=0X7E800001 BERR=0X0 LTSSM=0X9CC20026
PAYLOAD USBSMMU NEXT SMMU
PAYLOAD USBSMMU SMMU ID0=0X7C017E9A ID1=0X6000005F ID2=0X5222 SCR0=0X230406 GFSR=0X0
PAYLOAD USBSMMU SMMU SMRG=0X9A NCB=0X5F CBBASE=0X15080000 S1420=SMR3.TRANS.CB3 S1460=SMR4.TRANS.CB3
PAYLOAD USBSMMU NEXT RINGS
PAYLOAD USBSMMU RINGS CSZ=1 ERSTSZ=0X0 ERSTBA=0X0 ERDP=0X0 SEG0=NO_ERST
PAYLOAD USBSMMU TRB SKIPPED=NO_SEG0
PAYLOAD USBSMMU U0 SLOTS=NO_DCBAAP
PAYLOAD USBSMMU NEXT CB3
PAYLOAD USBSMMU CB3 CBAR=0X35E03 TYPE=NESTED CBA2R=0X1 VA64=1
PAYLOAD USBSMMU CB3 SCTLR=0XE0 M=0 TCR=0X0 T0SZ=0 TG0=4K EPD0=0 TCR2=0X60
PAYLOAD USBSMMU CB3 TTBR0=0X0 ASID=0X0 MAIR0=0X0 FSR=0X400 FAR=0X953FDF7CF7F7 FSYNR0=0X46005D
PAYLOAD USBSMMU CB3 TTBR1=0X0
PAYLOAD USBSMMU WALK UNSUPPORTED NESTED CBAR=0X35E03 CBA2R=0X1 SCTLR=0XE0 TCR=0X0 TTBR0=0X0
PAYLOAD DONE INDEX=1 RETURN=0X0 STACK=OK LOADS=213 FAULTS=0 REFUSED=0 LINES=17 DROPPED=0
```
<!-- /boot5-panel -->

## Payload `psci` (boot 5)

`LOADS=0 FAULTS=0 REFUSED=0 LINES=15`: 15 lines (22 under QEMU) and only `smc #0`. An SMC issued from q1n1's EL2, after the
Secure-Launch bounce, reached the firmware's PSCI and was answered: **OBSERVED** (it was UNKNOWN). What it answered:

| Asked | Raw answer | Decoded |
| --- | --- | --- |
| `MPIDR_EL1` (not an SMC) | `0X80000000` | the boot CPU, affinity 0 |
| `PSCI_VERSION` | `0X10001` | v1.1 |
| `SMCCC_VERSION` | `0X10001` | v1.1 |
| `MIGRATE_INFO_TYPE` | `0XFFFFFFFFFFFFFFFF` | `NOT_SUPPORTED(-1)` |
| `PSCI_FEATURES` of `CPU_SUSPEND` | `0X3` | flags bits 0 and 1 set |
| `PSCI_FEATURES` of `CPU_OFF`, `CPU_ON`, `AFFINITY_INFO`, `SYSTEM_OFF`, `SYSTEM_RESET`, `PSCI_FEATURES`, `SYSTEM_SUSPEND` | `0X0` | implemented (INFERRED: a 0 means implemented in the PSCI specification, which was not re-read) |
| `PSCI_FEATURES` of `MIGRATE_INFO_TYPE`, `SYSTEM_RESET2` | `0XFFFFFFFFFFFFFFFF` | `NOT_SUPPORTED(-1)` |
| `AFFINITY_INFO` of `0X0` | `0X0` | `ON`: the boot CPU |
| `AFFINITY_INFO` of the other eleven MPIDRs the MADT lists (`0X100` to `0X20300`) | `0X1` each | `OFF` |

So the eleven secondaries read OFF (OBSERVED) and `CPU_ON` is implemented (INFERRED, as above): OFF is the state a later
`CPU_ON` starts from (INFERRED), so secondary bring-up (the stick study's M4) is possible in principle. **Not tried:** the
payload cannot issue `CPU_ON`, `CPU_OFF`, `CPU_SUSPEND`, `SYSTEM_OFF` or `SYSTEM_RESET`, and none was issued. What a started CPU would
do was UNKNOWN until `cpuon` started them ([below](#payload-cpuon-boot-7-and-step-3)).

## Payload `usbsmmu` (boot 5)

`LOADS=213 FAULTS=0 REFUSED=0 LINES=17`, `RETURN=0X0 STACK=OK`: 213 loads, none aborted and none refused, 17 lines (24 at most)
and no hang. Its lines are in the block above, from `NEXT U0` to `WALK UNSUPPORTED NESTED`. What they say, all OBSERVED once:

* **Both xHCs read as idle or reset at EL2.** U0 (`usb_1_ss0`, window `0x0a600000`, where S0 found the stick) is `IDLE`:
  CAPLENGTH `0x20`, USBCMD 0, USBSTS `0x11` (HCH and PCD), DCBAAP 0, no device on either port (the `IDLE` rule is DCBAAP 0 and
  CCS clear on both ports); port 1's PORTSC is `0x20002A0` (RxDetect, PP, WCE). The `P2` field was cut by the 100-character
  line limit (the payload drops a field that does not fit), so port 2's raw value is not on the page; `IDLE` says its CCS is
  0. U1 (`usb_1_ss1`, `0x0a800000`) is `IDLE` too: USBSTS `0x1` (HCH), DCBAAP 0, port 1 `0x20002A0`.
* **U0's DWC3:** GSNPSID `0x33313130` (as in S0), GCTL `0x101005`, GSTS `0x7E800001`, no bus error latched (`BERR=0X0`),
  GDBGLTSSM `0x9CC20026`.
* **The event ring is empty:** ERSTSZ, ERSTBA and ERDP are all 0 (`SEG0=NO_ERST`), so the TRB group was skipped and there are
  no slots to list (`U0 SLOTS=NO_DCBAAP`).
* **The contrast with S0.** In the hub run U0 still held the firmware's rings: DCBAAP `0xCF412000`, three slots, USBSTS
  `0x1019` with HCE. In this direct run both xHCs read as unstarted or reset at EL2, with the stick attached and the firmware
  having just booted from it. The firmware's xHCI state is therefore not there to adopt, and the link is down at EL2 (no CCS
  on either of U0's ports). HCE is clear here. **The cause is UNKNOWN:** a reset between the firmware's last use and EL2, the
  different topology, or the unit; one boot per topology cannot separate them.
* **Consequence for a stick writer at EL2 (INFERRED):** it has to bring the controller and the link up from a reset state.
  The PHY and repeater state are UNIMPLEMENTED and UNKNOWN (the study's M3: not measured).
* **The apps SMMU** (`0x15000000`): ID0 `0x7C017E9A` (154 stream match registers), ID1 `0x6000005F` (NUMCB 95, NUMS2CB 0, 4 KiB
  pages, NUMPAGENDXB 6), ID2 `0x5222` (IAS, OAS and UBS 40 bits; 4 KiB and 64 KiB granules), sCR0 `0x230406`, sGFSR 0, context
  bank base `0x15080000`. Streams `0x1420` and `0x1460` match stream match registers 3 and 4, and their S2CR is `TRANS` into
  context bank 3 (as in S0).
* **Context bank 3** (S0 had not read it): CBAR `0x35E03` is TYPE 3, stage 1 followed by stage 2 (`NESTED`), with the
  VMID/CBNDX field 3, MemAttr 5 and BPSHCFG 2; CBA2R `0x1` (VA64); SCTLR `0xE0` (M 0: **stage 1 is off**, only fault-report
  bits are set); TCR, TTBR0, TTBR1 and MAIR0 are 0 and TCR2 is `0x60`. FSR is `0x400`: a fault record is present, and bit 10 is
  not in the FSR bit list of Linux's `arm-smmu.h`, so its meaning is UNKNOWN (perhaps implementation-defined); FAR
  `0x953FDF7CF7F7` and FSYNR0 `0x46005D` are UNKNOWN in meaning too.

**What it decides, and what it does not.** The outcome is the row `WALK UNSUPPORTED STAGE2_ONLY` or `NESTED` of
[the outcomes table](SP11-PAYLOAD-USBSMMU.md#what-the-outcomes-mean-for-the-next-step), whose verdict is UNKNOWN and stays so.
Stage 1 is off and its table registers are zero, so the payload has no stage-1 tables to walk; stage 2 is not walked by this
payload, and where the stage-2 context is stays UNKNOWN (NUMS2CB is 0). So whether an EL2 xHCI driver's DMA reaches DRAM is
UNKNOWN, and SC2 is neither triggered nor cleared. What would decide it: a stage-2 walker payload (it must first find the
stage-2 context: UNKNOWN how, with NUMS2CB 0) or the S1 No-Op (it needs authorization A1, the first xHC register write at EL2;
NOT granted). Against the four questions the payload was built for:

| Question ([SP11-PAYLOAD-USBSMMU.md](SP11-PAYLOAD-USBSMMU.md#what-it-answers)) | Boot 5 |
| --- | --- |
| 1. What is context bank 3, and can its stage-1 tables be walked? | Answered: `NESTED`, stage 1 off (SCTLR.M 0); the walk is not possible (`WALK UNSUPPORTED NESTED`) |
| 2. Does it map DRAM identity, only the firmware's xHCI memory, or nothing? | Not decided: the walk did not run (UNKNOWN) |
| 3. What does the HCE tail look like? | HCE is clear (USBSTS `0x11`), `BERR` 0, sGFSR 0 and there are no TRBs; the bank's fault record (FSR `0x400`) is present and UNKNOWN in meaning; S0's HCE was not reproduced |
| 4. What are the firmware's slot contexts for the direct topology? | None to read: DCBAAP is 0 (`SLOTS=NO_DCBAAP`) |

## Payload `cpuon` (boot 7 and step 3)

`RETURN=0X0 STACK=OK LOADS=0 FAULTS=0 REFUSED=0 LINES=40 DROPPED=0`: the payload returned, made no guarded load and printed 40
lines, the most it may. It ran alone and is the first payload that changes the machine: from EL2 it started the eleven secondary
CPUs with PSCI `CPU_ON` and had each power itself off with `CPU_OFF`. Boot 7's page was photographed at an angle and is blurred in
places; step 3 of [the restart probe](#the-restart-probe) was filmed and its 45 lines are crisp, so the values below are step 3's
and boot 7's agree where they are legible. The page is in [SP11-PAYLOAD-CPUON.md](SP11-PAYLOAD-CPUON.md#what-the-unit-showed);
around it the runner printed `PAYLOAD LOADED INDEX=0 BASE=0XCE60A000 BYTES=18056 SHA=3B4BFDA7D59F923C TYPE=1` (boot 7: base
`0xCEA8B000`; step 2: `0xCE5E5000`), `READY FILES=1 RANGES=4 CODE=1`, `VERIFY=OK` and `CALL 0 3B4BFDA7D59F923C`. What it answered, OBSERVED:

| Asked or measured | Answer on the page | Decoded |
| --- | --- | --- |
| `AFFINITY_INFO` of the eleven MADT affinities | `OFF` each | powered down, as `psci` found in boot 5 |
| `CPU_ON` of `0X100` alone, entry the image base plus `0x1000` (`0xCE60B000`; boot 7: `0xCEA8C000`; `EfiLoaderCode`) | `0X0:SUCCESS` | accepted; the core reported and was seen OFF (`P1 NORMAL`) |
| eleven `CPU_ON` back to back, the same entry | `ISSUED=11 SUCCESS=11` | twelve calls answered 0, none refused; `CORES STARTED=11 REPORTED=11 OFF=11` |
| `CurrentEL` and `SCTLR_EL2` of a secondary, as found | `EL=2` and `0x30000000` | EL2, MMU and caches off (the register lines of nine cores) |
| `MPIDR_EL1`, `CNTFRQ_EL0`, `CNTVOFF_EL2`, the ID registers | `MPIDR=OK`, `FRQ=SAME`, `0X0`, `IDS=SAME` or `IDS=MIDR` | the MADT's affinities are the cores' own; the boot CPU's frequency; only `MIDR_EL1` differs |
| `MIDR_EL1` | `0x512F0011` (boot CPU, `0X100` to `0X300`), `0x511F0011` (clusters 1 and 2, six cores read) | the variant field, 2 against 1 |
| `HCR_EL2` and `VBAR_EL2` as found | `0x80000000` and 0 on seven cores; `0x1488000038` and the same upper-half address on two (`0X100`'s first start, `0X10200`) | E2H = 1 on two; the upper half differs between boots (below); `0X20200` and `0X20300` printed no register line |
| first counter read after `CPU_ON` returned (`DT_US`) | 45, then 288 to 476 for eight, about 2000 for two (boot 7: 263 to 456) | microseconds; a sample |

* **`VBAR_EL2` survived a `CPU_OFF` and a `CPU_ON` (OBSERVED once, step 3).** At its second start `0X100` read `VBAR_EL2`
  `0xCE60A800`, the image base plus `0x800`, the vector table its own stub had installed, not the `0xFFFFFF9CEA002800` of its first
  start (`HCR_EL2` was `0x1488000038` at both): a core's EL2 registers were kept or restored across the power cycle (one core, one
  cycle). Boot 7's blurred page read the same (INFERRED).
* **The upper half of `VBAR_EL2` differs between boots (OBSERVED).** `0X100`'s first start read `0xFFFFFFB460602800` in step 2 (a
  crisp photograph taken at the second pause, last line `NEXT CPU_ON ALL AFTER 8 S`, with `BASE=0XCE5E5000`, `CPU_ON` of `0X100`
  answered `0X0:SUCCESS`, `DT_US=47` and `HCR_EL2` `0x1488000038`) and `0xFFFFFF9CEA002800` in step 3; boot 7's blurred
  `0xFFFFFF...2800` agrees with the shape. What stays INFERRED is the reason: a randomised high-half EL2 image ran on those cores
  earlier; which software is unknown.
* **The line budget was reached.** Each of the eight cores of clusters 1 and 2 prints a third line for its differing `MIDR_EL1`
  (INFERRED for `0X20300`, whose report was dropped), so six lines were dropped (`SUPPRESSED=6`); the summary counts are
  unaffected. The cache rules held twice: no report was missing (that each rule is needed is not shown).
* **What it decides, and what it does not.** It answers whether the firmware's PSCI starts a core at an address a payload chose,
  in which exception level and state, and whether it takes it down again: yes, at EL2 with the MMU off, in a state that is not
  the same on every core, and yes. It does not show what the secure monitor validates in an entry address (the same kind of
  address was accepted, twelve times in each of two boots), whether another unit repeats this, or anything with a core kept
  running, an interrupt or a guest (UNIMPLEMENTED). No cause is claimed for the differing entry states or for `MIDR_EL1`
  differing by cluster.
* **The restart after boot 7.** The board restarted by itself after the last photograph (operator report; no photograph, no
  time). **The cause of the restart is UNKNOWN.** The page was complete and every started core had been seen OFF. `UPTIME 16 S`
  was the first heartbeat after the chain (see "The heartbeat" above), so
  the restart came seconds after the chain ended, not 16 s later (INFERRED from the heartbeat code and the operator's words;
  about `UPTIME 17 to 25 S`, no number was recorded). The restart coincides with the first payload that issued `CPU_ON` and
  `CPU_OFF`; whether it repeats, and what the plain page and a read-only payload did, is in
  [the restart probe](#the-restart-probe), [the restart control](#the-restart-control) and
  [SP11-PAYLOAD-CPUON.md](SP11-PAYLOAD-CPUON.md#the-restart).

## The restart probe

The plan `restart-probe` (2026-11-15, after boot 7) ran three boots from the same stick to see whether the restart repeats and
when. Each step was started by the operator and preceded by slbounce's `SLBOUNCE-DEVHE-MARK.EFI`.

| Step | What ran | What was seen |
| --- | --- | --- |
| 1 | a plain q1n1 EL2 page (`Q1N1.EFI --el2`), no runner | alive at `UPTIME 123 S` (photographed); then power-cycled by the operator |
| 2 | `Q1N1-PAYLOAD.EFI --el2` with `CPUON.BIN` again (the same 18,056 bytes and sha256 as boot 7) | the board restarted by itself (operator report); five photographs, all `UPTIME 0 S`, none of a finished page (the one at the second pause is crisp); no time |
| 3 | the same, filmed | the board stayed up (operator report); the video shows the finished page, crisp, from about `UPTIME 20 S` to about 36 S |

* **A restart was reported in two of the three `cpuon` boots (boot 7 and step 2); their times are UNKNOWN.** Boot 7's is INFERRED
  seconds after `UPTIME 16 S`; step 2's is INFERRED, weakly, at `UPTIME` about 41 S or earlier, possibly before its chain ended
  (the timing method below). Step 3 was OBSERVED alive through `UPTIME 36 S`; the operator's "stayed up" has no duration, so what
  followed the video is UNKNOWN.
* **INFERRED: the restart is not at one fixed `UPTIME`.** One at about 17 to 41 S would have shown in step 3's video through 36 S,
  unless it falls between 36 and 41 S.
* **The plain page is solid:** it was alive at `UPTIME 123 S`, so a restart is not a property of q1n1's plain page (a plain page
  once stayed up about 40 minutes: operator report, X1 stage, an older build), and q1n1's `--el2` flow has no reset path of its own
  (VERIFIED by reading `main.c`). The runner flow with a read-only payload is the control below.
* **A plan can never run unattended.** After a self-restart the unit follows its normal boot order and never boots the stick
  (operator report, as after boot 4), so every boot of the stick is started by the operator, and a restart ends the experiment.

**Timing method.** The phone's videos keep a QuickTime `creationdate` (the start of the recording, local time; stills lose their
EXIF) and the stick's Shell script writes a marker file before each step whose FAT timestamp is the firmware's clock, which reads
the same local time (resolution 2 s): 21:38:28, 21:41:20 and 21:42:50 for steps 1, 2 and 3. Step 3's video started at 21:42:47;
q1n1's page was drawn 6.5 s into it (21:42:53.5, `UPTIME 0 S`, 3.5 s after the marker), the chain returned at about `UPTIME 19 to
20 S`, `UPTIME 32 S` showed at 38.5 s and the video ended at about `UPTIME 36 S`. The markers of steps 2 and 3 are 90 s (plus or minus 2 s) apart:
the gap holds step 2's restart, the operator's reaction and power cycle, and the firmware boot up to the next marker. The last two
parts took 45 s once (step 1's `UPTIME 123 S` photograph, about 21:40:35, to step 2's marker), so, at the same pace, step 2
restarted at most about 45 s after its marker: `UPTIME` about 41 S or earlier (INFERRED, weak: it assumes that pace).

### The restart control

The plan `restart-control` (2026-11-16, after the probe) ran two more boots from the same stick, each started by the operator under
the same slbounce (`SLBOUNCE-DEVHE-MARK.EFI`) and with the same runner image as boot 7 and steps 2 and 3, but with a manifest that
lists only `PSCI.BIN` (the `psci` payload, 4,285 bytes: read-only, no `CPU_ON`, no `CPU_OFF`). The operator photographed each page
once and powered the unit off; two videos cover only the first seconds (22.6 s and 12.6 s). No restart was reported.

| Step | What ran | What the crisp photograph showed |
| --- | --- | --- |
| 1 | `Q1N1-PAYLOAD.EFI --el2` with `PSCI.BIN` alone | `UPTIME 224 S`; 231 memory-map descriptors; `PAYLOAD LOADED INDEX=0 BASE=0XCEAB3000 BYTES=4285 SHA=D391A9C8CBEECD00 TYPE=1` |
| 2 | the same | `UPTIME 268 S`; 227 descriptors; `PAYLOAD LOADED INDEX=0 BASE=0XCDDD4000 BYTES=4285 SHA=D391A9C8CBEECD00 TYPE=1` |

* **A read-only payload kept the page alive to `UPTIME 224 S` and `268 S` in two boots (OBSERVED once each).** Both pages carry the
  same 15 payload lines as boot 5's `psci` part (`PSCI_VERSION=0X10001:V1.1`, the eleven secondaries `OFF`,
  `SMCCC_VERSION=0X10001:V1.1`, `DONE INDEX=0 RETURN=0X0 STACK=OK LOADS=0 FAULTS=0 REFUSED=0 LINES=15 DROPPED=0`). What happened
  after each photograph is UNKNOWN. The two boots differ in their payload base and in the number of descriptors (231 and 227).
* **So the runner flow alone is not what restarts the board (INFERRED strongly: two boots, evidence and not proof).** If the runner
  flow itself restarted the board in 2 of 3 boots, two boots in a row surviving 224 s would have a chance of about 11 %. Boots 8 and 9
  ([below](#payloads-hashbig-and-el2mem-boots-8-and-9)) add two read-only boots with no restart in their videos, the longer to
  `UPTIME` about 110 S.
* **The restart is associated with `cpuon`, that is with `CPU_ON` and `CPU_OFF` of the secondary cores (INFERRED: a correlation over
  five boots, three of `cpuon` and two of `psci`; the cause is UNKNOWN, and so is the time of a restart).** A delayed reaction of a
  watchdog or of the firmware to the core power cycles is one hypothesis. What would narrow it down is in
  [SP11-PAYLOAD-CPUON.md](SP11-PAYLOAD-CPUON.md#the-restart): a `cpuon` variant that starts and stops one core only, one that leaves
  cores running, and a film of a `cpuon` page until it restarts.

By the timing method above (markers 00:16:02 and 00:20:42): step 1's page started about 4 s after its marker, at about 00:16:06, so
`UPTIME 224 S` was at about 00:19:50, 52 s before the next marker (power cycle, boot and countdown: consistent with the 45 s seen
before); step 2's page started at about 00:20:46, so `UPTIME 268 S` was at about 00:25:14.

## Payloads `hashbig` and `el2mem` (boots 8 and 9)

The plan `memhash` (2026-11-16, after the restart control) ran two boots from the same stick, boot 8 (step 1) and boot 9 (step 2),
each started by the operator under slbounce's `SLBOUNCE-DEVHE-MARK.EFI` (sha256 prefix `4107c28c`) with the runner image of boot 4
(`Q1N1-PAYLOAD.EFI --el2`, prefix `c2057909`). Its manifest lists, in call order, `HASHBIG.BIN` (9,412 bytes, `674D27954AFCC3EE`),
`EL2MEM.BIN` (12,834 bytes, `9F8156C1C1134AA0`) and `BIG.DAT` (150,994,944 bytes = 144 MiB, `F93155C96304AAD8`), a data file that the
runner loads and hashes and no payload is called on. Both payloads are read only ([`hashbig`](SP11-PAYLOAD-HASHBIG.md),
[`el2mem`](SP11-PAYLOAD-EL2MEM.md)); the sizes and digest prefixes on the `LOADED` lines are those of the binaries this tree builds.
Each boot was filmed; the values were read by hand from enlarged crops of the last frame of each video (119.9 s
and 62.8 s long) and are not CRC-checked. Both boots ended on the finished page, `PAYLOAD DONE INDEX=1 RETURN=0X0 STACK=OK LOADS=4
FAULTS=0 REFUSED=0 LINES=18 DROPPED=0`: the plan's stop rule never triggered (no page ended at a `NEXT ... AFTER 8 S` line, no fault
page) and neither video shows a restart.

Boot 9's page, 36 lines (boot 8's differs only where the next paragraph says; the page font has capitals only):

<!-- boot9-panel -->
```
PAYLOAD LOADED INDEX=0 BASE=0XCEA8D000 BYTES=9412 SHA=674D27954AFCC3EE TYPE=1
PAYLOAD LOADED INDEX=1 BASE=0XCEA88000 BYTES=12834 SHA=9F8156C1C1134AA0 TYPE=1
PAYLOAD LOADED INDEX=2 BASE=0XC3E65000 BYTES=150994944 SHA=F93155C96304AAD8 TYPE=2
PAYLOAD READY FILES=3 RANGES=6 CODE=2
PAYLOAD VERIFY=OK
PAYLOAD CALL 0 674D27954AFCC3EE
PAYLOAD HASHBIG START CURRENTEL=0X8 FREQ=19200000
PAYLOAD HASHBIG FILE INDEX=2 BASE=0XC3E65000 BYTES=150994944 MIB=144
PAYLOAD HASHBIG EXTENT ALLOCATED DESCRIPTORS=1
PAYLOAD HASHBIG ATTR FIRST=WB.OS.NS1 MID=WB.OS.NS1 LAST=WB.OS.NS1
PAYLOAD HASHBIG NEXT SHA256 BOX=25 S
PAYLOAD HASHBIG HASH BYTES=150994944 TICKS=14204400 MS=739 MIBS=194
PAYLOAD HASHBIG DIGEST F93155C96304AAD8 MATCH
PAYLOAD HASHBIG DONE MATCH
PAYLOAD DONE INDEX=0 RETURN=0X0 STACK=OK LOADS=0 FAULTS=0 REFUSED=0 LINES=8 DROPPED=0
PAYLOAD VERIFY=OK
PAYLOAD CALL 1 9F8156C1C1134AA0
PAYLOAD EL2MEM START CURRENTEL=0X8 FREQ=19200000
PAYLOAD EL2MEM MAP DESC=234 STRIDE=48 CONV_EXTENTS=17 CONV_MIB=31961
PAYLOAD EL2MEM KEY RESULT=WB.OS.NS1 PROBES=16014 FIRST=0X815A0000 LAST=0XFFFFFF000
PAYLOAD EL2MEM SCAN EXTENTS=17 PROBES=16014 ALL=MAPPED ATTR=WB SH=OS NS=1
PAYLOAD EL2MEM BANK CONV_MIB=30720 PROBES=15361 ALL=MAPPED RESULT=WB.OS.NS1
PAYLOAD EL2MEM CONTROL T1=WB.OS.NS1 T2=WB.OS.NS1 T3=WB.OS.NS1 T4=WB.OS.NS1 T5=WB.OS.NS1 T6=WB.OS.NS1
PAYLOAD EL2MEM CONTROL CODE=WB.OS.NS1 STACK=WB.OS.NS1
PAYLOAD EL2MEM LOAD BANK_FIRST(0X880000000)=0X1F8A08BE BANK_LAST(0XFFFFFFFFC)=0X9F6636DA
PAYLOAD EL2MEM LOAD LOW_FIRST(0XA8000000)=0X380001 LOW_LAST(0XC3E64FFC)=0X1D11B2F9
PAYLOAD EL2MEM ID DFR1=0X0 ISAR2=0X10000012 MMFR1=0X111111312120 PAN=3 VH=1 HAFDBS=0 PFR2=0X0
PAYLOAD EL2MEM ID AIDR=0X0 REVIDR=0X0 MDCR_EL2=0X6
PAYLOAD EL2MEM NEXT MDSCR_EL1 AFTER 8 S
PAYLOAD EL2MEM MDSCR_EL1 RAW=0X0
PAYLOAD EL2MEM NEXT OSLSR_EL1 AFTER 8 S
PAYLOAD EL2MEM OSLSR_EL1 RAW=0X8 OSLK=0
PAYLOAD EL2MEM NEXT ICC_SRE_EL2 AFTER 8 S
PAYLOAD EL2MEM ICC_SRE_EL2 RAW=0XF SRE=1 ENABLE=1
PAYLOAD EL2MEM DONE SCAN_ALL_MAPPED LOADS_OK=4 OF=4 HAZARD_READS=3
PAYLOAD DONE INDEX=1 RETURN=0X0 STACK=OK LOADS=4 FAULTS=0 REFUSED=0 LINES=18 DROPPED=0
```
<!-- /boot9-panel -->

**Boot 8's differences.** `HASH ... TICKS=14204370` (boot 9: `14204400`; `MS=739 MIBS=194` in both) and the four words `el2mem` read
from RAM: `BANK_FIRST(0X880000000)=0X59ADB1EB`, `BANK_LAST(0XFFFFFFFFC)=0XF30F158`, `LOW_FIRST(0XA8000000)=0X380001` and
`LOW_LAST(0XC3E64FFC)=0XEC6A2481` (boot 9: `0X1F8A08BE`, `0X9F6636DA`, `0X380001`, `0X1D11B2F9`). Three of the four words differ between
the boots; every address, size, count and attribute is the same.

**q1n1's own page** (boot 8, `UPTIME 101 S`) shows the registers of the left column above (the same `HCR_EL2`, `SCTLR_EL2`, `TCR_EL2`,
`TTBR0_EL2` and `MAIR_EL2`), `MEMORY DESCRIPTORS` `0xEA` (234: the
`MAP DESC=234` that `el2mem` read in place) and the six ranges the runner declared, each in one descriptor (`DESC=1`): the image at
`0xCE86F000` (size `0x163000`), the map at `0xCEA36000` (`0x40000`), the preload table at `0xCEA86000` (`0x13A0`), the payload at
`0xCEA88000`, the first file at `0xCEA8D000` (`0x3000`) and the second at `0xC3E65000` (`0x9000000`): the bases of the `LOADED` lines,
and the base and size `hashbig` found for `BIG.DAT`.

**What the unit answered** (OBSERVED in both boots unless a cell says otherwise):

| Asked | What the page says | Label |
| --- | --- | --- |
| Does EL2's own stage-1 map reach the 30 GiB bank, `0x880000000` to `0x1000000000`? (U1) | Yes, for reads: `SCAN EXTENTS=17 PROBES=16014 ALL=MAPPED` over 31,961 MiB of Conventional memory, `BANK CONV_MIB=30720 PROBES=15361 ALL=MAPPED` for the bank alone, and the guarded loads of the bank's first and last word answered (`LOADS_OK=4 OF=4`) | OBSERVED; only `AT S1E2R` and loads were made: whether the bank is writable at EL2 is UNKNOWN |
| With what attributes? | `WB.OS.NS1` for every probe and for the `CONTROL` pages (the firmware's types 1 to 6, the payload's code, its stack): Normal write-back, outer-shareable, `PAR_EL1.NS` set (what that means for a non-secure EL2 translation is UNKNOWN) | OBSERVED; the names are the payload's decode of `PAR_EL1` |
| Where did the runner put a 144 MiB file? (U6) | `FILE INDEX=2 BASE=0XC3E65000 ... MIB=144`: below 4 GiB, in one allocated descriptor (`EXTENT ALLOCATED DESCRIPTORS=1`; the runner allocates a data file as `EfiLoaderData`), `WB.OS.NS1` at its first, middle and last page; the same address in both boots | OBSERVED |
| How fast does plain C hash it at EL2, caches on? | `HASH BYTES=150994944 TICKS=14204400 MS=739 MIBS=194` (boot 8: `TICKS=14204370`): 739 ms, 194 MiB/s; `DIGEST F93155C96304AAD8 MATCH`: equal to the digest the runner computed before the bounce; the 25 s box was never near | OBSERVED; `MS` and `MIBS` are the arithmetic of the ticks at 19.2 MHz |
| What do the ID registers read? | `ISAR2=0X10000012 MMFR1=0X111111312120 PAN=3 VH=1 HAFDBS=0`, `DFR1=0X0 PFR2=0X0 AIDR=0X0 REVIDR=0X0`, `MDCR_EL2=0X6` | OBSERVED; the decode below is INFERRED |
| Do the three reads that may go to EL3 return? | Yes, each after its `NEXT` line and eight seconds: `MDSCR_EL1 RAW=0X0`, `OSLSR_EL1 RAW=0X8 OSLK=0`, `ICC_SRE_EL2 RAW=0XF SRE=1 ENABLE=1`, `HAZARD_READS=3`; no hang, no reset, no fault page | OBSERVED; that none was trapped to EL3 and emulated there is INFERRED (an EL3 handler that emulated a read would look the same) |

**The decode (INFERRED: the Arm ARM was not re-read; the payload itself prints only `PAN`, `VH`, `HAFDBS`, `OSLK`, `SRE` and `ENABLE`, and
they agree with the raw values beside them).** `MMFR1` `0x111111312120`: HAFDBS 0 (no hardware access/dirty update), VMIDBits 2, VH 1,
HPDS 2, LO 1, PAN 3, SpecSEI 1, XNX 1, TWED 1, ETS 1, HCX 1, AFP 1. `ISAR2` `0x10000012`: WFxT 2, RPRES 1, CLRBHB 1, GPA3 and APA3 0.
`MDCR_EL2` `0x6`: HPMN 6, no trap bit set. `OSLSR_EL1` `0x8`: OSLM `0b10`, OSLK 0 (the OS lock is not set). `ICC_SRE_EL2` `0xF`: SRE,
DFB, DIB and Enable all 1.

**Placement (INFERRED from the printed addresses).** The file ends at `0xCCE65000` (`0xC3E65000 + 0x9000000`), and the largest
Conventional extent below 4 GiB, from which `el2mem` loaded its two low words, runs from `0xA8000000` (`LOW_FIRST`) to `0xC3E65000`
(`LOW_LAST` is the word before it): 446 MiB.
Together they make 590 MiB, the size of the largest low extent in boot 6's map ([`el2mem`](SP11-PAYLOAD-EL2MEM.md)), so the runner
took the file from the top of that extent. One file size was seen by these boots, so that rule is INFERRED. The stick wrapper's dry run
(a Snapintosh wrapper, not a q1n1 payload) was given a second size, 144,665,408 bytes, and the runner put it at `0xC446E000`, which ends at
`0xCCE64B40`, the same top after page rounding (INFERRED: that run printed no extent); that it holds for every size is UNKNOWN.

**Timing** (frames of the videos, plus or minus 3 s; the markers are 09:21:12 and 09:28:54, as in
[the timing method](#the-restart-probe) above). Boot 9's video starts at the Shell's countdown: the autorun text and slbounce loading at
about 6 s, q1n1's page at about 12 s (EL2 reached after `ExitBootServices`), the first payload lines at about 18 s and the finished page
by about 42 s, so about 45 s from the Shell step to the end. The runner's read of the 144 MiB from the stick and its hash before the
bounce therefore fit into the six seconds or so between the autorun text and q1n1's page (INFERRED by subtraction: no frame shows
them). In both videos q1n1's status text shows again over the payload text now and then (at about 50 and 110 s of boot 8's video, 54 s
of boot 9's) and the payload text is back in the next frame, 10 s later. It is not a restart: `UPTIME` keeps counting (101 S at 110 s,
42 S at 54 s). The cause of the redraw is UNKNOWN.

**Not shown, UNKNOWN.** Whether the bank is writable at EL2 stage 1 (`el2mem` stores nothing and asks `AT S1E2R` only), whether a cache
clean reaches DRAM, and whether a page in the bank survives the bounce (nothing was placed there or compared across the bounce). And
the cause of the restart after `cpuon`: these boots issued no `CPU_ON` and neither video shows a restart (boot 8 to `UPTIME` about
110 S, boot 9 to 42 S and a few seconds more), which adds a longer read-only chain to [the restart control](#the-restart-control) and
changes none of its labels.

## Payloads `cnthctl` and `el1trap` (boot 11)

The plan `timers` (2026-11-16, 11:44, after the `memhash` boots) ran one autorun step from the same stick: slbounce's
`SLBOUNCE-DEVHE-MARK.EFI` (sha256 prefix `4107c28c`), then the runner of boot 4 (`Q1N1-PAYLOAD.EFI --el2`, prefix `c2057909`). Its
manifest (624 bytes) lists, in call order, `CNTHCTL.BIN` (3,094 bytes, `9F06B31DA4BDC395`) and `EL1TRAP.BIN` (15,156 bytes,
`5074712516C1CF08`): [`cnthctl`](SP11-PAYLOAD-CNTHCTL.md) writes one system register and [`el1trap`](SP11-PAYLOAD-EL1TRAP.md) seven, and
runs code below EL2. The operator authorised both by name and SHA-256 (about 11:20) for this one boot. The documents had proposed `cnthctl`
alone and `el1trap` on a stick of its own after that page was read; the operator chose one boot with one manifest, so `el1trap` ran without
that page read first, behind its own refusals: the operator's decision for this boot, and the stop rules stand. The sizes and digest
prefixes on the `LOADED` lines are those of the binaries this tree builds. The boot was filmed (61.2 s); the coordinator read the page below
from full-resolution crops of two frames (34 s and 38 s in) that agree on every line; it is not CRC-checked. Both payloads returned 0
(`RETURN=0X0 STACK=OK`) and printed `RESTORED=YES`; no refusal, no fault page, no stop rule, and the video shows no restart.

Boot 11's page, 37 lines (the page font has capitals only):

<!-- boot11-panel -->
```
PAYLOAD LOADED INDEX=0 BASE=0XCEA8D000 BYTES=3094 SHA=9F06B31DA4BDC395 TYPE=1
PAYLOAD LOADED INDEX=1 BASE=0XCEA88000 BYTES=15156 SHA=5074712516C1CF08 TYPE=1
PAYLOAD READY FILES=2 RANGES=5 CODE=2
PAYLOAD VERIFY=OK
PAYLOAD CALL 0 9F06B31DA4BDC395
PAYLOAD CNTHCTL CURRENTEL=0X8 HCR_EL2=0X88000010 E2H=0X0
PAYLOAD CNTHCTL ID_AA64MMFR0_EL1=0X2100122100001024 ECV=0X2
PAYLOAD CNTHCTL CNTHCTL_EL2 OLD=0X3 CNTFRQ_EL0=0X124F800
PAYLOAD CNTHCTL NEXT CNTHCTL_EL2 WRITE AFTER 8 S
PAYLOAD CNTHCTL OLD=0X3 V=0X6000
PAYLOAD CNTHCTL R=0X6000 R2=0X3
PAYLOAD CNTHCTL BITS13_14_STUCK=YES R_EQ_V=YES
PAYLOAD CNTHCTL RESTORED=YES
PAYLOAD DONE INDEX=0 RETURN=0X0 STACK=OK LOADS=0 FAULTS=0 REFUSED=0 LINES=8 DROPPED=0
PAYLOAD VERIFY=OK
PAYLOAD CALL 1 5074712516C1CF08
PAYLOAD EL1TRAP CURRENTEL=0X8 HCR_EL2=0X88000010 E2H=0X0
PAYLOAD EL1TRAP DAIF=0X3C0 SPSEL=0X1 CNTFRQ_EL0=0X124F800
PAYLOAD EL1TRAP ID_AA64MMFR0_EL1=0X2100122100001024 ECV=0X2
PAYLOAD EL1TRAP ID_AA64PFR0_EL1=0X1201201023111111 EL1=0X1
PAYLOAD EL1TRAP OLD CNTHCTL_EL2=0X3 SCTLR_EL1=0X100030D0198D
PAYLOAD EL1TRAP OLD VBAR_EL1=0XA7004000 VBAR_EL2=0XCE879000
PAYLOAD EL1TRAP STUB_OFFSET=0X1790 EL1_VECTORS_OFFSET=0X1000 EL2_VECTORS_OFFSET=0X800
PAYLOAD EL1TRAP NEXT EL1 EXCURSION AFTER 8 S
PAYLOAD EL1TRAP HVC_AT_EL2=OK
PAYLOAD EL1TRAP WRITES HCR_EL2=0X80000000 CNTHCTL_EL2=0X6000 SCTLR_EL1=0X30500800
PAYLOAD EL1TRAP NEXT EL1 EXCURSION
PAYLOAD EL1TRAP READBACK HCR_EL2=0X80000000 CNTHCTL_EL2=0X6000
PAYLOAD EL1TRAP READBACK SCTLR_EL1=0X30500980 VBAR_EL1_OFFSET=0X1000
PAYLOAD EL1TRAP CNTVCT_EL0 TRAPPED EC=0X18 ISS=0X34F801 ISS_OK=YES
PAYLOAD EL1TRAP CNTV_CTL_EL0 TRAPPED EC=0X18 ISS=0X32F827 ISS_OK=YES
PAYLOAD EL1TRAP CNTFRQ_EL0 NOT_TRAPPED VALUE=0X124F800
PAYLOAD EL1TRAP CNTPCT_EL0 CONTROL TRAPPED EC=0X18 ISS=0X32F861 ISS_OK=YES
PAYLOAD EL1TRAP VERDICT=TRAPS_EFFECTIVE BITS13_14_IN_READBACK=YES
PAYLOAD EL1TRAP EXCURSION OK ENTRIES=0X4 TRAPS=0X3
PAYLOAD EL1TRAP RESTORED=YES
PAYLOAD DONE INDEX=1 RETURN=0X0 STACK=OK LOADS=0 FAULTS=0 REFUSED=0 LINES=20 DROPPED=0
```
<!-- /boot11-panel -->

**What the unit answered** (OBSERVED unless a cell says otherwise):

| Asked | What the page says | Label |
| --- | --- | --- |
| T-HW1: does `CNTHCTL_EL2` hold the monitor's value, bits 14 and 13 included, and give the old one back? | `OLD=0X3 V=0X6000`, `R=0X6000 R2=0X3`, `BITS13_14_STUCK=YES R_EQ_V=YES`, `RESTORED=YES`: the register held exactly V and gave OLD back | OBSERVED |
| Does `HVC` work at EL2? | `HVC_AT_EL2=OK` | OBSERVED; that `SCR_EL3.HCE` is set and `HCR_EL2.HCD` clear is INFERRED |
| Can a runner payload run code below EL2 and come back? | `EXCURSION OK ENTRIES=0X4 TRAPS=0X3`, then `RESTORED=YES`: four entries into EL2 (three trapped reads and the final `HVC #0`) and the five registers as found | OBSERVED, the first runner payload to do so (the X2 image's T02 had run an EL1 stub with an `ERET` path on the unit: 2026-11-11 and 2026-11-14, OBSERVED, Snapintosh `docs/SURFACE-PRO-11.md`); that the stub ran at EL1 follows from the traps (INFERRED) |
| T-HW2: with V in `CNTHCTL_EL2`, do EL1 reads of `CNTVCT_EL0` and `CNTV_CTL_EL0` trap to EL2? | both `TRAPPED EC=0X18` with ISS `0X34F801` and `0X32F827` (`ISS_OK=YES`); `VERDICT=TRAPS_EFFECTIVE BITS13_14_IN_READBACK=YES` | OBSERVED |
| The controls | `CNTFRQ_EL0 NOT_TRAPPED VALUE=0X124F800` (19.2 MHz); `CNTPCT_EL0 CONTROL TRAPPED EC=0X18 ISS=0X32F861 ISS_OK=YES` | OBSERVED |
| Did the writes hold? | `READBACK HCR_EL2=0X80000000 CNTHCTL_EL2=0X6000`; `SCTLR_EL1` `0X30500980` for `0X30500800` written | OBSERVED; why two bits differ: INFERRED, below |

**The decode (INFERRED: the Arm ARM was not re-read).** The ISS of a trapped `MRS` is `(Op0 << 20) + (Op2 << 17) + (Op1 << 14) + (CRn << 10) + (Rt << 5)
+ (CRm << 1) + 1`: `0x34F801` is Op0 3, Op1 3, CRn 14, CRm 0, Op2 2, Rt 0, a read: `CNTVCT_EL0` into X0; `0x32F827` is `CNTV_CTL_EL0` (CRm 3,
Op2 1) into X1; `0x32F861` is `CNTPCT_EL0` (CRm 0, Op2 1) into X3. The payload checked all three itself (`ISS_OK=YES`). `SCTLR_EL1` `0x30500980` is
`0x30500800` plus bits 7 and 8, which the unit forces to 1 (they are also set in the old value): ITD and SED, RES1 with no AArch32 at EL0
(`ID_AA64PFR0_EL1` `0x1201201023111111`: `EL0` and `EL1` 1, AArch64 only). The payload compares only the bits that decide whether EL1 can be entered
and left, so it did not print `WRITE_NOT_HELD`. The old `SCTLR_EL1` `0x100030D0198D` has `M`, `C` and `I` set, the firmware's leftover EL1 state.

**What follows for the monitor port (INFERRED).** With the monitor's `CNTHCTL_EL2` formula, EL1 reads of `CNTVCT_EL0` and `CNTV_CTL_EL0` trap to EL2 with
the register's own ISS and `CNTFRQ_EL0` does not, for an EL1 stub under the payload's own `HCR_EL2` and `SCTLR_EL1`: option O1 of the port's timer
options (the A16 recipe) is **supported, not decided**; the guest's frequency, the `CNTVOFF_EL2` check and the read-back refusal stay the monitor's
own design. Whether bits 13 and 14 depend on `SCR_EL3.ECVEn` is UNKNOWN (the Arm ARM was not re-read); boot 11 neither confirms nor refutes the INFERRED
explanation of boot 4's `timer` stall (`ECVEn` clear).

**Timing** (frames of the video). The video starts at 11:44:26, at the Shell's countdown, and the Shell's marker `DONE1.TXT`
(`AUTORUN timers STEP 1 STARTED`, 31 bytes) is stamped 11:44. The autorun text shows at about 6 s, q1n1's page at about 10 s, the payload
text from about 14 s and the page is complete by about 30 s. q1n1's status text shows over it now and then
(`UPTIME 33 S` at 42 s, `49 S` at 58 s): not a restart. The stick, re-read at 11:49, holds every file of the staged tree byte for byte (but for
the known `SP11\SLBOUNCE.EFI`) and one new file, the Shell's `DONE1.TXT`: the payloads wrote nothing to it.

**Not shown, UNKNOWN.** The traps were measured for the payload's own `HCR_EL2` `0x80000000` and `SCTLR_EL1` `0x30500800`, not for the monitor's guest
regime (`HCR_EL2` with `VM`, `TVM` and the rest), which is the monitor's own test; one unit, one boot. The rest that no boot has shown is in
[Still UNKNOWN](#still-unknown).

## Payload `timer` (boot 4)

**It did not return, INFERRED from a line count; its lines were never read.** Boot 4 ran `psci`, `usbsmmu` and `timer`. The
right-hand panel held exactly 58 lines (counted from the geometry of a photograph that cut the column off; the text was not
captured). `UPTIME` stayed 0 S in both photographs, and the board rebooted by itself before the operator could take a third
(operator report). Reading the 58 lines with boot 5's per-payload counts (`psci` 15 lines, `usbsmmu` 17):

| Lines | Count |
| --- | --- |
| the notes: three `LOADED` and `READY` | 4 |
| `psci`: `VERIFY`, `CALL`, its 15 lines, `DONE` | 18 |
| `usbsmmu`: `VERIFY`, `CALL`, its 17 lines, `DONE` | 20 |
| `timer`: `VERIFY`, `CALL`, then 14 lines | 16 |
| the panel | 58 |

The 14th line the timer payload prints is `PAYLOAD TIMER NEXT CNTPOFF_EL2` ([its lines](SP11-PAYLOAD-TIMER.md#what-it-prints)). So,
**INFERRED**, and only if `psci` and `usbsmmu` printed as many lines in boot 4 as in boot 5 (not checked): the timer payload
stopped after `NEXT CNTPOFF_EL2`, that is, the read of CNTPOFF_EL2 at EL2 on this unit never returned and the board was reset.
The cause stays INFERRED (SCR_EL3.ECVEn clear, which traps the access to EL3; SCR_EL3 is not readable from EL2).
CNTVOFF_EL2 is not the culprit: boot 3's T03 read it at EL2 (0). That T03 skipped CNTPOFF_EL2 on purpose, read CNTFRQ_EL0
`0x124F800` (19.2 MHz) and CNTHCTL_EL2 `0x3` (ECV bit 0), saw the counter advance and finished, which supports, and does not
prove, the explanation of the five earlier freezes.

What follows for chains: a payload that stalls the board hides every earlier line of its chain unless the screen is
photographed within seconds; in boot 4 the two photographs missed the right-hand column and the board reset before a third.
`timer` is therefore run alone, not behind other payloads (see "Order" in
[the chain](SP11-PAYLOAD.md#the-chain-several-payloads-in-one-boot)); boot 5, which had no such payload, is the first boot whose
page stayed readable.

## Still UNKNOWN

* Why U0's state differs from S0's (a reset between the firmware's last use and EL2, the topology, or the unit).
* SMMU stage 2 for streams `0x1420` and `0x1460`, and whether DMA by an EL2 xHCI driver works.
* What the context bank's fault record means (FSR `0x400`, FAR, FSYNR0).
* Whether `timer` stalls at the CNTPOFF_EL2 read (INFERRED only), why (SCR_EL3.ECVEn clear is INFERRED; boot 11 neither confirms nor
  refutes it, [above](#payloads-cnthctl-and-el1trap-boot-11)), and what its own lines said.
* DRAM retention across a reset (the study's M10: NOT RUN). After boot 4's automatic reset the board booted something other
  than the stick (operator report), so a log path that dumps retained DRAM on the next stick boot needs the operator to boot the
  stick again, and whether DRAM survived is not known.
* Secondary CPU start (the study's M4): boot 7 and step 3 of the restart probe started the eleven secondaries (OBSERVED,
  [above](#payload-cpuon-boot-7-and-step-3)). What the secure monitor validates in an entry address beyond the image base plus
  `0x1000` (`0xCEA8C000`, `0xCE60B000`), and what a core kept running or a guest on it would do, are UNKNOWN.
* Why the board restarted by itself after boot 7 and in step 2 of the probe (the association with `cpuon`'s `CPU_ON` and `CPU_OFF` is
  INFERRED, a correlation over five boots; a delayed reaction of a watchdog or of the firmware to the core power cycles is
  untested; the runner flow alone is excluded by two long holds of a read-only payload, INFERRED strongly, evidence not proof), and
  when: boot 7 seconds after `UPTIME 16 S` and step 2 at `UPTIME` about 41 S or earlier are INFERRED only, and step 3 was seen alive
  through 36 S but not beyond. The next experiments are in [SP11-PAYLOAD-CPUON.md](SP11-PAYLOAD-CPUON.md#the-restart).
* Why the secondaries' EL2 state differs from core to core and, for the high half of `VBAR_EL2`, from boot to boot (OBSERVED; that
  a randomised high-half EL2 image ran there earlier is INFERRED, and which software is unknown), and why `MIDR_EL1` differs by
  cluster (no cause is claimed); the entry state of `0X20200` and `0X20300`, which no register line showed.
* The NVMe and PCIe state at EL2: boot 3's T06 never returned from its read of the ECAM of segment 3 (`0x740000000`) and the
  board rebooted by itself (operator report); a hang followed by a watchdog reset is INFERRED.
* Whether the region really holds 89 rows on the unit (the most seen on the panel is 58).
* The high bank (from `0x880000000`) is mapped write-back and readable at EL2 (OBSERVED, boots 8 and 9: `el2mem`'s probes and four
  loads), but whether it is writable at EL2 stage 1, whether a cache clean reaches DRAM there and whether a page there survives the
  bounce are UNKNOWN: every file the runner placed sat below 4 GiB, the 144 MiB one at `0xC3E65000`.
* Whether the runner places another file size at the top of the same low extent (INFERRED from one size), and that none of the
  three hazard reads of `el2mem` was trapped to EL3 and emulated there (all three returned; the page cannot tell: INFERRED only).
* Whether the `CNTHCTL_EL2` traps of boot 11 (an EL1 stub under `HCR_EL2` `0x80000000`, one unit, one boot) hold in the monitor's guest
  regime, and whether bits 13 and 14 depend on `SCR_EL3.ECVEn`. NOT RUN: the monitor's entry, the timer interrupt through the GIC (PPI 26),
  PAuth under QARMA5, a guest in the bank, the real kernelcache bundle, stage-2 syndromes, the wrapper's refusal paths and whether a
  `DC CVAC` alone reaches DRAM.
