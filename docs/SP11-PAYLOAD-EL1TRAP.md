<!-- SPDX-License-Identifier: MIT -->
# SP11 payload `el1trap`: does an EL1 read of the virtual counter and timer trap to EL2 with the monitor's CNTHCTL_EL2 value? (T-HW2)

`payloads/el1trap.c` is one payload of the stick payload runner described in [SP11-PAYLOAD.md](SP11-PAYLOAD.md): the manifest and
the stick files, [the chain](SP11-PAYLOAD.md#the-chain-several-payloads-in-one-boot), ABI v1 and the
[line catalogue](SP11-PAYLOAD.md#line-catalogue) are defined there and not repeated. Its predecessor is
[`cnthctl`](SP11-PAYLOAD-CNTHCTL.md) (T-HW1: do bits 13 and 14 of `CNTHCTL_EL2` stick), the first payload that wrote an EL2 register,
and its closest relative [`cpuon`](SP11-PAYLOAD-CPUON.md), the first that ran code of its own on another core and the source of the
cache rule used here. Evidence labels as there: VERIFIED, OBSERVED, INFERRED, EXPERIMENTAL, UNIMPLEMENTED, UNKNOWN.
**EXPERIMENTAL; hardware NOT RUN.** It only runs after `cnthctl` has said `BITS13_14_STUCK=YES` with `RESTORED=YES`.

`el1trap` answers the second question of the Surface Pro 11 monitor port (Snapintosh `docs/SP11-MONITOR-PORT.md`, section 6,
experiment T-HW2): **with `CNTHCTL_EL2` holding the monitor's value, does a read of `CNTVCT_EL0` or of `CNTV_CTL_EL0` made at EL1 trap
to EL2 (`ESR_EL2` class `0x18`), or does it return a value?** `cnthctl` can only show that the register holds the bits; a register
can hold bits that do nothing (the Arm text for the ECV-gated fields, INFERRED, not re-read here: with `SCR_EL3.ECVEn` clear they
are expected to do nothing while a direct read may still show them). "Stuck but inert" is told apart from "effective" only by an
access made at EL1. This payload makes it: a five-instruction stub at EL1, a handler at EL2, and a page that says for each read
whether it trapped. **No value of this payload has been OBSERVED on the unit.**

It is the first payload that **runs code below EL2**, and it writes seven EL2 and EL1 system registers. It needs the operator's
named, SHA-256-pinned authorisation before any run on the unit ([Authorisation](#authorisation-and-the-stop-rule)). This document
asks for it; it is not it.

## What it does, in order

1. **Where it runs, and what it refuses.** Not at EL2 it prints `SKIPPED_NOT_AT_EL2` and returns. At EL2 it refuses a runner with no
   counter op (`REFUSED=NO_COUNTER`). It then reads its context (`HCR_EL2`, `DAIF`, `SPSel`, `CNTFRQ_EL0`, `ID_AA64MMFR0_EL1`,
   `ID_AA64PFR0_EL1`, `CNTHCTL_EL2` as OLD, `SCTLR_EL1`, `VBAR_EL1`, `VBAR_EL2`) and prints six lines, and refuses, before anything
   is written, in this order: an image whose stub or vector tables are not 2 KiB aligned inside it (`REFUSED=ENTRY`); `HCR_EL2.E2H`
   set (`REFUSED=E2H`: an `MSR SCTLR_EL1` would then write `SCTLR_EL2`); no AArch64 EL1 (`REFUSED=NO_EL1_AARCH64`); `DAIF` not all
   masked (`REFUSED=DAIF_NOT_MASKED`); `SPSel` not 1 (`REFUSED=SPSEL_NOT_EL2H`: the handler runs on the SP the payload had); OLD with
   bit 12, 13 or 14 set (`REFUSED=OLD_HAS_BITS_12_TO_14`); less than 16 KiB of its stack left (`REFUSED=STACK`).
2. **Announce, then wait eight seconds.** `NEXT EL1 EXCURSION AFTER 8 S`, then eight seconds on the runner's counter, so that a hang or a
   reset leaves a page that was already photographed. A counter that does not run (two million equal reads in a row) ends the payload
   with `REFUSED=COUNTER_STUCK`: nothing was written.
3. **Make the image visible to a core that fetches without its caches.** `DC CIVAC` over the whole image, `DSB`, `IC IVAU` over it,
   `DSB`, `ISB`, in 16-byte steps (the smallest line the architecture allows). EL1 runs with its MMU and caches off (below), so its
   instruction fetches see physical memory, not this core's data cache: the stub and the vector tables the payload just built must
   have reached it. This is `cpuon`'s rule for a core that starts with its caches off, for the same reason. That the image is
   identity mapped (VA = PA) is OBSERVED on the unit by `cpuon`, whose `CPU_ON` entry address is a pointer to its own stub.
4. **The probe.** `HVC #2` at EL2 under the payload's own EL2 vectors, before anything but `VBAR_EL2` has been changed. HVC is
   enabled by `SCR_EL3.HCE` and `HCR_EL2.HCD` (INFERRED), and an HVC that is UNDEFINED at EL1 would send the EL1 vectors, which
   report by HVC, into a loop nothing could end. If the probe does not come back as an HVC the payload prints `HVC_AT_EL2=FAILED`
   and why, `REFUSED=HVC_AT_EL2`, puts `VBAR_EL2` back and returns 2: **no EL1 code runs.** Otherwise `HVC_AT_EL2=OK`.
5. **Announce again, then the window.** The `WRITES` line, `NEXT EL1 EXCURSION`, then, with **no line printed from the first write to
   the last read-back**: write `VBAR_EL1`, `SCTLR_EL1`, `CNTHCTL_EL2`, `HCR_EL2` (in that order), `ISB`, read the four back. If one of the
   bits that decide whether EL1 can be entered and left is not as written (`HCR_EL2` RW, E2H, TGE, VM, HCD, FMO, IMO, AMO;
   `SCTLR_EL1` M, A, C, I, WXN, E0E, EE; the whole of `VBAR_EL1`; `CNTHCTL_EL2.ECV`) nothing is run: `REFUSED=WRITE_NOT_HELD`.
6. **The excursion** (`el1trap_run`, assembly). It saves `x19`-`x30`, `SP`, `SPSR_EL2`, `ELR_EL2` and `VBAR_EL2`, installs the payload's EL2
   vector table **before the first `ERET`**, and `ERET`s to the stub at EL1h with `D`, `A`, `I`, `F` masked. Every exception to EL2 enters one
   handler (below), which records each trapped read, skips it, and ends the excursion on the stub's `HVC #0` or, with a reason, on
   anything else. Ending is an `ERET` to the code after the first one, at EL2h, which restores what it saved and returns.
7. **Put back, in the reverse order, and report.** `HCR_EL2`, `CNTHCTL_EL2`, `SCTLR_EL1`, `VBAR_EL1`, `ISB`; then all five registers
   (those four and `VBAR_EL2`) are read back and each one that differs gets **one more write**: the only retry. A register that still
   differs is `NOT_RESTORED`, loudly, and the payload returns **3**. The page reports the read-back, each access, the verdict and the end.

Returns: 0 if the stub finished at its `HVC #0` and everything is back; 2 if the excursion did not run or ended any other way and
everything is back; 3 if a register could not be put back. A return value never stops the chain, but the page says it and the stop rule does.

## What it writes, and why each value

<!-- el1trap-write -->
| Register | Written by | Value | When |
| --- | --- | --- | --- |
| `VBAR_EL2` | `el1trap_run` | the payload's EL2 vector table, then the value found | installed before the first `ERET` or `HVC`, put back before it returns (probe and excursion); one more write from C if the put-back did not hold |
| `SPSR_EL2`, `ELR_EL2` | `el1trap_run` and its handler | `0x3C5` and the stub's address; the next instruction after each trapped read; `0x3C9` and the resume address | saved first, restored before it returns |
| `VBAR_EL1` | C | the payload's EL1 vector table | first of the four writes |
| `SCTLR_EL1` | C | `0x30500800` | second |
| `CNTHCTL_EL2` | C | V, the monitor's formula (below) | third |
| `HCR_EL2` | C | `0x80000000` | fourth |
| the same four | C | as found, in the reverse order, and once more each if it differs | after the excursion |
<!-- /el1trap-write -->

The formula for V, V = `(OLD & ~3) | (1 << 14) | (1 << 13)`, is VERIFIED against the monitor's source (`guest_cnthctl = (save_cnthctl & ~3UL) | (1UL<<14) | (1UL<<13)`,
`probes/xnuboot/prepare.c`; the test compares it when `SNAPINTOSH_DIR` names the tree). `HCR_EL2` is `RW` only:

<!-- el1trap-hcr -->
| Bit | Name | Value | Why |
| --- | --- | --- | --- |
| 31 | `RW` | set | EL1 is AArch64 |
| 34 | `E2H` | clear | the non-VHE layout; set is refused before anything is written |
| 27 | `TGE` | clear | no routing of EL1 to EL2 |
| 0 | `VM` | clear | no stage 2: the stub and the vectors are fetched by physical address |
| 29 | `HCD` | clear | HVC is enabled: the stub and the EL1 vectors end by HVC |
| 5:3 | `AMO`, `IMO`, `FMO` | clear | no physical interrupt or SError is routed to EL2 while EL1 runs (and none is taken at EL1: `SPSR_EL2` masks `D`, `A`, `I`, `F`) |
| the rest | every trap bit | clear | only what `CNTHCTL_EL2` traps reaches EL2 |
<!-- /el1trap-hcr -->

`SCTLR_EL1 = 0x30500800` has the MMU and both caches off, no alignment check, little endian, and the bits that are RES1 or "legacy"
in the architecture set: it is `INIT_SCTLR_EL1_MMU_OFF` of Linux (VERIFIED against that name in commit 7475ea8b5861, GPL-2.0-only,
facts only, nothing copied; the test compares it when `LINUX_DIR` names a tree). An earlier value with `SPAN` set was wrong. `SPAN` clear
means an exception taken to EL1 sets `PSTATE.PAN`: OBSERVED under QEMU in the `SPSR_EL2` an EL1 vector's HVC saves (`0x4023C5`).

<!-- el1trap-sctlr -->
| Bit | Name | Value | Why |
| --- | --- | --- | --- |
| 0 | `M` | clear | MMU off: the stub runs at a physical address |
| 1 | `A` | clear | no alignment check |
| 2 | `C` | clear | no data cache: the stub touches no memory |
| 12 | `I` | clear | no instruction cache for EL1 (instruction fetches are then Normal Non-cacheable, INFERRED), hence the cache work |
| 19 | `WXN` | clear | no write-implies-execute-never |
| 24 | `E0E` | clear | little endian at EL0 |
| 25 | `EE` | clear | little endian at EL1 |
| 29, 28, 22, 20, 11 | `LSMAOE`, `nTLSMD`, `EIS`, `TSCXT`, `EOS` | set | as Linux sets them with the MMU off: RES1 or the legacy behaviour (INFERRED) |
<!-- /el1trap-sctlr -->

The bits of `CNTHCTL_EL2`, for the `HCR_EL2.E2H = 0` layout the unit runs in, as in [`cnthctl`](SP11-PAYLOAD-CNTHCTL.md):

<!-- el1trap-bits -->
| Bit | Name | In V | Source |
| --- | --- | --- | --- |
| 0 | `EL1PCTEN` (EL1 and EL0 access to the physical counter) | cleared | the monitor's formula; the **control** below uses it |
| 1 | `EL1PCEN` (EL1 and EL0 access to the physical timer) | cleared | the same |
| 11:2 | the event stream and the rest of the layout | as found in OLD | V keeps them |
| 12 | `ECV` | **never set** | OLD with it set is refused; the payload never sets it |
| 13 | `EL1TVT` (traps the EL1 virtual timer registers) | set | `prepare.c`; FEAT_ECV level 1 |
| 14 | `EL1TVCT` (traps the EL1 virtual counter) | set | `prepare.c`; FEAT_ECV level 1 |
<!-- /el1trap-bits -->

What it never touches, and a test checks the source and the binary for each: **`CNTPOFF_EL2`** (a read of it never returned on this
unit and the board restarted, INFERRED from a line count), `CNTVOFF_EL2`, `CNTKCTL_EL1`, `CNTHCTL_EL2.ECV` (bit 12), `SP_EL1`, the
timer control registers, any device. The stub reads `CNTVCT_EL0`, `CNTV_CTL_EL0`, `CNTFRQ_EL0` and `CNTPCT_EL0` and nothing else.

## The EL1 stub, the vector tables and the handler

The stub is position independent, five instructions, no branch, no memory access, no stack. The destination register says which read it was,
and each trapped read is recorded with its `ESR_EL2` and the `ELR_EL2` of the instruction. The first three are the brief's; the fourth is
an **added control**: a read of `CNTPCT_EL0` with `CNTHCTL_EL2.EL1PCTEN` clear (bit 0 of V) is trapped by an Armv8.0 bit that needs no ECV
(INFERRED, not re-read), so it separates "the ECV traps are inert" from "no trap of this setup ever reaches EL2".

<!-- el1trap-stub -->
| Instruction | Expected if the traps are effective | ISS if trapped |
| --- | --- | --- |
| `mrs x0, cntvct_el0` | traps (`EL1TVCT`) | `0x34F801` |
| `mrs x1, cntv_ctl_el0` | traps (`EL1TVT`) | `0x32F827` |
| `mrs x2, cntfrq_el0` | does not trap: no bit of `CNTHCTL_EL2` traps it (INFERRED) | `0x30F841` |
| `mrs x3, cntpct_el0` | the control: traps, whatever ECV does | `0x32F861` |
| `hvc #0` | the stub is finished: returns to EL2 | - |
<!-- /el1trap-stub -->

The ISS of a trapped `MRS` is `Op0 << 20 | Op2 << 17 | Op1 << 14 | CRn << 10 | Rt << 5 | CRm << 1 | 1` (the last bit: a read), the layout of the
architecture (INFERRED, not re-read) and the numbers above OBSERVED under QEMU. With `IL` set the whole `ESR_EL2` is `0x62000000` plus the ISS. A trap whose
class is not `0x18` or whose ISS is not the register's prints `ISS_OK=NO`.

Both vector tables are 2 KiB aligned (`VBAR_ELx` keeps bits 10:0 reserved), 16 entries 128 bytes apart. Every EL2 entry is
`mov x15, #n; b handler`; every EL1 entry is `mov x16, #n; hvc #1`, so that an exception at EL1 is reported, never a hang. The handler, with
`x15` the entry:

<!-- el1trap-handler -->
| Entry | What | Action |
| --- | --- | --- |
| 8 (lower EL, AArch64, synchronous), class `0x18` | a trapped `MRS` | record `ESR_EL2` and `ELR_EL2`, `ELR_EL2 += 4`, `ERET` to the stub |
| 8, class `0x16` (HVC), immediate 0 | the stub finished | end: the excursion is OK |
| 8, class `0x16`, immediate 1 | an EL1 vector reported an exception | record `ESR_EL1`, `ELR_EL1`, `FAR_EL1` and the vector: `EL1_EXCEPTION` |
| 8, class `0x16`, another immediate | `UNEXPECTED_HVC_IMM` | end |
| 8, another class | `UNEXPECTED_CLASS` | end |
| 4 (current EL, synchronous), `HVC #2` | the probe | set `probe_ok`, `ERET` |
| 4, anything else | an exception of EL2 itself: `EL2_EXCEPTION` | end |
| any other | an interrupt, an SError, an AArch32 entry: `UNEXPECTED_VECTOR` | end |
<!-- /el1trap-handler -->

The excursion is bounded, as far as it can be:

<!-- el1trap-bounds -->
| Bound | Value | What happens at it |
| --- | --- | --- |
| entries | 8: the ninth ends it | `BUDGET` |
| trap records | 8 | `BUDGET` |
| deadline | 1 second of `CNTPCT_EL0`, checked at every entry | `DEADLINE` |
| a handler that faults | 24 entries | `VBAR_EL2` as found is put back and `UDF` executes: the runner's own fault page |
| the stub | 5 instructions, no branch | at most five instructions run between entries |
| an EL1 vector entry | 2 instructions | the same |
| the wait before | 8 seconds | a page photographed before anything is written |
| stack kept | 16 KiB | `REFUSED=STACK` |
<!-- /el1trap-bounds -->

**What is not bounded:** an instruction that never completes, and EL1 code that never reaches an entry (no timer interrupt is armed: arming one
would write more registers and a GIC). The stub cannot loop, and the EL1 vectors only report, so the second is not expected; a stub that
never returns is the test's `hang` world. The last line on the page, `NEXT EL1 EXCURSION`, names it, as for every payload.

## The instructions it uses, and why

Checked by `tools/sp11_payload_testlib.py`, by the disassembly and, independently, by the encoding of every aligned word of its code. Its policy
uses the `allow` key for forms the engine did not yet know, as data rows (`ALLOW_WORDS`) and no engine logic: `msr` to seven registers, three `hvc`
immediates, `eret`, `dc civac`, `ic ivau`. The older policies are unchanged.

<!-- el1trap-instructions -->
| Kind | Operands allowed | Sites | Where | Why |
| --- | --- | --- | --- | --- |
| `MRS` | `CurrentEL`, `HCR_EL2`, `DAIF`, `SPSel`, `CNTFRQ_EL0`, `ID_AA64MMFR0_EL1`, `ID_AA64PFR0_EL1`, `CNTHCTL_EL2`, `SCTLR_EL1`, `VBAR_EL1`, `VBAR_EL2`, `SPSR_EL2`, `ELR_EL2`, `ESR_EL2`, `FAR_EL2`, `CNTPCT_EL0`, `ESR_EL1`, `ELR_EL1`, `FAR_EL1`, `CNTVCT_EL0`, `CNTV_CTL_EL0` | 27 | context, read-backs, the handler, the stub's four | what it reports |
| `MSR` | `VBAR_EL2` 4, `ELR_EL2` 4, `SPSR_EL2` 3, `HCR_EL2` 1, `CNTHCTL_EL2` 1, `SCTLR_EL1` 1, `VBAR_EL1` 1 | 15 | one C helper each; the assembly | the only writes |
| `HVC` | `#1` 16, `#0` 1, `#2` 1 | 18 | the EL1 vector entries; the stub; the probe | report, finish, probe |
| `ERET` | - | 4 | to the stub; after the probe; after a trapped read; to the resume code | the excursion |
| `DC CIVAC` | - | 1 | one helper, over the whole image | the image reaches memory |
| `IC IVAU` | - | 1 | one helper, over the whole image | the instruction cache drops its lines |
| `DSB` | - | 1 | one helper, called twice | the cache work has completed |
| `ISB` | - | 4 | one helper; the assembly | the writes have taken effect |
| `UDF` | - | 1 | the handler's fatal path | the runner's fault page |
<!-- /el1trap-instructions -->

Nothing else: no other `MSR` (the policy names every allowed one), no `DMB`, no `TLBI`, `AT`, `SYS`, `SMC`, `SVC`, `WFI`, `WFE`, `SEV`, no exclusive or atomic
instruction, and **neither `CNTPOFF_EL2` nor `CNTVOFF_EL2` is named** by the source or the binary.

## What it prints

At most 37 lines (the ABI allows 40; the runner adds three more), each at most 100 characters in the page font and never cut: a line holds at most
three 64-bit values. Every line begins `PAYLOAD EL1TRAP `. Values are printed as the runner's hex op prints them (`0X` and capitals).

<!-- el1trap-lines -->
| Line | Meaning |
| --- | --- |
| `SKIPPED_NOT_AT_EL2` | CurrentEL is not EL2: nothing else was done |
| `REFUSED=NO_COUNTER` | the runner gave no counter: nothing else was done |
| `CURRENTEL=0X8 HCR_EL2=0X.. E2H=0X0` | the exception level, `HCR_EL2` and its E2H bit |
| `DAIF=0X.. SPSEL=0X.. CNTFRQ_EL0=0X..` + ` FREQ=DEFAULT` | the masks, the stack pointer selected, the frequency; `FREQ=DEFAULT` if it is outside 1 MHz to 1 GHz and 19.2 MHz is used |
| `ID_AA64MMFR0_EL1=0X.. ECV=0X..` | the ID register and its ECV field (2 on the unit: OBSERVED) |
| `ID_AA64PFR0_EL1=0X.. EL1=0X..` | the ID register and its EL1 field |
| `OLD CNTHCTL_EL2=0X.. SCTLR_EL1=0X..` | the two registers as found |
| `OLD VBAR_EL1=0X.. VBAR_EL2=0X..` | the two as found |
| `REFUSED=ENTRY` | the stub or a table is not inside the image or not aligned: nothing was written |
| `STUB_OFFSET=0X.. EL1_VECTORS_OFFSET=0X.. EL2_VECTORS_OFFSET=0X..` | where they are in the image |
| `REFUSED=E2H`, `REFUSED=NO_EL1_AARCH64`, `REFUSED=DAIF_NOT_MASKED`, `REFUSED=SPSEL_NOT_EL2H`, `REFUSED=OLD_HAS_BITS_12_TO_14`, `REFUSED=STACK` | a precondition: nothing was written |
| `NEXT EL1 EXCURSION AFTER 8 S` | what follows starts eight seconds after this line |
| `REFUSED=COUNTER_STUCK` | the counter does not run: the wait cannot be made and nothing was written |
| `HVC_AT_EL2=OK` | the probe came back as an HVC |
| `HVC_AT_EL2=FAILED NONE\|EL2_EXCEPTION ENTRIES=0X.. VECTOR=0X..`, `HVC_AT_EL2 ESR_EL2=0X.. ELR_EL2=0X..`, `REFUSED=HVC_AT_EL2` | it did not (or `VBAR_EL2` did not come back): no EL1 code ran |
| `WRITES HCR_EL2=0X.. CNTHCTL_EL2=0X.. SCTLR_EL1=0X..` | the values about to be written (the fourth is the EL1 table's address, which depends on the load address, shown in the next lines) |
| `NEXT EL1 EXCURSION` | from here no line is printed until the registers are back |
| `READBACK HCR_EL2=0X.. CNTHCTL_EL2=0X..`, `READBACK SCTLR_EL1=0X.. VBAR_EL1_OFFSET=0X..` | the four read back after the writes; the last is `VBAR_EL1` minus the image's base |
| `REFUSED=WRITE_NOT_HELD` | a bit that matters is not as written: nothing was run |
| `CNTVCT_EL0`, `CNTV_CTL_EL0`, `CNTFRQ_EL0`, `CNTPCT_EL0 CONTROL` + ` TRAPPED EC=0X.. ISS=0X.. ISS_OK=YES\|NO` or ` NOT_TRAPPED VALUE=0X..` | each read: trapped, with the class and the ISS and whether they are the register's, or the value it returned |
| `VERDICT=TRAPS_EFFECTIVE\|TRAPS_INERT\|TRAPS_PARTIAL\|CONTROL_NOT_TRAPPED BITS13_14_IN_READBACK=YES\|NO\|PARTIAL` + ` CNTFRQ_EL0_TRAPPED` | the answer (the table below) and whether bits 13 and 14 read back set |
| `EXCURSION OK ENTRIES=0X.. TRAPS=0X..` | the stub finished at its `HVC #0` |
| `EXCURSION NONE\|BUDGET\|DEADLINE\|UNEXPECTED_VECTOR\|UNEXPECTED_CLASS\|UNEXPECTED_HVC_IMM\|EL1_EXCEPTION\|EL2_EXCEPTION\|UNKNOWN_REASON ENTRIES=0X.. TRAPS=0X.. VECTOR=0X..` | it ended another way (`UNKNOWN_REASON` for a code outside this list); then `ESR_EL2=0X.. ELR_EL2=0X..`, `FAR_EL2=0X.. SPSR_EL2=0X..`, for an EL1 exception `ESR_EL1=0X.. ELR_EL1=0X..` and `FAR_EL1=0X.. EL1_VECTOR=0X..`, one `TRAP ESR_EL2=0X.. ELR_EL2=0X..` per record, and `ACCESSES_NOT_CLASSIFIED` |
| `RESTORE_RETRY <register> NOW=0X..` | that register was not as found: the one retry, and what it read back |
| `RESTORED=YES` | all five registers are as found |
| `RESTORED=NO`, `NOT_RESTORED <register> WANT=0X.. NOW=0X..`, `POWER_CYCLE_BEFORE_ANY_OTHER_PAYLOAD` | they are not, after the retry: the payload returns 3 |
<!-- /el1trap-lines -->

The pages of the host model for the machines the host test scripts (the unit-like world: EL2, `HCR_EL2` `0x88000010`, ECV 2, 19.2 MHz, OLD `0x3`; **the
values are the model's, not a unit's**: EXPERIMENTAL, the program the host test pins line by line). The machine whose traps are effective:

<!-- el1trap-page -->
```
PAYLOAD EL1TRAP CURRENTEL=0X8 HCR_EL2=0X88000010 E2H=0X0
PAYLOAD EL1TRAP DAIF=0X3C0 SPSEL=0X1 CNTFRQ_EL0=0X124F800
PAYLOAD EL1TRAP ID_AA64MMFR0_EL1=0X2100032310201126 ECV=0X2
PAYLOAD EL1TRAP ID_AA64PFR0_EL1=0X1301001121110222 EL1=0X2
PAYLOAD EL1TRAP OLD CNTHCTL_EL2=0X3 SCTLR_EL1=0X30C50838
PAYLOAD EL1TRAP OLD VBAR_EL1=0X0 VBAR_EL2=0X5C155000
PAYLOAD EL1TRAP STUB_OFFSET=0X1000 EL1_VECTORS_OFFSET=0X800 EL2_VECTORS_OFFSET=0X0
PAYLOAD EL1TRAP NEXT EL1 EXCURSION AFTER 8 S
PAYLOAD EL1TRAP HVC_AT_EL2=OK
PAYLOAD EL1TRAP WRITES HCR_EL2=0X80000000 CNTHCTL_EL2=0X6000 SCTLR_EL1=0X30500800
PAYLOAD EL1TRAP NEXT EL1 EXCURSION
PAYLOAD EL1TRAP READBACK HCR_EL2=0X80000000 CNTHCTL_EL2=0X6000
PAYLOAD EL1TRAP READBACK SCTLR_EL1=0X30500800 VBAR_EL1_OFFSET=0X800
PAYLOAD EL1TRAP CNTVCT_EL0 TRAPPED EC=0X18 ISS=0X34F801 ISS_OK=YES
PAYLOAD EL1TRAP CNTV_CTL_EL0 TRAPPED EC=0X18 ISS=0X32F827 ISS_OK=YES
PAYLOAD EL1TRAP CNTFRQ_EL0 NOT_TRAPPED VALUE=0X124F800
PAYLOAD EL1TRAP CNTPCT_EL0 CONTROL TRAPPED EC=0X18 ISS=0X32F861 ISS_OK=YES
PAYLOAD EL1TRAP VERDICT=TRAPS_EFFECTIVE BITS13_14_IN_READBACK=YES
PAYLOAD EL1TRAP EXCURSION OK ENTRIES=0X4 TRAPS=0X3
PAYLOAD EL1TRAP RESTORED=YES
```
<!-- /el1trap-page -->

The tails of the other worlds (the first eleven lines are the same except where stated). Bits that do not stick (RES0); bits that stick but are inert;
only bit 14 sticks; the control does not trap; the probe's HVC is UNDEFINED; a write that does not hold (`E2H` comes up set); a register not put back:

<!-- el1trap-pages -->
```
# bits do not stick
PAYLOAD EL1TRAP READBACK HCR_EL2=0X80000000 CNTHCTL_EL2=0X0
PAYLOAD EL1TRAP READBACK SCTLR_EL1=0X30500800 VBAR_EL1_OFFSET=0X800
PAYLOAD EL1TRAP CNTVCT_EL0 NOT_TRAPPED VALUE=0X123456789
PAYLOAD EL1TRAP CNTV_CTL_EL0 NOT_TRAPPED VALUE=0X0
PAYLOAD EL1TRAP CNTFRQ_EL0 NOT_TRAPPED VALUE=0X124F800
PAYLOAD EL1TRAP CNTPCT_EL0 CONTROL TRAPPED EC=0X18 ISS=0X32F861 ISS_OK=YES
PAYLOAD EL1TRAP VERDICT=TRAPS_INERT BITS13_14_IN_READBACK=NO
PAYLOAD EL1TRAP EXCURSION OK ENTRIES=0X2 TRAPS=0X1
PAYLOAD EL1TRAP RESTORED=YES
# stuck but inert
PAYLOAD EL1TRAP READBACK HCR_EL2=0X80000000 CNTHCTL_EL2=0X6000
PAYLOAD EL1TRAP READBACK SCTLR_EL1=0X30500800 VBAR_EL1_OFFSET=0X800
PAYLOAD EL1TRAP CNTVCT_EL0 NOT_TRAPPED VALUE=0X123456789
PAYLOAD EL1TRAP CNTV_CTL_EL0 NOT_TRAPPED VALUE=0X0
PAYLOAD EL1TRAP CNTFRQ_EL0 NOT_TRAPPED VALUE=0X124F800
PAYLOAD EL1TRAP CNTPCT_EL0 CONTROL TRAPPED EC=0X18 ISS=0X32F861 ISS_OK=YES
PAYLOAD EL1TRAP VERDICT=TRAPS_INERT BITS13_14_IN_READBACK=YES
PAYLOAD EL1TRAP EXCURSION OK ENTRIES=0X2 TRAPS=0X1
PAYLOAD EL1TRAP RESTORED=YES
# only bit 14 sticks
PAYLOAD EL1TRAP READBACK HCR_EL2=0X80000000 CNTHCTL_EL2=0X4000
PAYLOAD EL1TRAP READBACK SCTLR_EL1=0X30500800 VBAR_EL1_OFFSET=0X800
PAYLOAD EL1TRAP CNTVCT_EL0 TRAPPED EC=0X18 ISS=0X34F801 ISS_OK=YES
PAYLOAD EL1TRAP CNTV_CTL_EL0 NOT_TRAPPED VALUE=0X0
PAYLOAD EL1TRAP CNTFRQ_EL0 NOT_TRAPPED VALUE=0X124F800
PAYLOAD EL1TRAP CNTPCT_EL0 CONTROL TRAPPED EC=0X18 ISS=0X32F861 ISS_OK=YES
PAYLOAD EL1TRAP VERDICT=TRAPS_PARTIAL BITS13_14_IN_READBACK=PARTIAL
PAYLOAD EL1TRAP EXCURSION OK ENTRIES=0X3 TRAPS=0X2
PAYLOAD EL1TRAP RESTORED=YES
# control not trapped
PAYLOAD EL1TRAP READBACK HCR_EL2=0X80000000 CNTHCTL_EL2=0X6000
PAYLOAD EL1TRAP READBACK SCTLR_EL1=0X30500800 VBAR_EL1_OFFSET=0X800
PAYLOAD EL1TRAP CNTVCT_EL0 TRAPPED EC=0X18 ISS=0X34F801 ISS_OK=YES
PAYLOAD EL1TRAP CNTV_CTL_EL0 TRAPPED EC=0X18 ISS=0X32F827 ISS_OK=YES
PAYLOAD EL1TRAP CNTFRQ_EL0 NOT_TRAPPED VALUE=0X124F800
PAYLOAD EL1TRAP CNTPCT_EL0 CONTROL NOT_TRAPPED VALUE=0X123456000
PAYLOAD EL1TRAP VERDICT=CONTROL_NOT_TRAPPED BITS13_14_IN_READBACK=YES
PAYLOAD EL1TRAP EXCURSION OK ENTRIES=0X3 TRAPS=0X2
PAYLOAD EL1TRAP RESTORED=YES
# hvc undefined at el2
PAYLOAD EL1TRAP HVC_AT_EL2=FAILED EL2_EXCEPTION ENTRIES=0X1 VECTOR=0X4
PAYLOAD EL1TRAP HVC_AT_EL2 ESR_EL2=0X0 ELR_EL2=0X5CB55123
PAYLOAD EL1TRAP REFUSED=HVC_AT_EL2
PAYLOAD EL1TRAP RESTORED=YES
# write not held
PAYLOAD EL1TRAP READBACK HCR_EL2=0X480000000 CNTHCTL_EL2=0X6000
PAYLOAD EL1TRAP READBACK SCTLR_EL1=0X30500800 VBAR_EL1_OFFSET=0X800
PAYLOAD EL1TRAP REFUSED=WRITE_NOT_HELD
PAYLOAD EL1TRAP RESTORED=YES
# restore fails
PAYLOAD EL1TRAP READBACK HCR_EL2=0X80000000 CNTHCTL_EL2=0X6000
PAYLOAD EL1TRAP READBACK SCTLR_EL1=0X30500800 VBAR_EL1_OFFSET=0X800
PAYLOAD EL1TRAP CNTVCT_EL0 TRAPPED EC=0X18 ISS=0X34F801 ISS_OK=YES
PAYLOAD EL1TRAP CNTV_CTL_EL0 TRAPPED EC=0X18 ISS=0X32F827 ISS_OK=YES
PAYLOAD EL1TRAP CNTFRQ_EL0 NOT_TRAPPED VALUE=0X124F800
PAYLOAD EL1TRAP CNTPCT_EL0 CONTROL TRAPPED EC=0X18 ISS=0X32F861 ISS_OK=YES
PAYLOAD EL1TRAP VERDICT=TRAPS_EFFECTIVE BITS13_14_IN_READBACK=YES
PAYLOAD EL1TRAP EXCURSION OK ENTRIES=0X4 TRAPS=0X3
PAYLOAD EL1TRAP RESTORE_RETRY HCR_EL2 NOW=0X80000000
PAYLOAD EL1TRAP RESTORED=NO
PAYLOAD EL1TRAP NOT_RESTORED HCR_EL2 WANT=0X88000010 NOW=0X80000000
PAYLOAD EL1TRAP POWER_CYCLE_BEFORE_ANY_OTHER_PAYLOAD
```
<!-- /el1trap-pages -->

For `hvc undefined at el2` the tail starts at line 8 (the first eight lines of the first page are the same, and the `HVC_AT_EL2=FAILED` line replaces `HVC_AT_EL2=OK`); for the others the
tail starts at line 11 and the first eleven lines are the same. The pages of an excursion that ends another way print addresses (`ELR_EL2` of each record), so the host test pins them
with the model's addresses and no page of them is shown here; the QEMU test pins the shapes (below).

## What each outcome means for the monitor's timer options

INFERRED throughout: nothing below has been observed on the unit. The options are those of section 6.3 of the monitor port audit: **O1** the A16
recipe (24 MHz for the guest by trapping its counter and timer, plus a `CNTHCTL_EL2` read-back refusal and a `CNTVOFF_EL2` = 0 check; needs bits 13 and
14 *effective* at EL2), **O2** 19.2 MHz everywhere with no scaling (profile changes only), **O3** patching the guest away from architectural counter
reads, **O4** `CNTPOFF_EL2` / ECV level 2 ("never": a read of it stalls the board). A "next step" is a proposal for a separate, authorised change, never
something this payload does. The page's own words are `TRAPS_EFFECTIVE` and so on; the stub runs under this payload's `HCR_EL2` and `SCTLR_EL1`, not
the monitor's guest's, which is a difference the table cannot remove.

<!-- el1trap-decisions -->
| Outcome on the page | What it means | O1 to O4, and the next step |
| --- | --- | --- |
| `VERDICT=TRAPS_EFFECTIVE`, `EXCURSION OK`, `RESTORED=YES` | with V in `CNTHCTL_EL2`, EL1 reads of `CNTVCT_EL0` and `CNTV_CTL_EL0` trap to EL2 with class `0x18` and the register's ISS, and the control does too | O1 is **supported, not decided**: the trap mechanism works at EL2 on this unit for an EL1 stub. What the monitor still needs (the guest's frequency, the `CNTVOFF_EL2` check, the read-back refusal) is its own design. O2, O3 unchanged; O4 unchanged (never) |
| `VERDICT=TRAPS_INERT BITS13_14_IN_READBACK=YES` | the bits read back as written and the reads returned values while the control trapped: **stuck but inert** | **O1 is eliminated**: the monitor's recipe cannot trap the guest's counter and timer on this unit. INFERRED cause: the ECV-gated fields do nothing (for example `SCR_EL3.ECVEn` clear), which no payload can read. Next: O2 (an A16 run at 19.2 MHz, the operator's decision) or O3 |
| `VERDICT=TRAPS_INERT BITS13_14_IN_READBACK=NO` | the bits did not read back either (RES0 or gated) | **O1 is eliminated**, as above; `cnthctl` would already have said it |
| `VERDICT=TRAPS_PARTIAL` | only one of the two ECV reads trapped | O1 as designed (both bits) is eliminated; a design that traps only the counter or only the timer is another design, UNKNOWN. Next: O2 or O3 first |
| `VERDICT=CONTROL_NOT_TRAPPED` | the control read returned a value: this setup delivers no trap to EL2 at all | the experiment is **void**: no answer about O1. INFERRED causes: the read did not run at EL1 as intended, or an EL3 or `HCR_EL2` setting. Analyse before any other run |
| `CNTFRQ_EL0_TRAPPED` after the verdict | a read of `CNTFRQ_EL0` trapped, which no `CNTHCTL_EL2` bit is expected to do | a finding on its own, to report whatever the verdict is |
| `HVC_AT_EL2=FAILED`, `REFUSED=HVC_AT_EL2` | HVC does not work at EL2 here (INFERRED: `SCR_EL3.HCE` or `HCR_EL2.HCD`); no EL1 code ran and only `VBAR_EL2` was changed, then put back | no answer about O1 from this design; a stub that ends without HVC would be another payload (UNKNOWN) |
| `REFUSED=WRITE_NOT_HELD` | one of the four registers did not hold what was written | nothing ran at EL1; read `READBACK` for which: a register of EL1 or EL2 that cannot be set is the finding |
| `EXCURSION EL1_EXCEPTION`, `ESR_EL1`... | a read at EL1 raised an exception there (class `0x00`: UNDEFINED) | INFERRED: the access is blocked in a way that is not a trap to EL2. No answer about O1; the record is the finding |
| `EXCURSION BUDGET`, `DEADLINE`, `UNEXPECTED_CLASS`, `UNEXPECTED_VECTOR`, `UNEXPECTED_HVC_IMM`, `EL2_EXCEPTION`, `NONE`, `ACCESSES_NOT_CLASSIFIED` | the excursion ended another way, with a reason | no answer about O1 and no verdict is printed; the `TRAP` records and the registers are the finding |
| `RESTORED=NO`, `NOT_RESTORED`, `RESTORE_RETRY`, return 3 | a register cannot be put back | **stop** (below): the board must be power-cycled before any other payload |
| the page ends at `NEXT EL1 EXCURSION AFTER 8 S` | a hang or a reset in the cache work or the probe | INFERRED: the HVC probe or a cache operation does not work at EL2 here. Photograph, power-cycle, report; O1 undecided |
| the page ends at `NEXT EL1 EXCURSION` | a hang or a reset in a write, an `ISB`, or the excursion (EL1 code that never comes back is the one thing not bounded) | UNKNOWN which; the board restarts ([Residual risks](#residual-risks)). O1 undecided; stop |
| q1n1's fault page | an exception at EL2 the handler could not take, or the 24-entry fatal path, under the runner's `VBAR_EL2` | `ESR_EL2` bits 31:26 are the class; no answer about O1; stop |
| `REFUSED=ENTRY`, `REFUSED=E2H`, `REFUSED=NO_EL1_AARCH64`, `REFUSED=DAIF_NOT_MASKED`, `REFUSED=SPSEL_NOT_EL2H`, `REFUSED=OLD_HAS_BITS_12_TO_14`, `REFUSED=STACK` | a precondition is not met: nothing was written | the line says which; bits 13 and 14 already set in OLD is not a surprise after `cnthctl`, bit 12 set (ECV on) is a finding |
| `REFUSED=COUNTER_STUCK`, `REFUSED=NO_COUNTER`, `SKIPPED_NOT_AT_EL2`, `FREQ=DEFAULT` | the counter does not run, there is none, the runner is not at EL2, or the frequency is odd | nothing was written; a runner or CPU question |
<!-- /el1trap-decisions -->

## Authorisation and the stop rule

**Authorisation.** This payload writes `HCR_EL2`, `CNTHCTL_EL2`, `SCTLR_EL1`, `VBAR_EL1`, `VBAR_EL2`, `SPSR_EL2` and `ELR_EL2`, and **runs code at EL1**, which no
payload has done. The runner's rule for anything beyond a read applies ([SP11-PAYLOAD.md](SP11-PAYLOAD.md#what-the-next-payloads-need-from-this-abi), item 3,
and the hardware rules of `AGENTS.md`): the operator names the payload and its SHA-256 in writing before it runs on the unit, together with the registers, the
values above, the fact that they are restored, the bounds and **the one thing that is not bounded**. **No run is authorised by this document, by its test, or by
the fact that the file is on the stick.** The digest is the manifest's: `python3 tools/test-q1n1-sp11-payload-el1trap.py facts` prints it, and the page shows
its first eight bytes in `PAYLOAD LOADED` and `PAYLOAD CALL`.

**Stop rule.** After the run the operator reads the page before anything else is run. The sequence stops, and the unit is power-cycled, on any of:
`RESTORED=NO` or `NOT_RESTORED`; a page that ends at a `NEXT` line; a fault page; a board restart; `REFUSED=OLD_HAS_BITS_12_TO_14` with bit 12 set; any
value the decision table does not list. There is no retry of the payload in the same boot, and it is not run in the same boot as `cpuon`.

## Staging plan

One manifest per stick, and `el1trap` **alone** on its stick, **only after** `cnthctl` printed `BITS13_14_STUCK=YES` with `RESTORED=YES`, the operator read that
page, and the operator authorised this payload by name and digest in turn (a `NO` or `PARTIAL` from `cnthctl` makes this payload pointless: O1 is already
eliminated). One payload per boot, so that its page is the only page and its risk the only risk. With the runner and the payloads built as in
[SP11-PAYLOAD.md](SP11-PAYLOAD.md#build):

```sh
python3 tools/sp11_payload_manifest.py --out-dir build/stick build/uefi/payloads/el1trap.bin
```

writes `build/stick/SP11/PAYLOAD.MAN` and `build/stick/SP11/EL1TRAP.BIN`. The stick holds exactly `SP11\Q1N1-PAYLOAD.EFI` (not written by the tool),
`SP11\PAYLOAD.MAN` and `SP11\EL1TRAP.BIN`, and the run is, from the UEFI Shell with slbounce loaded as for the other payloads, `SP11\Q1N1-PAYLOAD.EFI --el2`.
The conditions of every run: AC power or at least 50% battery, the page filmed or photographed from the `NEXT` line on, one hardware client at a time.
Status of the staging: **proposed, NOT RUN**.

## What QEMU shows

OBSERVED, QEMU 11.1.3 (`virt,virtualization=on,gic-version=3`, TCG, EDK2 AArch64, one CPU), by `tools/test-q1n1-sp11-payload-qemu-el1trap.py`, the real binary
at a real EL2 with its MMU on: the only place the assembly runs, on QEMU's model of a core. With `-cpu max` (ECV 2) the reads of `CNTVCT_EL0` and `CNTV_CTL_EL0` and the
control trap with the ISS above, the read of `CNTFRQ_EL0` does not, and the verdict is `TRAPS_EFFECTIVE`; with `-cpu cortex-a76` (ECV 0) only the control traps,
the bits read back as zero and the verdict is `TRAPS_INERT`. The page of `-cpu max`:

<!-- el1trap-qemu-panel -->
```
CURRENTEL=0X8 HCR_EL2=0X8000038 E2H=0X0
DAIF=0X3C0 SPSEL=0X1 CNTFRQ_EL0=0X3B9ACA00
ID_AA64MMFR0_EL1=0X2100032310201126 ECV=0X2
ID_AA64PFR0_EL1=0X1301001121110222 EL1=0X2
OLD CNTHCTL_EL2=0X3 SCTLR_EL1=0XC50838
OLD VBAR_EL1=0X0 VBAR_EL2=0X5C155000
STUB_OFFSET=0X1790 EL1_VECTORS_OFFSET=0X1000 EL2_VECTORS_OFFSET=0X800
NEXT EL1 EXCURSION AFTER 8 S
HVC_AT_EL2=OK
WRITES HCR_EL2=0X80000000 CNTHCTL_EL2=0X6000 SCTLR_EL1=0X30500800
NEXT EL1 EXCURSION
READBACK HCR_EL2=0X80000000 CNTHCTL_EL2=0X6000
READBACK SCTLR_EL1=0X30500800 VBAR_EL1_OFFSET=0X1000
CNTVCT_EL0 TRAPPED EC=0X18 ISS=0X34F801 ISS_OK=YES
CNTV_CTL_EL0 TRAPPED EC=0X18 ISS=0X32F827 ISS_OK=YES
CNTFRQ_EL0 NOT_TRAPPED VALUE=0X3B9ACA00
CNTPCT_EL0 CONTROL TRAPPED EC=0X18 ISS=0X32F861 ISS_OK=YES
VERDICT=TRAPS_EFFECTIVE BITS13_14_IN_READBACK=YES
EXCURSION OK ENTRIES=0X4 TRAPS=0X3
RESTORED=YES
```
<!-- /el1trap-qemu-panel -->

The three offsets are those of this build and move with it; the suite only asserts that the tables are 2 KiB aligned, 2 KiB apart, that the stub follows the EL1 table and that `VBAR_EL1`
was set to the EL1 table. What the suite asserts, besides this page and the `-cpu cortex-a76` one: the wait is between 7 and 40 seconds of wall-clock time between the `NEXT` line and the
probe's answer (the serial log is read every 0.2 s); in a chain `state`, `el1trap`, `state` every register the `state` payload prints (`HCR_EL2`, `SCTLR_EL2`, `TCR_EL2`, `TTBR0_EL2`, `MAIR_EL2`,
`VBAR_EL2`, `CPTR_EL2`, `CNTHCTL_EL2`, `CNTFRQ_EL0`, `DAIF`, `SPSEL`) is identical before and after; and nine copies of the source, each edited once (the edit is asserted to apply once), in each way an
excursion can go wrong: a probe HVC that is UNDEFINED (no EL1 code runs and nothing is written), a stub whose first instruction is UNDEFINED or an SVC (reported by an EL1 vector through `HVC #1`,
`ESR_EL1` `0x2000000` and `0x56000000`), a stub ending in `HVC #5` (`UNEXPECTED_HVC_IMM`), a stub looping on trapping reads (`BUDGET`, 9 entries, 8 records, in program order), a deadline that has
passed (`DEADLINE` at the first entry), two registers never put back (`RESTORED=NO`, return 3, and the next `state` page shows `HCR_EL2=0X80000000` and `CNTHCTL_EL2=0X6000`: the failure is seen
by the next payload, not hidden), a stub that never returns (the last line is `NEXT EL1 EXCURSION`, nothing follows, and the panel stays the quiet one), and a handler that faults (it stops after 24 entries,
puts the runner's `VBAR_EL2` back and executes `UDF`: the runner's own fault page, the red bar of the panel, and no `PAYLOAD DONE`). No file of the stick changes.

What QEMU cannot show: the unit's EL3 (UNKNOWN: whether `SCR_EL3.ECVEn` makes the bits do anything, whether `SCR_EL3.HCE` enables HVC, what traps EL3 adds), the unit's counter, the cache
behaviour of the stub's fetch (TCG has no such cache), and whether any of this hangs or restarts the board. QEMU's `-cpu max` implements FEAT_ECV and its `EL1TVT` and `EL1TVCT` fields, so that
it traps with the bits: that is QEMU, not the unit. The unit's rows of the decision table are UNKNOWN.

## Tests

Hardware: NOT RUN. Every command writes only under `build/`.

| Command | What it runs |
| --- | --- |
| `python3 tools/test-q1n1-sp11-payload-el1trap.py` | the host program `tools/test-q1n1-sp11-payload-el1trap.c` (nine suites over a modelled machine: five registers whose writes can be ignored, come up wrong or stop working, a counter, an EL1 whose reads trap or do not, scripted ends; a predictor and a checker of the order and the page; 6000 random worlds) under ASan and UBSan; 127 seeded-bug mutants and an unmutated control; the source audits; the allow-list on the binary with 40 seeded bad binaries and a flat binary patched behind the disassembly; the EL1 stub and both vector tables, entry by entry; the stick, the manifest tool and the runner's own validator |
| `python3 tools/test-q1n1-sp11-payload-qemu-el1trap.py` | the QEMU boots above |
| `python3 tools/test-q1n1-sp11-payload-el1trap-doc.py` | this document against the source, the host model and the binary, with 48 seeded mistakes in the document |
| `python3 tools/test-q1n1-sp11-payload-build.py` | `make payloads` builds `el1trap.bin`, the ELF check, the allow-list of every payload, two builds byte-identical, the same bytes at another link address |
| `python3 tools/test-q1n1-sp11-payload-el1trap.py facts` | the size, digest and instruction inventory of the built binary |

## Planning a chain's page

The formula is the one of [the runner's planning table](SP11-PAYLOAD.md#the-chain-several-payloads-in-one-boot): `LOADED` for each file and `READY` (files + 1), `VERIFY`, `CALL` and `DONE`
for each payload (3), and the payload's own most lines. The host test measures the most `el1trap` prints over every scripted end, both probe results, the traps effective or inert, and no
register, four or all five not put back: 37.

<!-- el1trap-chain-budget -->
| Chain | Lines | Fits the unit's 89 rows | Fits the 60 the layout asks for |
| --- | --- | --- | --- |
| `el1trap` alone | (1 + 1) + 3 + 37 = 42 | yes | yes |
| `psci`, then `el1trap` | (2 + 1) + 3 x 2 + 30 + 37 = 76 | yes | no |
<!-- /el1trap-chain-budget -->

A normal run is 20 lines. The stick is `el1trap` alone, so the first row is the one that matters.

## Residual risks

* **An EL1 excursion is a different kind of risk from a register write, and from a core power cycle.** It is bounded and reported (the table above) except for the one case named. Whether
  the unit's EL3 lets an EL1 stub run at all, and what an HVC or a trap does there, is UNKNOWN: the probe asks about HVC and nothing asks about the rest.
* **A board restart is not a surprise to plan for, and not one to blame on this payload.** Restarts of the board have been seen after the `cpuon` payload, INFERRED to be associated
  with its core power cycling (cause UNKNOWN), and a runner flow with a read-only `psci` payload stayed up for 224 s and 268 s in two boots ([the restart control](SP11-PAYLOAD-RESULTS.md#the-restart-control), 2026-11-16). `el1trap` powers no core off. A restart in its run is a finding about its excursion, to be reported with the last line of the page.
* **The writes are UNKNOWN on this unit.** `cnthctl` is the first to write `CNTHCTL_EL2`, and `HCR_EL2`, `SCTLR_EL1`, `VBAR_EL1` and `VBAR_EL2` are ordinary EL2 and EL1 accesses no payload
  has written; the `CNTPOFF_EL2` stall is INFERRED to come from an EL3 gate, and whether any EL3 trap covers these writes is UNKNOWN.
* **The cache work is the payload's own claim** (`DC CIVAC` to the point of coherency and `IC IVAU` over the image, behind `DSB` and `ISB`), because EL1 fetches with its MMU off. TCG cannot show it.
* **While `VBAR_EL2` is the payload's, an exception of the payload's own code enters its handler**, which counts, ends the excursion and, after 24, puts the runner's table back and faults.
* **The restore is the payload's own claim** (all five registers are read back), and it covers the registers, not any effect of the excursion, which is none beyond the counter reads (INFERRED).
* **E2H.** The payload refuses `E2H` set; the unit's value is OBSERVED clear.
* The stub runs under this payload's `HCR_EL2` and `SCTLR_EL1`, not the monitor's guest's: a finding here is about the mechanism, and the monitor's own run is another experiment.

## Status

EXPERIMENTAL. Hardware NOT RUN. OBSERVED on the unit by other payloads and by q1n1's page: `HCR_EL2` `0x88000010`, `CNTHCTL_EL2` `0x3` at handoff, `CNTFRQ_EL0` `0x124F800`,
`ID_AA64MMFR0_EL1.ECV` 2, `DAIF` `0x3C0` (Snapintosh `docs/SP11-MONITOR-PORT.md`, section 6.2, which cites its sources). OBSERVED under QEMU only: the pages above and the behaviours listed under them.
UNKNOWN: everything this payload would print on the unit.
