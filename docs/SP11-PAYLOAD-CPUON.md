<!-- SPDX-License-Identifier: MIT -->
# SP11 payload `cpuon`: start the eleven secondary CPUs with PSCI CPU_ON at EL2

`payloads/cpuon.c` is one payload of the stick payload runner described in [SP11-PAYLOAD.md](SP11-PAYLOAD.md): the manifest
and the stick files, [the chain](SP11-PAYLOAD.md#the-chain-several-payloads-in-one-boot), ABI v1 and the
[line catalogue](SP11-PAYLOAD.md#line-catalogue) are defined there and not repeated. Its closest relative is
[`psci`](SP11-PAYLOAD-PSCI.md), which only asks questions. Evidence labels as there: VERIFIED, OBSERVED, INFERRED,
EXPERIMENTAL, UNIMPLEMENTED, UNKNOWN. **EXPERIMENTAL; hardware NOT RUN.**

`cpuon` starts the Surface Pro 11's eleven secondary CPUs through PSCI `CPU_ON` from EL2, lets each one report the state it
was entered in and power itself off with `CPU_OFF`, and prints what happened. It is **the first payload that changes the
machine**: a core that starts and never reports is left running, and a core that locks up may reset the board. That is why
it announces every risky step on the page, waits eight seconds before the first start so that the page can be photographed,
starts one core before it starts eleven, and goes **last** in a chain. What it answers is what the monitor's SMP bring-up
needs to know before it is designed (see [the decision table](#what-each-outcome-means-for-the-monitors-smp-bring-up)):
whether the firmware's PSCI starts a core at an address the payload chose, in which exception level, in which state, and
whether it takes the core down again. Nothing here says what the unit does: **no value of this payload has been OBSERVED on
the unit.** Facts about the unit that the design rests on, OBSERVED on earlier runs (the `psci` payload's page for the PSCI facts,
q1n1's own EL2 state page for the registers): PSCI 1.1 and SMCCC 1.1, `CPU_ON` and `AFFINITY_INFO` implemented (no `CPU_ON` has
been called there), CPU 0 ON and the eleven others OFF, the boot CPU's `MPIDR_EL1` is `0x80000000`, q1n1 runs at EL2 with its
MMU on (`SCTLR_EL2` `0x0000100030C5183D`), `HCR_EL2` `0x88000010` (E2H = 0) and `CNTFRQ_EL0` 19.2 MHz.

## What it does, in order

1. **Where it runs.** It reads CurrentEL first. Not at EL2 it prints `PAYLOAD CPUON SKIPPED_NOT_AT_EL2` and returns: no SMC, no
   cache operation. At EL2 it refuses, with one `REFUSED=` line and nothing else done, a runner that gives it no counter, a
   stack it cannot hold its report slots in, or an image whose stub is not inside it (`NO_COUNTER`, `STACK`, `ENTRY`).
2. **The boot CPU.** One `BOOT_CPU` line: its `MPIDR_EL1`, its `CNTFRQ_EL0`, and `FREQ=DEFAULT` if that frequency is not
   between 1 MHz and 1 GHz, in which case the waits use 19.2 MHz. The boot CPU is never started, never asked about and never
   touched: no `MSR` of the payload ever runs on it.
3. **Phase 0, who is OFF.** `NEXT AFFINITY`, then `AFFINITY_INFO` (SMC64, lowest affinity level 0) for each of the eleven
   targets in a fixed table. **Only a target that answers exactly 1 (OFF) is ever started**; ON, ON_PENDING, an error and any
   other value skip the core and are printed.
4. **Phase 1, one round trip, core `0X100` alone** (only if it was OFF). `NEXT PREPARE`, then the memory preparation (see the
   cache rules). Then `NEXT CPU_ON 0X100 AFTER 8 S` and **eight seconds of waiting on the counter**: a stall or a reset
   leaves exactly the lines printed so far, and the board has reset before its page could be photographed. Then the one
   `CPU_ON`. The payload polls the core's done flag for at most one second, reads its slot, prints it, polls
   `AFFINITY_INFO` for OFF for at most two seconds and prints a verdict, `P1 NORMAL` or `P1 ABNORMAL=<reasons>`.
5. **Phase 2, the other cores, only after `P1 NORMAL`** (an entry from EL2, the target's own `MPIDR_EL1`, the boot CPU's ID
   registers and counter frequency, and OFF again). `NEXT CPU_ON ALL AFTER 8 S`, eight more seconds, then `CPU_ON` for every
   target that answered OFF in phase 0 (core `0X100` too: it is started a second time, from its own slot), back to back with
   nothing printed in between. One poll for all the done flags (two seconds in total), the reports, one poll for OFF (two
   seconds), then the summary. If phase 1 was not normal, phase 2 is skipped and the page says why.
6. **The end.** `CORES STARTED=<n> REPORTED=<n> OFF=<n>` and `NOT_DONE ... LEFT_RUNNING=<n>`. The return value is 0, or 2 if
   any started core was not seen OFF (a bad argument block returns 1, as for every payload). What it returns never stops the
   chain.

A timeout is `NO_REPORT` or `NOT_OFF`, never success. A `CPU_ON` that does not answer 0 in its low 32 bits is not a start,
is named (`NOT_SUPPORTED(-1)`, `INVALID_PARAMETERS(-2)`, `DENIED(-3)`, `ALREADY_ON(-4)`, `ON_PENDING(-5)`,
`INTERNAL_FAILURE(-6)`, `NOT_PRESENT(-7)`, `DISABLED(-8)`, `INVALID_ADDRESS(-9)`; any other value is printed raw) and is
**never retried**. The payload issues no other PSCI function than the three below: no `SYSTEM_OFF`, `SYSTEM_RESET`,
`SYSTEM_SUSPEND`, `CPU_SUSPEND` or `MIGRATE`, and never `CNTPOFF_EL2`.

## What it may issue

The ids are SMCCC fast calls; the numbers match Linux's `include/uapi/linux/psci.h` (VERIFIED against it; the PSCI
specification itself was not re-read, so the meanings below are INFERRED from it). **Each id is a literal in one helper** (or,
for `CPU_OFF`, in the stub), and the build test counts exactly three `smc #0` in the binary and reads the id each one is
called with:

<!-- cpuon-ids -->
| Name | Function id | Size | x1 | x2 | x3 | Issued by | Evidence |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `CPU_ON` | `0xC4000003` | SMC64 | the target's MPIDR affinity | entry address: the stub, in the payload image | context id: the core's report slot | the primary, `smc_cpu_on` | id VERIFIED; implemented on the unit OBSERVED |
| `AFFINITY_INFO` | `0xC4000004` | SMC64 | the target's MPIDR affinity | 0 (the CPU itself) | 0 | the primary, `smc_affinity_info` | id VERIFIED; implemented on the unit OBSERVED |
| `CPU_OFF` | `0x84000002` | SMC32 | 0 | 0 | 0 | each secondary's stub, once | id VERIFIED |
<!-- /cpuon-ids -->

`AFFINITY_INFO` answers 0 ON, 1 OFF, 2 ON_PENDING. `CPU_ON` answers 0 on success. `CPU_OFF` does not return on success.
The twelve MPIDR affinities are the ones the MADT's GICC entries list (OBSERVED, as in [the `psci` payload](SP11-PAYLOAD-PSCI.md)),
in CPU order, and the table is fixed in the source: `0x0` (the boot CPU, entry 0, never a target), `0x100`, `0x200`, `0x300`,
`0x10000`, `0x10100`, `0x10200`, `0x10300`, `0x20000`, `0x20100`, `0x20200`, `0x20300`.

## The instructions it uses, and why

The binary is checked by `tools/sp11_payload_testlib.py`, by the disassembly and, independently, by the encoding of every
aligned word of its code. Its policy is the first to use the allow-list keys `allow`, `smc_ids` and `single_reads`; the
policies of the other payloads do not use them and are checked exactly as before (a test compares the new engine with the
base commit's on every binary of a corpus under every older policy).

<!-- cpuon-instructions -->
| Kind | Operands allowed | Where | Why |
| --- | --- | --- | --- |
| `MRS` | `CurrentEL`, `MPIDR_EL1`, `MIDR_EL1`, `ID_AA64MMFR0_EL1`, `ID_AA64ISAR0_EL1`, `ID_AA64PFR0_EL1`, `CNTFRQ_EL0` | the primary and every stub | the entry state, and the boot CPU's values the report is compared with |
| `MRS` | `SCTLR_EL2`, `HCR_EL2`, `VBAR_EL2`, `CNTPCT_EL0` | each stub | the state the core was entered in (as found), and the counter for the start latency |
| `MRS` | `ESR_EL2`, `ELR_EL2`, `FAR_EL2` | a stub's vectors | what a fault on that core was |
| `MRS` | `CNTVOFF_EL2`, by encoding `S3_4_C14_C0_3`, **once** | each stub | the virtual offset the core starts with (READING it is fine: OBSERVED 0 on the boot CPU, the X2 test T03) |
| `MSR` | `VBAR_EL2` once, `DAIFSet` once | each stub | its own vector table, so that a fault becomes a report and not a hang; interrupts masked |
| `DC` | `CIVAC` (4 sites), `IVAC` (1 site) | primary and stub | the cache rules below |
| `DSB SY` | 7 sites; `ISB` 1 site | primary and stub | ordering of the report; the new `VBAR_EL2` takes effect |
| `WFE` | 1 site | a stub whose `CPU_OFF` returned | park instead of running random code |
| `SMC #0` | 3 sites | see above | the three PSCI calls |
<!-- /cpuon-instructions -->

Nothing else: no other `MSR` (**never `CNTPOFF_EL2`** (a read of it never returns on this unit and the board resets), and
`CNTHCTL_EL2.ECV` is never set), no `HVC`, `SVC`, `ERET`, `WFI`, `SEV`, `SYS`, `IC`, `TLBI`, `AT`, `DMB`, exclusive or atomic,
no other `DC` form. The stub has no stack and never reads memory; the primary reads seven registers, a stub fifteen.

## Memory and ordering rules

A secondary starts with its MMU and caches off (PSCI; INFERRED, not re-read): its fetches and stores go straight to memory and
nothing snoops for it. The A16 project's probe `probes/psci-roundtrip.S` (Snapintosh repository) states the rule this payload
follows, in its header comment: *Scratch/report must be clean to PoC before entry on a cache-off CPU.*

| # | Rule | Why |
| --- | --- | --- |
| 1 | Every report slot and scratch word is in the stack region the runner gives the payload (4 KiB in, 12 slots of 256 bytes, at least 16 KiB of real stack above them), never in the payload image. | The page attributes of the image at EL2 are UNKNOWN (it is LoaderCode, executable: OBSERVED); the stack is LoaderData, writable. The payload refuses (`REFUSED=STACK`) if the region does not fit. |
| 2 | A slot is 128-byte aligned and 256 bytes long; no two cores share a cache line. | `DC IVAC` drops dirty data; a line shared with another core's store would lose it. |
| 3 | Before the first `CPU_ON`: zero the slots (the **only** store the primary ever makes into a slot), `DC CIVAC` over the whole payload image and over every slot, then `DSB SY`. | The stub and its vectors are fetched from memory with the caches off, and the secondary's slot must read zero there. The zeros and the code must be at the point of coherency before the core starts. |
| 4 | After that the primary never writes a slot. | A dirty line in the primary's cache could later overwrite what a secondary stored. The host model makes the page read-only from the first `CPU_ON` on, so a store even of the value already there ends the run. |
| 5 | Every read of a slot is `DC IVAC` of its line, `DSB SY`, load. After the done flag was seen the whole slot is invalidated again; after the last read nothing else is done to it (except one more read for a core that never reached OFF). | The primary's cache may hold a copy fetched before the secondary stored: a prefetch refills the other lines of the slot too. |
| 6 | A secondary's stores are single 64-bit stores, `DSB SY` before the done flag, the done flag, `DSB SY`, `DC CIVAC` of the first line. | With its MMU off its stores are Device-nGnRnE: ordered, uncached. The barrier keeps the flag behind the report. The `DC CIVAC` is free in that state and makes the report visible if the core was entered with caches on after all. |
| 7 | The stub installs its vector table **before its first store**. | A fault in any later instruction, the stores included, is taken by it. (The A16 probe stores first and installs after; this order is a deliberate change, QEMU-checked.) |
| 8 | A `NEXT` line, then eight seconds on the counter, then the call. Nothing is printed between the calls of a batch. | A stall or a reset leaves exactly the lines printed so far. |
| 9 | Only a target that answered exactly OFF; the boot CPU never; each once per phase; no retry. | `CPU_ON` of a core that is on or starting is refused by the firmware at best. |
| 10 | AFFINITY_INFO of a started core at most once a millisecond while waiting for OFF. | The secure world is not polled as fast as a loop can go. |

**QEMU is coherent and shows none of rules 3 to 6**; the host model checks them (a cache that agrees with memory only through
cache maintenance), and the hardware run is NOT RUN.

## The report slot

Each core writes 64-bit words at these byte offsets of its own 256-byte slot; the done flag is `0x444F4E45` in its upper half
and, in its lower half, how the stub finished: 1 a full report, 2 an entry at another EL, 3 a fault, 4 `CPU_OFF` came back.
`STAGE` says how far the stub got: 1 `CurrentEL` stored (at EL2 the vectors are already installed), 2 `VBAR_EL2` as found stored,
3 everything stored.

<!-- cpuon-slot -->
| Offset | Word | Offset | Word |
| --- | --- | --- | --- |
| 0 | done flag | 80 | `ID_AA64MMFR0_EL1` |
| 8 | `CurrentEL` | 88 | `ID_AA64ISAR0_EL1` |
| 16 | `MPIDR_EL1` | 96 | `ID_AA64PFR0_EL1` |
| 24 | `MIDR_EL1` | 104 | `ESR_EL2` (fault) |
| 32 | `SCTLR_EL2` | 112 | `ELR_EL2` (fault) |
| 40 | `HCR_EL2` | 120 | `FAR_EL2` (fault) |
| 48 | `VBAR_EL2` as found | 128 | vector number (fault) |
| 56 | `CNTVOFF_EL2` | 136 | stage |
| 64 | `CNTFRQ_EL0` | 144 | the answer of a `CPU_OFF` that returned |
| 72 | `CNTPCT_EL0` | | |
<!-- /cpuon-slot -->

## What it prints

At most 40 lines (the ABI's limit; the runner adds three more), each at most 100 characters in the page font. Every line begins
`PAYLOAD CPUON `. Values are printed as the runner's hex op prints them (`0X` and capitals). The last six lines the payload may
print are reserved for the four `NEXT` lines, the summary and the last line, so a long report can never push them out: another
line that would leave less room is dropped and counted in `SUPPRESSED=` on the summary line. A group that does not fit a line
continues on another with the same label; an entry is never cut.

<!-- cpuon-lines -->
| Line | Meaning |
| --- | --- |
| `SKIPPED_NOT_AT_EL2` | CurrentEL is not EL2: nothing else was done |
| `REFUSED=NO_COUNTER` / `STACK` / `ENTRY` | the runner gave no counter / a stack that cannot hold the slots / an image the stub is not inside; nothing else was done |
| `BOOT_CPU MPIDR_EL1=0X.. CNTFRQ_EL0=0X..` + ` FREQ=DEFAULT` | the boot CPU; `FREQ=DEFAULT` if the frequency is implausible and 19.2 MHz is used |
| `NEXT AFFINITY` | the eleven `AFFINITY_INFO` calls follow |
| `AFFINITY 0X<aff>=<state> ...` | each target's answer: `ON`, `OFF`, `ON_PENDING`, `NAME(-N)`, a raw `0X..`; `BOOT_CPU` for the boot CPU's own entry |
| `SKIP_NOT_OFF 0X<aff> ...` | the targets that are not started because they did not answer OFF |
| `P1 SKIPPED=NOT_OFF` / `COUNTER_STUCK` | phase 1 did not start: core `0X100` was not OFF / the counter does not run (the wait cannot be made) |
| `NEXT PREPARE` | the memory preparation follows: the slots are zeroed, and the image and the slots are cleaned to the point of coherency |
| `NEXT CPU_ON 0X100 AFTER 8 S` | the one start of phase 1 follows eight seconds after this line |
| `P1 CPU_ON 0X100 RET=0X<raw>` + `:SUCCESS` / `:NAME(-N)` | the answer of `CPU_ON`; only 0 in the low 32 bits is a start |
| `P1 0X100 EL=<n> MPIDR=OK` / `0X<raw>` ` IDS=SAME` / `<names>` ` FRQ=SAME` / `0X<raw>` ` CNTVOFF_EL2=0X.. DT_US=<n>` | a report: the EL the core entered at, whether its `MPIDR_EL1` affinity is the target's, which of `MIDR`/`MMFR0`/`ISAR0`/`PFR0` differ from the boot CPU's, whether `CNTFRQ_EL0` is, its `CNTVOFF_EL2`, and the microseconds from the primary's counter read right after `CPU_ON` returned to the stub's own read (negative: the core ran before `CPU_ON` returned) |
| `P1 0X100 SCTLR_EL2=0X.. HCR_EL2=0X.. VBAR_EL2=0X..` | the registers as the core found them |
| `P1 0X100 MIDR=0X../BOOT=0X.. MMFR0=...` | only if `IDS` is not `SAME`: each differing value and the boot CPU's |
| `P1 0X100 ENTERED_AT_EL<n> NOT_EL2 CURRENTEL=0X..` | the core was entered below EL2 and touched nothing of EL2: it stored `CurrentEL` and the stage and called `CPU_OFF` |
| `P1 0X100 FAULT STAGE=<n> VECTOR=<n> ESR_EL2=0X.. ELR_EL2=0X.. FAR_EL2=0X..` | the stub's own vectors took an exception (vector 0 to 15); the report lines follow only if `STAGE` is 3 |
| `P1 0X100 NO_REPORT STAGE=<n> CURRENTEL=0X..` | no done flag within a second; how far the stub got (`STAGE` 0: never seen running) |
| `P1 POWER_OFF OFF=<n> NOT_OFF=<n>` | how many started cores AFFINITY_INFO showed OFF within two seconds |
| `P1 NOT_OFF 0X100=<state>` | the core that did not, and its last answer |
| `P1 0X100 STILL_ON LAST=<state> KIND=<k>` + ` CPU_OFF_RET=0X..:NAME` / ` ESR_EL2=0X.. ELR_EL2=0X..` | for a core that was not seen OFF: one more read of its slot (`KIND` 4: `CPU_OFF` came back, with its answer; 3: it faulted) |
| `P1 NORMAL` / `P1 ABNORMAL=<reasons>` | `NOT_STARTED`, `NO_REPORT`, `NOT_EL2`, `FAULT`, `MPIDR`, `IDS`, `FRQ`, `NOT_OFF`, joined with `/` |
| `NEXT CPU_ON ALL AFTER 8 S` | the batch of phase 2 follows eight seconds after this line |
| `P2 SKIPPED=P1_NOT_NORMAL` / `COUNTER_STUCK` | phase 2 did not run, and why |
| `P2 CPU_ON ISSUED=<n> SUCCESS=<n>` | how many `CPU_ON` were issued and answered 0 |
| `P2 CPU_ON_FAILED 0X<aff>=<NAME(-N)>` / `0X<raw>` | each one that did not |
| `P2 0X<aff> ...` | one report per started core, the same lines as phase 1 |
| `P2 POWER_OFF OFF=<n> NOT_OFF=<n>` / `P2 NOT_OFF ...` / `P2 0X<aff> STILL_ON ...` | as phase 1, for all of them |
| `CORES STARTED=<n> REPORTED=<n> OFF=<n>` + ` SUPPRESSED=<n>` | the last phase that ran; `SUPPRESSED` only if lines were dropped |
| `NOT_DONE NO_SYSTEM_OFF_RESET_SUSPEND NO_CPU_SUSPEND BOOT_CPU_NO_MSR LEFT_RUNNING=<n>` | what was not done, and how many started cores (of either phase) were not seen OFF |
<!-- /cpuon-lines -->

**A normal run**, as the host model prints it (38 lines; the values are the model's, **not** a unit's: EXPERIMENTAL, the same
script the host test pins line by line):

<!-- cpuon-page -->
```
PAYLOAD CPUON BOOT_CPU MPIDR_EL1=0X80000000 CNTFRQ_EL0=0X124F800
PAYLOAD CPUON NEXT AFFINITY
PAYLOAD CPUON AFFINITY 0X100=OFF 0X200=OFF 0X300=OFF 0X10000=OFF 0X10100=OFF 0X10200=OFF 0X10300=OFF
PAYLOAD CPUON AFFINITY 0X20000=OFF 0X20100=OFF 0X20200=OFF 0X20300=OFF
PAYLOAD CPUON NEXT PREPARE
PAYLOAD CPUON NEXT CPU_ON 0X100 AFTER 8 S
PAYLOAD CPUON P1 CPU_ON 0X100 RET=0X0:SUCCESS
PAYLOAD CPUON P1 0X100 EL=2 MPIDR=OK IDS=SAME FRQ=SAME CNTVOFF_EL2=0X0 DT_US=500
PAYLOAD CPUON P1 0X100 SCTLR_EL2=0X30C50830 HCR_EL2=0X80000000 VBAR_EL2=0X0
PAYLOAD CPUON P1 POWER_OFF OFF=1 NOT_OFF=0
PAYLOAD CPUON P1 NORMAL
PAYLOAD CPUON NEXT CPU_ON ALL AFTER 8 S
PAYLOAD CPUON P2 CPU_ON ISSUED=11 SUCCESS=11
PAYLOAD CPUON P2 0X100 EL=2 MPIDR=OK IDS=SAME FRQ=SAME CNTVOFF_EL2=0X0 DT_US=500
PAYLOAD CPUON P2 0X100 SCTLR_EL2=0X30C50830 HCR_EL2=0X80000000 VBAR_EL2=0X0
PAYLOAD CPUON P2 0X200 EL=2 MPIDR=OK IDS=SAME FRQ=SAME CNTVOFF_EL2=0X0 DT_US=500
PAYLOAD CPUON P2 0X200 SCTLR_EL2=0X30C50830 HCR_EL2=0X80000000 VBAR_EL2=0X0
PAYLOAD CPUON P2 0X300 EL=2 MPIDR=OK IDS=SAME FRQ=SAME CNTVOFF_EL2=0X0 DT_US=500
PAYLOAD CPUON P2 0X300 SCTLR_EL2=0X30C50830 HCR_EL2=0X80000000 VBAR_EL2=0X0
PAYLOAD CPUON P2 0X10000 EL=2 MPIDR=OK IDS=SAME FRQ=SAME CNTVOFF_EL2=0X0 DT_US=500
PAYLOAD CPUON P2 0X10000 SCTLR_EL2=0X30C50830 HCR_EL2=0X80000000 VBAR_EL2=0X0
PAYLOAD CPUON P2 0X10100 EL=2 MPIDR=OK IDS=SAME FRQ=SAME CNTVOFF_EL2=0X0 DT_US=500
PAYLOAD CPUON P2 0X10100 SCTLR_EL2=0X30C50830 HCR_EL2=0X80000000 VBAR_EL2=0X0
PAYLOAD CPUON P2 0X10200 EL=2 MPIDR=OK IDS=SAME FRQ=SAME CNTVOFF_EL2=0X0 DT_US=500
PAYLOAD CPUON P2 0X10200 SCTLR_EL2=0X30C50830 HCR_EL2=0X80000000 VBAR_EL2=0X0
PAYLOAD CPUON P2 0X10300 EL=2 MPIDR=OK IDS=SAME FRQ=SAME CNTVOFF_EL2=0X0 DT_US=500
PAYLOAD CPUON P2 0X10300 SCTLR_EL2=0X30C50830 HCR_EL2=0X80000000 VBAR_EL2=0X0
PAYLOAD CPUON P2 0X20000 EL=2 MPIDR=OK IDS=SAME FRQ=SAME CNTVOFF_EL2=0X0 DT_US=500
PAYLOAD CPUON P2 0X20000 SCTLR_EL2=0X30C50830 HCR_EL2=0X80000000 VBAR_EL2=0X0
PAYLOAD CPUON P2 0X20100 EL=2 MPIDR=OK IDS=SAME FRQ=SAME CNTVOFF_EL2=0X0 DT_US=500
PAYLOAD CPUON P2 0X20100 SCTLR_EL2=0X30C50830 HCR_EL2=0X80000000 VBAR_EL2=0X0
PAYLOAD CPUON P2 0X20200 EL=2 MPIDR=OK IDS=SAME FRQ=SAME CNTVOFF_EL2=0X0 DT_US=500
PAYLOAD CPUON P2 0X20200 SCTLR_EL2=0X30C50830 HCR_EL2=0X80000000 VBAR_EL2=0X0
PAYLOAD CPUON P2 0X20300 EL=2 MPIDR=OK IDS=SAME FRQ=SAME CNTVOFF_EL2=0X0 DT_US=500
PAYLOAD CPUON P2 0X20300 SCTLR_EL2=0X30C50830 HCR_EL2=0X80000000 VBAR_EL2=0X0
PAYLOAD CPUON P2 POWER_OFF OFF=11 NOT_OFF=0
PAYLOAD CPUON CORES STARTED=11 REPORTED=11 OFF=11
PAYLOAD CPUON NOT_DONE NO_SYSTEM_OFF_RESET_SUSPEND NO_CPU_SUSPEND BOOT_CPU_NO_MSR LEFT_RUNNING=0
```
<!-- /cpuon-page -->

A report takes two lines per core, not one: the entry state, the ID comparison and the latency already fill 85 characters, and
`SCTLR_EL2`, `HCR_EL2` and `VBAR_EL2` as found (16 digits each, up to 100 characters) cannot join them. Eleven cores and the
phase 1 core plus the fixed lines are the 38 lines above; the worst case the host tests measure is the full 40.

## What each outcome means for the monitor's SMP bring-up

INFERRED throughout: nothing below has been observed on the unit. The "next step" is a proposal for a separate, authorized
change, never something this payload does.

<!-- cpuon-decisions -->
| Outcome on the page | What it means | Next step |
| --- | --- | --- |
| `P1 NORMAL`, then `P2 POWER_OFF OFF=11` and `CORES STARTED=11 REPORTED=11 OFF=11` | PSCI `CPU_ON` from EL2 starts every secondary at a flat address in the payload image, with the target's own MPIDR and the boot CPU's ID registers, at the exception level printed (`EL=2` expected); `CPU_OFF` takes it down; the entry state printed (`SCTLR_EL2`, `HCR_EL2`, `VBAR_EL2`, `CNTVOFF_EL2`) is what the monitor's secondary entry code starts from | design the monitor's secondary entry from those values: its own `VBAR_EL2`, `HCR_EL2`, translation registers and stack, then the guest; first as a payload that keeps one core alive instead of calling `CPU_OFF` |
| `P1 CPU_ON 0X100 RET=...:INVALID_ADDRESS(-9)` or `INVALID_PARAMETERS(-2)`, then `P1 ABNORMAL=NOT_STARTED` | the secure monitor refuses the entry address (what it validates is UNKNOWN: a region, an alignment, a type of memory) or the target | print where the image is (the `LOADED` note names its base) and try an entry address elsewhere (another region, below 4 GiB) in a separate payload; the target itself was accepted by `AFFINITY_INFO` |
| `...:DENIED(-3)` | PSCI refuses to start a core from this context | the monitor cannot use `CPU_ON` as it is; look for the firmware's other route (the ACPI parking protocol the MADT may describe, or an HVC the firmware owns) |
| `...:ALREADY_ON(-4)` or `ON_PENDING(-5)` although phase 0 said OFF | `AFFINITY_INFO` and `CPU_ON` disagree, or an earlier run left the core running (`LEFT_RUNNING` above 0 and no power cycle) | power-cycle, run again; if it recurs `AFFINITY_INFO` is not the state `CPU_ON` sees |
| `P1 CPU_ON ... RET=0X0:SUCCESS`, then `NO_REPORT STAGE=0 CURRENTEL=0X0` | the call succeeded but nothing the stub should have stored is in memory: the core never ran the stub (entry address translated or checked differently), or its stores do not reach the memory the primary reads (a cache or attribute problem, rules 3 to 6) | a stub that does nothing but `WFE` at the same address, to separate "never ran" from "ran and could not report"; compare with the cache rules before suspecting the address |
| `NO_REPORT STAGE=1` or `2 CURRENTEL=0X8` | the stub ran at EL2 and stopped before it finished: one of the reads or stores after the vectors hung without a fault | a stub that stores a stage number after each read, to name the register |
| `FAULT STAGE=<n> VECTOR=<v> ESR_EL2=... ELR_EL2=...` | the stub's own vectors caught an exception on that core. `ELR_EL2` minus the image base (`LOADED`) is the offset into `cpuon.bin`; `ESR_EL2` bits 31:26 are the class: `0x18` a trapped system-register access (which one: disassemble the binary at that offset), `0x20`/`0x21` an instruction abort, `0x24`/`0x25` a data abort; `VECTOR` 4 is a synchronous exception at the same EL | the monitor must not use that register on a secondary at that point, or must configure the trap first; a data abort on the slot means the memory is not writable in the entry state |
| `P1 0X100 ENTERED_AT_EL1 NOT_EL2 CURRENTEL=0X4` | the secondaries are started below EL2: no EL2 register is reachable on them | a design blocker for an EL2 monitor that expects its own cores: the bring-up would need the firmware's help to enter EL2 on a secondary; decide before anything else |
| `MPIDR=0X<raw>` instead of `MPIDR=OK` | the core that started is not the one asked for | build the real MPIDR map from the printed values; do not trust the MADT order |
| `IDS=MMFR0/PFR0...` and the `MIDR=...` line | the ID registers of that core differ from the boot CPU's | the monitor reads the ID registers per core instead of copying the boot CPU's |
| `FRQ=0X<raw>` | `CNTFRQ_EL0` of that core is not the boot CPU's | the monitor must take the frequency from one place, not from each core |
| `CNTVOFF_EL2=0X<nonzero>` | the secondary starts with a virtual counter offset | the monitor clears it before a guest runs there, or uses it on purpose |
| `DT_US` | microseconds from `CPU_ON` returning to the stub's first counter read; the first number measured for how long a real core takes (UNKNOWN until then) | size the monitor's wait for a secondary from it; the payload's own bound is one second |
| `P1 POWER_OFF OFF=0 NOT_OFF=1` with `STILL_ON LAST=ON KIND=1` | the core reported but `CPU_OFF` never took effect and never returned (or took longer than two seconds) | the core is still in the secure world or spinning: power-cycle before another try; the monitor cannot rely on taking a core down |
| `STILL_ON LAST=ON KIND=4 CPU_OFF_RET=0X...:DENIED(-3)` | `CPU_OFF` came back: PSCI refuses to power a core off from here; the stub parked it in `WFE` | a started core stays running, which is the point of an SMP bring-up; but power-cycle after this run |
| `P2 CPU_ON_FAILED ...` for some of the eleven, the others fine | the firmware does not take eleven calls back to back | start them one at a time and wait for each to report |
| `P2 SKIPPED=P1_NOT_NORMAL` | phase 1 was abnormal: its `ABNORMAL=` line says which row above applies | fix that first; eleven cores are not tried on an unexplained one |
| the page ends at `NEXT AFFINITY`, `NEXT PREPARE` or `NEXT CPU_ON ... AFTER 8 S` | a hang or a reset in the step that line announced: the `SMC` itself, the cache work (a fault there lands in q1n1's fault page: `DC IVAC` needs a writable page), or the wait | photograph the page, power-cycle; the line says which step to suspect |
| the page ends at `P1 CPU_ON ... RET=0X0:SUCCESS` or the board resets while a core runs | the secondary locked up, or its start disturbed the board | a lockup of a secondary may reset the board (UNKNOWN); the eight-second pause exists so that this page was photographed before |
<!-- /cpuon-decisions -->

## What QEMU shows

OBSERVED, QEMU 11.1.3 (`virt,virtualization=on,gic-version=3`, `-cpu max -smp 12`, TCG, EDK2 AArch64), by
`tools/test-q1n1-sp11-payload-qemu-cpuon.py`. QEMU's PSCI answers an `SMC` from EL2 itself, starts the secondaries **at EL2**
and powers them off on `CPU_OFF`, so the real assembly stub and the real vector table run on eleven CPUs. Its twelve CPUs
are MPIDR `0x0` to `0xB`, not the unit's, so the **shipped binary cannot start anything there**: all eleven `AFFINITY_INFO`
are `INVALID_PARAMETERS(-2)`, no `CPU_ON` is issued and the payload returns 0 (fail closed, tested). The flow below is of a
**variant that differs from the shipped source in the one line of the table** (`0x0, 0x1, ... 0xB`, asserted by the test).
QEMU's counter is 1 GHz, not 19.2 MHz (`CNTFRQ_EL0=0X3B9ACA00`); the numbers vary per run, the lines do not:

<!-- cpuon-qemu-panel -->
```
BOOT_CPU MPIDR_EL1=0X80000000 CNTFRQ_EL0=0X3B9ACA00
NEXT AFFINITY
AFFINITY 0X1=OFF 0X2=OFF 0X3=OFF 0X4=OFF 0X5=OFF 0X6=OFF 0X7=OFF 0X8=OFF 0X9=OFF
AFFINITY 0XA=OFF 0XB=OFF
NEXT PREPARE
NEXT CPU_ON 0X1 AFTER 8 S
P1 CPU_ON 0X1 RET=0X0:SUCCESS
P1 0X1 EL=2 MPIDR=OK IDS=SAME FRQ=SAME CNTVOFF_EL2=0X0 DT_US=112
P1 0X1 SCTLR_EL2=0X0 HCR_EL2=0X0 VBAR_EL2=0X0
P1 POWER_OFF OFF=1 NOT_OFF=0
P1 NORMAL
NEXT CPU_ON ALL AFTER 8 S
P2 CPU_ON ISSUED=11 SUCCESS=11
P2 0X1 EL=2 MPIDR=OK IDS=SAME FRQ=SAME CNTVOFF_EL2=0X0 DT_US=192
P2 0X1 SCTLR_EL2=0X0 HCR_EL2=0X0 VBAR_EL2=0X0
P2 0X2 EL=2 MPIDR=OK IDS=SAME FRQ=SAME CNTVOFF_EL2=0X0 DT_US=62
P2 0X2 SCTLR_EL2=0X0 HCR_EL2=0X0 VBAR_EL2=0X0
P2 0X3 EL=2 MPIDR=OK IDS=SAME FRQ=SAME CNTVOFF_EL2=0X0 DT_US=115
P2 0X3 SCTLR_EL2=0X0 HCR_EL2=0X0 VBAR_EL2=0X0
P2 0X4 EL=2 MPIDR=OK IDS=SAME FRQ=SAME CNTVOFF_EL2=0X0 DT_US=233
P2 0X4 SCTLR_EL2=0X0 HCR_EL2=0X0 VBAR_EL2=0X0
P2 0X5 EL=2 MPIDR=OK IDS=SAME FRQ=SAME CNTVOFF_EL2=0X0 DT_US=40
P2 0X5 SCTLR_EL2=0X0 HCR_EL2=0X0 VBAR_EL2=0X0
P2 0X6 EL=2 MPIDR=OK IDS=SAME FRQ=SAME CNTVOFF_EL2=0X0 DT_US=152
P2 0X6 SCTLR_EL2=0X0 HCR_EL2=0X0 VBAR_EL2=0X0
P2 0X7 EL=2 MPIDR=OK IDS=SAME FRQ=SAME CNTVOFF_EL2=0X0 DT_US=44
P2 0X7 SCTLR_EL2=0X0 HCR_EL2=0X0 VBAR_EL2=0X0
P2 0X8 EL=2 MPIDR=OK IDS=SAME FRQ=SAME CNTVOFF_EL2=0X0 DT_US=307
P2 0X8 SCTLR_EL2=0X0 HCR_EL2=0X0 VBAR_EL2=0X0
P2 0X9 EL=2 MPIDR=OK IDS=SAME FRQ=SAME CNTVOFF_EL2=0X0 DT_US=171
P2 0X9 SCTLR_EL2=0X0 HCR_EL2=0X0 VBAR_EL2=0X0
P2 0XA EL=2 MPIDR=OK IDS=SAME FRQ=SAME CNTVOFF_EL2=0X0 DT_US=-38
P2 0XA SCTLR_EL2=0X0 HCR_EL2=0X0 VBAR_EL2=0X0
P2 0XB EL=2 MPIDR=OK IDS=SAME FRQ=SAME CNTVOFF_EL2=0X0 DT_US=63
P2 0XB SCTLR_EL2=0X0 HCR_EL2=0X0 VBAR_EL2=0X0
P2 POWER_OFF OFF=11 NOT_OFF=0
CORES STARTED=11 REPORTED=11 OFF=11
NOT_DONE NO_SYSTEM_OFF_RESET_SUSPEND NO_CPU_SUSPEND BOOT_CPU_NO_MSR LEFT_RUNNING=0
```
<!-- /cpuon-qemu-panel -->

What the QEMU suite asserts and observed, besides this page (the `DT_US` numbers are masked when the page is compared):

* The eight-second waits are real: in one run the serial log shows 8.09 s and 7.89 s (the log is read every 0.2 s) between each
  `NEXT` line and the `CPU_ON` line that follows it; the test asserts between 7 s and 30 s.
* Every core is entered at EL2 with `SCTLR_EL2` bits M and C clear (the PSCI entry state, as found: QEMU's value is 0), the
  target's own `MPIDR_EL1`, the boot CPU's ID registers and counter frequency, and reads OFF again.
* A fault on a secondary (a variant with one `UDF` after the vectors are installed) is reported by those vectors:
  `P1 0X1 FAULT STAGE=2 VECTOR=4 ESR_EL2=0X2000000 ELR_EL2=<the UDF's exact address> FAR_EL2=0X0`: vector 4 is a synchronous
  exception at the same EL, class 0, and `ELR_EL2` is the image base plus the instruction's offset. The core still goes OFF
  and phase 2 is skipped.
* A stub that takes EL2 for another EL reports `ENTERED_AT_EL2 NOT_EL2 CURRENTEL=0X8`; one that never publishes its flag is
  `NO_REPORT STAGE=3` after the second the primary waits, and the core goes OFF; one whose `CPU_OFF` is a `NOP` parks, is
  `NOT_OFF`, `STILL_ON ... KIND=4`, `LEFT_RUNNING=1`, and the payload returns 2.
* **Starting a core twice.** Two back-to-back `CPU_ON` for one affinity (a table with one core twice) are **both answered
  success** by QEMU 11.1.3: it models neither `ON_PENDING` nor a window between the request and the start, and the later request
  wins, so the earlier slot never gets a report and the payload says `P2 0X2 NO_REPORT STAGE=0 CURRENTEL=0X0` and counts
  `STARTED=11 REPORTED=10`. A `CPU_ON` for a core that is **running** (a parked one, started again by phase 2) is answered
  `ALREADY_ON(-4)`, named in `P2 CPU_ON_FAILED 0X1=ALREADY_ON(-4)`, and the core is not counted as started. That variant parks
  all eleven cores, so the page also shows the line budget at work: `CORES STARTED=10 REPORTED=10 OFF=0 SUPPRESSED=10`, the
  four `NEXT` lines and the last line all present, 40 lines.

What QEMU cannot show: **the cache rules** (QEMU is coherent: `DC CIVAC`/`DC IVAC` are no-ops in TCG, so a missing clean or
invalidate cannot fail there), page permissions, the unit's entry exception level, what the secure monitor validates in the
entry address, how long a real core takes, and the 8 s wait against the unit's counter. The QEMU test says SKIP, not pass, for
the cache rules. The unit's rows of the decision table are UNKNOWN.

## Tests

Hardware: NOT RUN. Every command writes only under `build/`.

| Command | What it runs |
| --- | --- |
| `python3 tools/test-q1n1-sp11-payload-cpuon.py` | the host program `tools/test-q1n1-sp11-payload-cpuon.c` (ten suites over a modelled machine: scripted PSCI answers and errors, a counter, a cache that agrees with memory only through cache maintenance, an independent oracle of the page, 2500 random worlds) under ASan and UBSan; more than sixty seeded bugs in `cpuon.c`, each of which it must reject; the allow-list on the binary with more than thirty seeded bad binaries and a flat binary patched behind the disassembly; the new engine against the base commit's on a corpus under every older policy; the id reader on synthetic input; the source audits; this document against the source |
| `python3 tools/test-q1n1-sp11-payload-qemu-cpuon.py` | the QEMU boots above |
| `python3 tools/test-q1n1-sp11-payload-cpuon-doc.py` | this document against the source (ids, slot layout, every keyword the payload prints), the host model (the page of a normal run), the binary (the instruction table) and the chain arithmetic |
| `python3 tools/test-q1n1-sp11-payload.py` | the shared machinery, which now also builds the `cpuon` program from a copy of the tree |
| `python3 tools/test-q1n1-sp11-payload-build.py` | `make payloads` builds `cpuon.bin`, the ELF check, the allow-list of every payload, two builds byte-identical, the same bytes at another link address |
| `python3 tools/test-q1n1-sp11-payload-cpuon.py facts` | the size, digest and instruction inventory of the built binary |

## Planning a chain's page

The formula is the one of [the runner's planning table](SP11-PAYLOAD.md#the-chain-several-payloads-in-one-boot): `LOADED` for
each file and `READY` (files + 1), `VERIFY`, `CALL` and `DONE` for each payload (3), and the payload's own most lines. The host
tests measure the most `cpuon` prints over every world they script: 40.

<!-- cpuon-chain-budget -->
| Chain | Lines | Fits the unit's 89 rows | Fits the 60 the layout asks for |
| --- | --- | --- | --- |
| `cpuon` alone | (1 + 1) + 3 + 40 = 45 | yes | yes |
| `psci`, then `cpuon` | (2 + 1) + 3 x 2 + 30 + 40 = 79 | yes | no |
| `psci`, `usbsmmu`, `timer`, then `cpuon` | (4 + 1) + 3 x 4 + 30 + 24 + 16 + 40 = 127 | no | no |
<!-- /cpuon-chain-budget -->

**Order.** `cpuon` goes **last** (`psci.bin cpuon.bin`): a stall or a reset in it then costs only its own lines, and what it leaves
running runs after everything else has printed. The manifest tool keeps the order it is given. A normal run is 38 lines, so
the first row holds with room to spare and the second needs the unit's panel.

## Residual risks

* **The entry exception level is UNKNOWN.** PSCI says the highest non-secure EL, so EL2 is expected. The stub reads CurrentEL
  first and touches nothing of EL2 unless it says EL2; at EL1 it stores `ENTERED_AT_EL1` and calls `CPU_OFF`, whose behaviour
  from there is the firmware's.
* **What the secure monitor validates in the entry address is UNKNOWN** (the image is LoaderCode memory the runner placed);
  an `INVALID_ADDRESS` is the likely answer if it dislikes it, and the payload never retries.
* **Whether eleven `CPU_ON` back to back are accepted, and how long a core takes to come up, are UNKNOWN.**
* **A core that starts and never reports is left running** (`NO_REPORT`, `LEFT_RUNNING`). A core that starts after the payload
  gave up (it waits one second for the flag and two for OFF in phase 1, two and two in phase 2) would write its report into the
  slot region of the stack the runner gave the payload: words 4 KiB above the guard words, far below the top 16 KiB the next
  payload's frames use. The payload does not touch the boot CPU's state, and a power cycle ends every running core.
* **QEMU does not validate the cache rules**, only the host model does (a model of the rules, not of the unit's caches).
* **A lockup of a secondary may reset the board** (UNKNOWN), which is why the page is photographed before the first start.
* The page attributes of the payload image and of the stack at EL2 are UNKNOWN: `DC CIVAC` over the image needs it readable,
  `DC IVAC` over a slot needs it writable (a fault would land in q1n1's fault page).
* `CNTVOFF_EL2` is read on a secondary: reading it on the boot CPU was fine (OBSERVED), on a secondary it is the same register
  at the same EL, but that is INFERRED. `CNTPOFF_EL2` is never named by the source or the binary (tested).

**The five things most likely to go wrong on the first run**, in the order they are likely: (1) the entry address or the exception
level is not what a flat stub in LoaderCode expects (an `INVALID_ADDRESS`, or `ENTERED_AT_EL1`); (2) a secondary locks up before its
vectors are installed and the board resets; (3) the cache work faults or does not make the stub and slots visible to a cache-off core
(`NO_REPORT STAGE=0`); (4) the firmware does not take eleven calls in a row, or a late core writes after the payload returned;
(5) `CPU_OFF` is refused or never takes effect, so cores stay running (`LEFT_RUNNING`) and the next run needs a power cycle.

## Status

EXPERIMENTAL. Hardware NOT RUN. OBSERVED on the unit by other payloads: PSCI 1.1, SMCCC 1.1, `CPU_ON` and `AFFINITY_INFO`
implemented, CPU 0 ON and the eleven others OFF. OBSERVED under QEMU only: the page above and the behaviours listed under it.
UNKNOWN: everything else this payload would print on the unit.
