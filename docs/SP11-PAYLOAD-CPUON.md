<!-- SPDX-License-Identifier: MIT -->
# SP11 payload `cpuon`: start the eleven secondary CPUs with PSCI CPU_ON at EL2

`payloads/cpuon.c` is one payload of the stick payload runner described in [SP11-PAYLOAD.md](SP11-PAYLOAD.md): the manifest
and the stick files, [the chain](SP11-PAYLOAD.md#the-chain-several-payloads-in-one-boot), ABI v1 and the
[line catalogue](SP11-PAYLOAD.md#line-catalogue) are defined there and not repeated. Its closest relative is
[`psci`](SP11-PAYLOAD-PSCI.md), which only asks questions. Evidence labels as there: VERIFIED, OBSERVED, INFERRED,
EXPERIMENTAL, UNIMPLEMENTED, UNKNOWN. **EXPERIMENTAL; ran three times on the unit (2026-11-15: boot 7 and steps 2 and 3 of the restart probe; one unit).** Which page
is which: [What it prints](#what-it-prints) and [What QEMU shows](#what-qemu-shows) are **models** (the host model and QEMU);
[What the unit showed](#what-the-unit-showed) is **the unit's**, read by hand from a video.

`cpuon` starts the Surface Pro 11's eleven secondary CPUs through PSCI `CPU_ON` from EL2, lets each one report the state it
was entered in and power itself off with `CPU_OFF`, and prints what happened. It is **the first payload that changes the
machine**: a core that starts and never reports is left running, and a core that locks up may reset the board. That is why
it announces every risky step on the page, waits eight seconds before the first start so that the page can be photographed,
starts one core before it starts eleven, and goes **last** in a chain. What it answers is what the monitor's SMP bring-up
needs to know before it is designed (see [the decision table](#what-each-outcome-means-for-the-monitors-smp-bring-up)):
whether the firmware's PSCI starts a core at an address the payload chose, in which exception level, in which state, and
whether it takes the core down again. **It ran three times on the unit** (boot 7 and steps 2 and 3 of the restart probe); the two
finished pages (boot 7, step 3) agree: `CPU_ON` started all eleven secondaries at the address the payload chose, all eleven
reported and were seen OFF after their `CPU_OFF`, and every report that reached the page says EL2. The board restarted by itself
after boot 7 and in step 2 (operator reports; times and cause UNKNOWN); step 3 was seen alive through `UPTIME 36 S`. What the
design rested on, OBSERVED on earlier runs (the `psci` payload's page for PSCI, q1n1's EL2 state page for the registers): PSCI 1.1
and SMCCC 1.1, `CPU_ON` and `AFFINITY_INFO` implemented, CPU 0 ON and the eleven others OFF,
the boot CPU's `MPIDR_EL1` is `0x80000000`, q1n1 runs at EL2 with its MMU on (`SCTLR_EL2` `0x0000100030C5183D`), `HCR_EL2`
`0x88000010` (E2H = 0) and `CNTFRQ_EL0` 19.2 MHz.

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
| `CPU_ON` | `0xC4000003` | SMC64 | the target's MPIDR affinity | entry address: the stub, in the payload image | context id: the core's report slot | the primary, `smc_cpu_on` | id VERIFIED; issued on the unit, twelve calls answered 0 (boot 7 and step 3: OBSERVED twice) |
| `AFFINITY_INFO` | `0xC4000004` | SMC64 | the target's MPIDR affinity | 0 (the CPU itself) | 0 | the primary, `smc_affinity_info` | id VERIFIED; answered on the unit (boots 5 and 7, step 3: OBSERVED) |
| `CPU_OFF` | `0x84000002` | SMC32 | 0 | 0 | 0 | each secondary's stub, once | id VERIFIED; took every started core OFF on the unit (boot 7 and step 3: OBSERVED twice) |
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

A secondary starts with its MMU and caches off (PSCI; OBSERVED twice on the unit: `SCTLR_EL2` `0x30000000` as found, boot 7 and step 3):
its fetches and stores go straight to memory and nothing snoops for it. The A16 project's probe `probes/psci-roundtrip.S`
(Snapintosh repository) states the rule this payload follows, in its header comment: *Scratch/report must be clean to PoC
before entry on a cache-off CPU.*

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
cache maintenance). The unit's runs are the only check on real caches: all eleven reports arrived in boot 7 and in step 3, so the
rules were enough there; that does not show that each is needed.

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
phase 1 core plus the fixed lines are the 38 lines above; the worst case the host tests measure is the full 40, which the
unit's runs reached ([below](#what-the-unit-showed): a core whose ID registers differ prints a third line).

## What each outcome means for the monitor's SMP bring-up

INFERRED throughout, except the four rows marked **OBSERVED** (boot 7, step 3); every other row was not reached. The "next step"
is a proposal for a separate, authorized change, never something this payload does.

<!-- cpuon-decisions -->
| Outcome on the page | What it means | Next step |
| --- | --- | --- |
| `P1 NORMAL`, then `P2 POWER_OFF OFF=11` and `CORES STARTED=11 REPORTED=11 OFF=11` | **OBSERVED twice (boot 7, step 3), but without the `P2 POWER_OFF` line (dropped by the line budget) and with other ID registers on clusters 1 and 2.** PSCI `CPU_ON` from EL2 starts every secondary at a flat address in the payload image, with the target's own MPIDR and the boot CPU's ID registers, at the exception level printed (`EL=2` expected); `CPU_OFF` takes it down; the entry state printed (`SCTLR_EL2`, `HCR_EL2`, `VBAR_EL2`, `CNTVOFF_EL2`) is what the monitor's secondary entry code starts from | design the monitor's secondary entry from those values: its own `VBAR_EL2`, `HCR_EL2`, translation registers and stack, then the guest; first as a payload that keeps one core alive instead of calling `CPU_OFF`, **and only after the restarts are understood** ([below](#the-restart)) |
| `P1 CPU_ON 0X100 RET=...:INVALID_ADDRESS(-9)` or `INVALID_PARAMETERS(-2)`, then `P1 ABNORMAL=NOT_STARTED` | the secure monitor refuses the entry address (what it validates is UNKNOWN: a region, an alignment, a type of memory) or the target | print where the image is (the `LOADED` note names its base) and try an entry address elsewhere (another region, below 4 GiB) in a separate payload; the target itself was accepted by `AFFINITY_INFO` |
| `...:DENIED(-3)` | PSCI refuses to start a core from this context | the monitor cannot use `CPU_ON` as it is; look for the firmware's other route (the ACPI parking protocol the MADT may describe, or an HVC the firmware owns) |
| `...:ALREADY_ON(-4)` or `ON_PENDING(-5)` although phase 0 said OFF | `AFFINITY_INFO` and `CPU_ON` disagree, or an earlier run left the core running (`LEFT_RUNNING` above 0 and no power cycle) | power-cycle, run again; if it recurs `AFFINITY_INFO` is not the state `CPU_ON` sees |
| `P1 CPU_ON ... RET=0X0:SUCCESS`, then `NO_REPORT STAGE=0 CURRENTEL=0X0` | the call succeeded but nothing the stub should have stored is in memory: the core never ran the stub (entry address translated or checked differently), or its stores do not reach the memory the primary reads (a cache or attribute problem, rules 3 to 6) | a stub that does nothing but `WFE` at the same address, to separate "never ran" from "ran and could not report"; compare with the cache rules before suspecting the address |
| `NO_REPORT STAGE=1` or `2 CURRENTEL=0X8` | the stub ran at EL2 and stopped before it finished: one of the reads or stores after the vectors hung without a fault | a stub that stores a stage number after each read, to name the register |
| `FAULT STAGE=<n> VECTOR=<v> ESR_EL2=... ELR_EL2=...` | the stub's own vectors caught an exception on that core. `ELR_EL2` minus the image base (`LOADED`) is the offset into `cpuon.bin`; `ESR_EL2` bits 31:26 are the class: `0x18` a trapped system-register access (which one: disassemble the binary at that offset), `0x20`/`0x21` an instruction abort, `0x24`/`0x25` a data abort; `VECTOR` 4 is a synchronous exception at the same EL | the monitor must not use that register on a secondary at that point, or must configure the trap first; a data abort on the slot means the memory is not writable in the entry state |
| `P1 0X100 ENTERED_AT_EL1 NOT_EL2 CURRENTEL=0X4` | the secondaries are started below EL2: no EL2 register is reachable on them | a design blocker for an EL2 monitor that expects its own cores: the bring-up would need the firmware's help to enter EL2 on a secondary; decide before anything else |
| `MPIDR=0X<raw>` instead of `MPIDR=OK` | the core that started is not the one asked for | build the real MPIDR map from the printed values; do not trust the MADT order |
| `IDS=MMFR0/PFR0...` and the `MIDR=...` line | **OBSERVED twice (boot 7, step 3): `IDS=MIDR` on seven of the eight cores of clusters 1 and 2 (the eighth's report was dropped), `MIDR=0X511F0011/BOOT=0X512F0011` on six; the other three ID registers were the boot CPU's.** The ID registers of that core differ from the boot CPU's | the monitor reads the ID registers per core instead of copying the boot CPU's |
| `FRQ=0X<raw>` | `CNTFRQ_EL0` of that core is not the boot CPU's | the monitor must take the frequency from one place, not from each core |
| `CNTVOFF_EL2=0X<nonzero>` | the secondary starts with a virtual counter offset | the monitor clears it before a guest runs there, or uses it on purpose |
| `DT_US` | **OBSERVED twice (boot 7, step 3): 45 for the phase-1 start, 263 to 476 for eight phase-2 starts, about 2000 for two.** Microseconds from `CPU_ON` returning to the stub's first counter read: how long a real core takes | size the monitor's wait for a secondary from it (two boots: a sample, not a bound); the payload's own bound is one second |
| `P1 POWER_OFF OFF=0 NOT_OFF=1` with `STILL_ON LAST=ON KIND=1` | the core reported but `CPU_OFF` never took effect and never returned (or took longer than two seconds) | the core is still in the secure world or spinning: power-cycle before another try; the monitor cannot rely on taking a core down |
| `STILL_ON LAST=ON KIND=4 CPU_OFF_RET=0X...:DENIED(-3)` | `CPU_OFF` came back: PSCI refuses to power a core off from here; the stub parked it in `WFE` | a started core stays running, which is the point of an SMP bring-up; but power-cycle after this run |
| `P2 CPU_ON_FAILED ...` for some of the eleven, the others fine | the firmware does not take eleven calls back to back | start them one at a time and wait for each to report |
| `P2 SKIPPED=P1_NOT_NORMAL` | phase 1 was abnormal: its `ABNORMAL=` line says which row above applies | fix that first; eleven cores are not tried on an unexplained one |
| the page ends at `NEXT AFFINITY`, `NEXT PREPARE` or `NEXT CPU_ON ... AFTER 8 S` | a hang or a reset in the step that line announced: the `SMC` itself, the cache work (a fault there lands in q1n1's fault page: `DC IVAC` needs a writable page), or the wait | photograph the page, power-cycle; the line says which step to suspect |
| the page ends at `P1 CPU_ON ... RET=0X0:SUCCESS` or the board resets while a core runs | the secondary locked up, or its start disturbed the board | a lockup of a secondary may reset the board (UNKNOWN); the eight-second pause exists so that this page was photographed before |
| the page is complete and normal, and the board restarts by itself afterwards | **OBSERVED (operator reports: boot 7 and, with no photograph of its finished page, step 2); times and cause UNKNOWN.** Not a lockup the page shows: every started core had reported and been seen OFF | [the restart](#the-restart): film the page until it happens; try one core only; only then change what the cores do |
<!-- /cpuon-decisions -->

## What the unit showed

**OBSERVED on one unit (2026-11-15), read by hand from the operator's photographs and, for step 3, a video** (no UART, no log, no
copy on the stick; boots are numbered as in [SP11-PAYLOAD-RESULTS.md](SP11-PAYLOAD-RESULTS.md#the-boots)). `cpuon` ran three
times from the stick, each under slbounce's `SLBOUNCE-DEVHE-MARK.EFI`, through `q1n1-payload.efi --el2` (boot 7: the runner of boots
4 and 5, q1n1 build `A9F00F9CCBB5`, the stick plugged in directly) and a `PAYLOAD.MAN` of one entry: `CPUON.BIN`, 18,056 bytes, sha256
`3b4bfda7d59f923c21641472a4bc532fff61e4967e6e0b15dccbd023e632d09e` (the page shows the size and the first 16 digits;
`python3 tools/test-q1n1-sp11-payload-cpuon.py facts` prints all of them for the binary this tree builds). The runs: boot 7 (its
finished page photographed), steps 2 (finished page not photographed) and 3 (filmed, crisp) of the plan
`restart-probe` ([the restart](#the-restart)). The runner loaded the payload as `EfiLoaderCode` (base `0xCEA8B000` in boot 7,
`0xCE5E5000` in step 2, `0xCE60A000` in step 3) and `CPU_ON` was given the base plus `0x1000` (`cpuon_entry`).

The finished page of step 3, from the video (the unit prints capitals; every digit is legible):

<!-- cpuon-unit-page -->
```
PAYLOAD LOADED INDEX=0 BASE=0XCE60A000 BYTES=18056 SHA=3B4BFDA7D59F923C TYPE=1
PAYLOAD READY FILES=1 RANGES=4 CODE=1
PAYLOAD VERIFY=OK
PAYLOAD CALL 0 3B4BFDA7D59F923C
PAYLOAD CPUON BOOT_CPU MPIDR_EL1=0X80000000 CNTFRQ_EL0=0X124F800
PAYLOAD CPUON NEXT AFFINITY
PAYLOAD CPUON AFFINITY 0X100=OFF 0X200=OFF 0X300=OFF 0X10000=OFF 0X10100=OFF 0X10200=OFF 0X10300=OFF
PAYLOAD CPUON AFFINITY 0X20000=OFF 0X20100=OFF 0X20200=OFF 0X20300=OFF
PAYLOAD CPUON NEXT PREPARE
PAYLOAD CPUON NEXT CPU_ON 0X100 AFTER 8 S
PAYLOAD CPUON P1 CPU_ON 0X100 RET=0X0:SUCCESS
PAYLOAD CPUON P1 0X100 EL=2 MPIDR=OK IDS=SAME FRQ=SAME CNTVOFF_EL2=0X0 DT_US=45
PAYLOAD CPUON P1 0X100 SCTLR_EL2=0X30000000 HCR_EL2=0X1488000038 VBAR_EL2=0XFFFFFF9CEA002800
PAYLOAD CPUON P1 POWER_OFF OFF=1 NOT_OFF=0
PAYLOAD CPUON P1 NORMAL
PAYLOAD CPUON NEXT CPU_ON ALL AFTER 8 S
PAYLOAD CPUON P2 CPU_ON ISSUED=11 SUCCESS=11
PAYLOAD CPUON P2 0X100 EL=2 MPIDR=OK IDS=SAME FRQ=SAME CNTVOFF_EL2=0X0 DT_US=294
PAYLOAD CPUON P2 0X100 SCTLR_EL2=0X30000000 HCR_EL2=0X1488000038 VBAR_EL2=0XCE60A800
PAYLOAD CPUON P2 0X200 EL=2 MPIDR=OK IDS=SAME FRQ=SAME CNTVOFF_EL2=0X0 DT_US=288
PAYLOAD CPUON P2 0X200 SCTLR_EL2=0X30000000 HCR_EL2=0X80000000 VBAR_EL2=0X0
PAYLOAD CPUON P2 0X300 EL=2 MPIDR=OK IDS=SAME FRQ=SAME CNTVOFF_EL2=0X0 DT_US=2001
PAYLOAD CPUON P2 0X300 SCTLR_EL2=0X30000000 HCR_EL2=0X80000000 VBAR_EL2=0X0
PAYLOAD CPUON P2 0X10000 EL=2 MPIDR=OK IDS=MIDR FRQ=SAME CNTVOFF_EL2=0X0 DT_US=476
PAYLOAD CPUON P2 0X10000 SCTLR_EL2=0X30000000 HCR_EL2=0X80000000 VBAR_EL2=0X0
PAYLOAD CPUON P2 0X10000 MIDR=0X511F0011/BOOT=0X512F0011
PAYLOAD CPUON P2 0X10100 EL=2 MPIDR=OK IDS=MIDR FRQ=SAME CNTVOFF_EL2=0X0 DT_US=444
PAYLOAD CPUON P2 0X10100 SCTLR_EL2=0X30000000 HCR_EL2=0X80000000 VBAR_EL2=0X0
PAYLOAD CPUON P2 0X10100 MIDR=0X511F0011/BOOT=0X512F0011
PAYLOAD CPUON P2 0X10200 EL=2 MPIDR=OK IDS=MIDR FRQ=SAME CNTVOFF_EL2=0X0 DT_US=458
PAYLOAD CPUON P2 0X10200 SCTLR_EL2=0X30000000 HCR_EL2=0X1488000038 VBAR_EL2=0XFFFFFF9CEA002800
PAYLOAD CPUON P2 0X10200 MIDR=0X511F0011/BOOT=0X512F0011
PAYLOAD CPUON P2 0X10300 EL=2 MPIDR=OK IDS=MIDR FRQ=SAME CNTVOFF_EL2=0X0 DT_US=1994
PAYLOAD CPUON P2 0X10300 SCTLR_EL2=0X30000000 HCR_EL2=0X80000000 VBAR_EL2=0X0
PAYLOAD CPUON P2 0X10300 MIDR=0X511F0011/BOOT=0X512F0011
PAYLOAD CPUON P2 0X20000 EL=2 MPIDR=OK IDS=MIDR FRQ=SAME CNTVOFF_EL2=0X0 DT_US=369
PAYLOAD CPUON P2 0X20000 SCTLR_EL2=0X30000000 HCR_EL2=0X80000000 VBAR_EL2=0X0
PAYLOAD CPUON P2 0X20000 MIDR=0X511F0011/BOOT=0X512F0011
PAYLOAD CPUON P2 0X20100 EL=2 MPIDR=OK IDS=MIDR FRQ=SAME CNTVOFF_EL2=0X0 DT_US=428
PAYLOAD CPUON P2 0X20100 SCTLR_EL2=0X30000000 HCR_EL2=0X80000000 VBAR_EL2=0X0
PAYLOAD CPUON P2 0X20100 MIDR=0X511F0011/BOOT=0X512F0011
PAYLOAD CPUON P2 0X20200 EL=2 MPIDR=OK IDS=MIDR FRQ=SAME CNTVOFF_EL2=0X0 DT_US=440
PAYLOAD CPUON CORES STARTED=11 REPORTED=11 OFF=11 SUPPRESSED=6
PAYLOAD CPUON NOT_DONE NO_SYSTEM_OFF_RESET_SUSPEND NO_CPU_SUSPEND BOOT_CPU_NO_MSR LEFT_RUNNING=0
PAYLOAD DONE INDEX=0 RETURN=0X0 STACK=OK LOADS=0 FAULTS=0 REFUSED=0 LINES=40 DROPPED=0
```
<!-- /cpuon-unit-page -->

Boot 7's page (photographed at an angle) has the same lines and summary and other latencies; its register lines (`SCTLR_EL2`,
`HCR_EL2`, `VBAR_EL2`) were read with blur (the high-half `VBAR_EL2` as `0xFFFFFF...2800`), and what is legible agrees with this page.

What the pages say, OBSERVED twice (boot 7, step 3) unless it says otherwise:

* **`CPU_ON` from EL2 starts a core at an address the payload chose, and `CPU_OFF` takes it down.** All eleven targets read OFF
  first. `CPU_ON` of `0X100` alone answered `0X0:SUCCESS`; the core reported and was seen OFF (`P1 NORMAL`). Eleven more back to
  back, `0X100` again among them, were all answered 0: twelve calls, none refused. `CORES STARTED=11 REPORTED=11 OFF=11`;
  `RETURN=0X0` (the source returns 0 only if no started core was left running); `STACK=OK`; `LOADS=0 FAULTS=0` (no guarded load).
* **A secondary starts at EL2 with the MMU and caches off.** The ten cores on the page say `EL=2` and `MPIDR=OK` (the MADT's
  affinities are the cores' own), with the boot CPU's counter frequency, `CNTVOFF_EL2` 0 (readable on a secondary) and
  `ID_AA64MMFR0`, `ISAR0` and `PFR0`; `SCTLR_EL2` is `0x30000000` (M, C and I clear) on every register line.
* **`MIDR_EL1` differs by cluster.** The boot CPU and cluster 0 (`0X100` to `0X300`): `0x512F0011`. Clusters 1 and 2: `0x511F0011`
  on the six cores whose `MIDR=` line is on the page; `0X20200` says `IDS=MIDR` and its line was dropped. Only the variant field
  differs (2 and 1); implementer `0x51`, architecture `0xF`, part `0x001` and revision 1 are the same. No cause is claimed.
  INFERRED: the monitor reads the ID registers per core.
* **The EL2 state a secondary is entered with is not uniform.** Of the nine cores whose register line is on the page, seven read
  `HCR_EL2` `0x80000000` and `VBAR_EL2` 0; two (`0X100` at its first start, `0X10200`) read `HCR_EL2` `0x1488000038` (E2H, TGE, RW,
  TERR, AMO, IMO, FMO set; the boot CPU's own is `0x88000010`) and, in step 3, the same 16-digit high-half `VBAR_EL2`
  (`0xFFFFFF9CEA002800`). **That value differs between boots (OBSERVED, two crisp values for `0X100`'s first start):
  `0xFFFFFFB460602800` in step 2 (a mid-chain photograph), `0xFFFFFF9CEA002800` in step 3; boot 7's blurred `0xFFFFFF...2800` agrees
  with the shape.** INFERRED, the reason: a randomised high-half EL2 image (a hypervisor in VHE mode) ran on those cores earlier;
  which software is unknown. `0X20200` and `0X20300` printed no register line: UNKNOWN. INFERRED: a secondary's entry code cannot
  assume any EL2 register, `HCR_EL2.E2H` included.
* **`VBAR_EL2` survives a `CPU_OFF` and a `CPU_ON` (OBSERVED once, step 3; boot 7's blurred page reads the same).** At its second
  start `0X100` read `HCR_EL2` `0x1488000038` again and `VBAR_EL2` `0xCE60A800`, the base plus `0x800`, where the stub installed
  its own vectors at its first start, not the `0xFFFFFF9CEA002800` of that start: the core's EL2 registers were kept or restored
  across its power cycle.
* **Start latency** (`DT_US`, microseconds from `CPU_ON` returning to the stub's first counter read): 45 for the phase-1 start;
  of the ten printed phase-2 starts eight took 288 to 476 in step 3 (boot 7: 263 to 456) and the same two cores, `0X300` and
  `0X10300`, about 2 ms in both; `0X20300`'s was not printed. Two boots: a sample, not a bound.
* **The cache rules held twice.** All eleven reports arrived (none read `NO_REPORT`), and `DC CIVAC` over the image and `DC IVAC`
  over the slots raised no fault page, so the page attributes allow both. That each rule is needed is not shown.
* **The line budget cost six lines, by design.** Each of the eight cores of clusters 1 and 2 needs a third line (`MIDR=`), so
  each run wanted 46 lines against the ABI's 40, and a line that is not essential is dropped once it would leave no room for the
  summary and the last line. The six (`SUPPRESSED=6` on both pages): the last two lines of `0X20200`, the three of `0X20300` and
  `P2 POWER_OFF` (`OFF=11` says the same). That `0X20300` printed three is INFERRED from the count (the host model, scripted with
  the unit's `MIDR_EL1` and register values, prints these 40 lines and `SUPPRESSED=6`, and 5 for a two-line `0X20300`;
  EXPERIMENTAL: checked once by hand in a scratch program outside this repository).

### The restart

OBSERVED (restarts: operator reports with no `UPTIME`, no time; step 3: a video): **the board restarted by itself after boot 7's page
and in step 2 of the restart probe; step 3 was seen alive through `UPTIME 36 S` (the operator: "stayed up"). The cause and the times
are UNKNOWN.** Boot 7's page
was complete (`DONE`, `RETURN=0X0`) and every started core had been seen OFF: not a lockup the page shows. Step 2's five photographs
all read `UPTIME 0 S` (nothing draws it during the chain; the last is mid-chain): its restart has no time.

* **UPTIME.** It counts from before the chain: `start` is read before the runner is called (`platform/uefi/main.c`, line 1626
  against 1641) and the loop at lines 1645 to 1655 draws `(counter - start) / frequency` once a second. Boot 7's last photograph,
  `UPTIME 16 S`, was therefore the first heartbeat after the chain's two eight-second waits, not a time the page stayed up
  afterwards. In boot 7 the restart came seconds after the chain ended, not 16 s later (INFERRED from that code and the operator's
  words: about `UPTIME 17 to 25 S`; no number was recorded).
* **The probe** (plan `restart-probe`). After a self-restart the unit follows its normal boot order and never boots the stick
  (operator report), so every boot of the stick is started by the operator and a plan cannot run unattended. Step 1, a plain
  `Q1N1.EFI --el2`, was alive at `UPTIME 123 S` (photographed) and power-cycled; steps 2 and 3 ran `cpuon` again.
  Step 3's video shows its finished page through `UPTIME 36 S` (the chain returned at about 19 to 20 S).
* **Step 2's time (INFERRED, weak).** From the stick's markers and the operator's pace
  ([SP11-PAYLOAD-RESULTS.md](SP11-PAYLOAD-RESULTS.md#the-restart-probe)): at most about 45 s after its marker, `UPTIME` about 41 S
  or earlier, possibly before its chain ended. So INFERRED: the restart is not at one fixed `UPTIME` (one at about 17 to 41 S would
  show in step 3's video through 36 S, unless it falls in 36 to 41 S).
* **What is solid.** The plain page was alive at `UPTIME 123 S`, and q1n1's `--el2` flow has no reset path of its own (VERIFIED by
  reading `main.c`: `set_watchdog(0, 0, 0, NULL)` before `ExitBootServices`, lines 1819 and 2032; an idle `for (;;)`; a `WFE` halt
  on a fault; `reset_now`, line 757, reached only from the proxy). **The control** (plan `restart-control`,
  [SP11-PAYLOAD-RESULTS.md](SP11-PAYLOAD-RESULTS.md#the-restart-control)): the same runner with `psci.bin` alone (read-only, no
  `CPU_ON`, no `CPU_OFF`) was alive at `UPTIME 224 S` and `268 S` in two boots (OBSERVED once each; no restart reported), so the
  runner flow alone is not what restarts the board (INFERRED strongly: evidence, not proof).
* **What it may be.** The restart is associated with `cpuon`, that is with `CPU_ON` and `CPU_OFF` (INFERRED: a correlation over five
  boots; the cause is UNKNOWN, a delayed reaction of a watchdog or of the firmware (TZ, CPUCP) to the power cycles being one
  hypothesis). To narrow it down: a `cpuon` variant that starts and stops ONE core only; a variant that leaves cores running (never
  `CPU_OFF`; the riskiest, a separate, supervised change); and a film of a `cpuon` page until it restarts, to get the time.

### What the runs did not show

* What the secure monitor validates in an entry address: one kind (the image base plus `0x1000` in `EfiLoaderCode` memory below
  4 GiB, at two bases) was accepted, twelve calls per run; what else it checks or refuses is UNKNOWN.
* Anything with a core kept running, an interrupt or a guest (UNIMPLEMENTED): every core ran for microseconds with DAIF masked and
  ran none of the monitor's code.
* The cause and the times of the restarts (associated with `cpuon`: INFERRED), whether step 3 restarted after `UPTIME 36 S`; why
  the entry states differ between cores and boots.

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

* The eight-second waits are real: the serial log shows 8.09 s and 7.89 s between each `NEXT` line and the `CPU_ON` line after it
  (the test asserts 7 s to 30 s).
* Every core is entered at EL2 with `SCTLR_EL2` bits M and C clear (QEMU's value is 0), the target's own `MPIDR_EL1`, the boot
  CPU's ID registers and counter frequency, and reads OFF again.
* A fault on a secondary (a variant with one `UDF` after the vectors are installed) is reported by those vectors: `P1 0X1 FAULT
  STAGE=2 VECTOR=4 ESR_EL2=0X2000000 ELR_EL2=<the UDF's exact address> FAR_EL2=0X0` (vector 4: a synchronous exception at the same
  EL). The core still goes OFF and phase 2 is skipped.
* A stub that takes EL2 for another EL reports `ENTERED_AT_EL2 NOT_EL2 CURRENTEL=0X8`; one that never publishes its flag is
  `NO_REPORT STAGE=3` after the second the primary waits, and goes OFF; one whose `CPU_OFF` is a `NOP` parks: `NOT_OFF`,
  `STILL_ON ... KIND=4`, `LEFT_RUNNING=1`, return 2.
* **Starting a core twice.** Two back-to-back `CPU_ON` for one affinity are **both answered success** by QEMU 11.1.3 (it models
  neither `ON_PENDING` nor a window between request and start; the later request wins), so the earlier slot never gets a report:
  `P2 0X2 NO_REPORT STAGE=0 CURRENTEL=0X0`, `STARTED=11 REPORTED=10`. A `CPU_ON` for a core that is **running** (a parked one,
  started again by phase 2) is answered `ALREADY_ON(-4)`, named in `P2 CPU_ON_FAILED 0X1=ALREADY_ON(-4)`, and not counted as
  started. That variant parks all eleven cores, so the page also shows the line budget at work: `CORES STARTED=10 REPORTED=10
  OFF=0 SUPPRESSED=10`, the four `NEXT` lines and the last line present, 40 lines.

What QEMU cannot show: **the cache rules** (QEMU is coherent: `DC CIVAC`/`DC IVAC` are no-ops in TCG, so a missing clean or
invalidate cannot fail there), page permissions, the entry exception level, what the secure monitor validates in the entry
address, how long a real core takes, and the 8 s wait against the unit's counter. The QEMU test says SKIP, not pass, for the
cache rules. The unit's runs ([above](#what-the-unit-showed)) reached four decision-table rows; the rest stay INFERRED.

## Tests

No command below touches the unit (its runs were manual). Every command writes only under `build/`.

| Command | What it runs |
| --- | --- |
| `python3 tools/test-q1n1-sp11-payload-cpuon.py` | the host program `tools/test-q1n1-sp11-payload-cpuon.c` (ten suites over a modelled machine: scripted PSCI answers and errors, a counter, a cache that agrees with memory only through cache maintenance, an independent oracle of the page, 2500 random worlds) under ASan and UBSan; more than sixty seeded bugs in `cpuon.c`, each of which it must reject; the allow-list on the binary with more than thirty seeded bad binaries; the new engine against the base commit's on a corpus under every older policy; the source audits |
| `python3 tools/test-q1n1-sp11-payload-qemu-cpuon.py` | the QEMU boots above |
| `python3 tools/test-q1n1-sp11-payload-cpuon-doc.py` | this document against the source (ids, slot layout, every keyword the payload prints), the host model (the page of a normal run), the binary (the instruction table; the size and digest the unit's page shows), the unit's page (step 3's) against itself and the chain arithmetic |
| `python3 tools/test-q1n1-sp11-payload.py`, `...-build.py` | the shared machinery (which also builds the `cpuon` program from a copy of the tree) and `make payloads`: `cpuon.bin`, the ELF check, the allow-list of every payload, two builds byte-identical, the same bytes at another link address |
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
running runs after everything else has printed. The manifest tool keeps the order it is given. A normal run is 38 lines (the unit's
pages: 40), so the first row holds with room to spare and the second needs the unit's panel.

## Residual risks

* **Settled by boot 7 and step 3** (OBSERVED, [above](#what-the-unit-showed)): the entry at EL2; eleven `CPU_ON` back to back
  accepted, a core up in 45 us to about 2 ms; no fault page from the cache maintenance; `CNTVOFF_EL2` readable on a secondary; no
  refused call, late core or failed `CPU_OFF`. A restart was reported instead, in two of the three runs.
* **What the secure monitor validates in the entry address is UNKNOWN beyond one accepted kind of address** (the image base plus
  `0x1000` in `EfiLoaderCode` memory the runner placed, below 4 GiB; twelve calls per run, two bases). The stub still reads
  CurrentEL first and touches nothing of EL2 unless it says EL2; at EL1 it would store `ENTERED_AT_EL1` and call `CPU_OFF`, whose
  behaviour from there is the firmware's.
* **A core that starts and never reports is left running** (`NO_REPORT`, `LEFT_RUNNING`; none did in the unit's runs). One that
  starts after the payload gave up (it waits one second for the flag and two for OFF in phase 1, two and two in phase 2) would
  write its report into the slot region of the stack the runner gave the payload, far below the top 16 KiB the next payload's
  frames use. The payload does not touch the boot CPU's state, and a power cycle ends every running core.
* **QEMU does not validate the cache rules**, only the host model and the unit's runs do.
* **A lockup of a secondary may reset the board** (UNKNOWN), which is why the page is photographed before the first start. A
  restart was reported after two of the three runs, none shown to be a lockup: [the restart](#the-restart). `CNTPOFF_EL2` is never
  named by the source or the binary (tested).

## Status

EXPERIMENTAL. Ran three times on the unit (2026-11-15: boot 7 and steps 2 and 3 of the restart probe): the facts of
[What the unit showed](#what-the-unit-showed) are OBSERVED twice. UNKNOWN: the cause and the times of the restarts (after boot 7 and
in step 2); what the secure monitor validates in an entry address beyond one kind; anything with a core kept running or a guest
(UNIMPLEMENTED). OBSERVED under QEMU only: [What QEMU shows](#what-qemu-shows) and its behaviours.
