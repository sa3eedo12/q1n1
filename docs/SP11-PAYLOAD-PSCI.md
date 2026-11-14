<!-- SPDX-License-Identifier: MIT -->
# SP11 payload `psci`: read-only PSCI queries with SMC at EL2

`payloads/psci.c` is one payload of the stick payload runner described in [SP11-PAYLOAD.md](SP11-PAYLOAD.md): the
manifest and the stick files, [the chain](SP11-PAYLOAD.md#the-chain-several-payloads-in-one-boot), ABI v1 and the
[line catalogue](SP11-PAYLOAD.md#line-catalogue) are defined there and not repeated. Evidence labels as there: VERIFIED,
OBSERVED, INFERRED, EXPERIMENTAL, UNIMPLEMENTED, UNKNOWN. **EXPERIMENTAL; hardware NOT RUN.**

`payloads/psci.c` asks the firmware's PSCI implementation what it supports, with `smc #0` at EL2, and prints the
answers. It is the first payload that is not MRS-only, so it is deliberately narrow. **EXPERIMENTAL; hardware NOT
RUN**: nothing here says what the unit's firmware answers, or whether it answers at all.

**The conduit.** The unit's FADT has ARM_BOOT_ARCH_FLAGS 0x1: PSCI_COMPLIANT = 1, PSCI_USE_HVC = 0, so the PSCI
conduit is SMC (OBSERVED). That an SMC issued from q1n1's EL2 context, after the Secure-Launch bounce, reaches the
firmware's PSCI at all is UNKNOWN until this runs (the FADT describes what an operating system should use).

**What it may issue.** Exactly five function ids, through **one** helper (`smc_query`), which is the only place an
`smc` appears in the source and, a test counts, the only `smc` instruction in the binary. The helper takes a kind of
query and a table index, never a function id, so no other id can be expressed through it; an index outside its
table issues nothing. The ids are SMCCC fast calls; the numbers match Linux's `include/uapi/linux/psci.h` and
`include/linux/arm-smccc.h` (VERIFIED against those headers; the PSCI and SMCCC specifications themselves were not
re-read, so the meanings given for the answers in the tables below are INFERRED from them):

<!-- psci-ids -->
| Name | Function id | Size | x1 | x2 | x0 on return | Evidence |
| --- | --- | --- | --- | --- | --- | --- |
| `SMCCC_VERSION` | `0x80000000` | SMC32 | 0 | 0 | major in bits 31:16, minor in 15:0; -1 if SMCCC 1.0 | id VERIFIED |
| `PSCI_VERSION` | `0x84000000` | SMC32 | 0 | 0 | major in bits 31:16, minor in 15:0 | id VERIFIED |
| `MIGRATE_INFO_TYPE` | `0x84000006` | SMC32 | 0 | 0 | 0 UP migratable, 1 UP not migratable, 2 Trusted OS absent or MP | id VERIFIED |
| `PSCI_FEATURES` | `0x8400000A` | SMC32 | a function id from the next table | 0 | 0 or the flags if implemented, -1 if not | id VERIFIED |
| `AFFINITY_INFO` | `0xC4000004` | SMC64 | one affinity from the third table | 0 (the CPU itself) | 0 ON, 1 OFF, 2 ON_PENDING | id VERIFIED |
<!-- /psci-ids -->

It **never** issues CPU_ON, CPU_OFF, CPU_SUSPEND, SYSTEM_OFF, SYSTEM_RESET, SYSTEM_RESET2, SYSTEM_SUSPEND, MIGRATE or
any vendor id. The ids below are only ever the **argument** of PSCI_FEATURES, a question about whether the function
exists, which has no effect:

<!-- psci-features -->
| Name | Id (argument only) | If PSCI_FEATURES answers 0 (or flags), it means |
| --- | --- | --- |
| `CPU_SUSPEND` | `0xC4000001` | implemented; flags: bit 0 OS-initiated mode, bit 1 extended power-state format (Linux) |
| `CPU_OFF` | `0x84000002` | implemented |
| `CPU_ON` | `0xC4000003` | the secondaries can be started through PSCI |
| `AFFINITY_INFO` | `0xC4000004` | the state query used below exists |
| `MIGRATE_INFO_TYPE` | `0x84000006` | implemented |
| `SYSTEM_OFF` | `0x84000008` | the firmware can power the machine off |
| `SYSTEM_RESET` | `0x84000009` | a PSCI reset exists |
| `PSCI_FEATURES` | `0x8400000A` | PSCI 1.0 or later (INFERRED: the function arrived with 1.0) |
| `SYSTEM_SUSPEND` | `0xC400000E` | suspend-to-RAM exists |
| `SYSTEM_RESET2` | `0xC4000012` | the PSCI 1.1 reset with a reset type exists |
<!-- /psci-features -->

The twelve affinities (lowest affinity level 0), the CPUs the MADT's GICC entries list (OBSERVED on the unit), in CPU
order:

<!-- psci-mpidrs -->
| Cluster | MPIDR affinities | Evidence |
| --- | --- | --- |
| 0 | `0x0`, `0x100`, `0x200`, `0x300` | OBSERVED (MADT) |
| 1 | `0x10000`, `0x10100`, `0x10200`, `0x10300` | OBSERVED (MADT) |
| 2 | `0x20000`, `0x20100`, `0x20200`, `0x20300` | OBSERVED (MADT) |
<!-- /psci-mpidrs -->

The boot CPU reads MPIDR_EL1 = 0x80000000 (OBSERVED): bit 31 is RES1 and its affinity is 0, the first entry. The
payload prints the MPIDR_EL1 of the CPU it runs on.

**Registers (SMCCC 1.1).** `x0` = function id; `x1`..`x3` = arguments, zeroed when unused; results in `x0`..`x3`
(only `x0` is used, and printed raw); `x4`..`x17` and memory are declared clobbered, so the compiler assumes nothing
about them across the call. It reads CurrentEL first and does nothing else unless that says EL2: not at
EL2 it prints `PAYLOAD PSCI SKIPPED_NOT_AT_EL2` and issues no SMC (the only system registers it reads are CurrentEL
and MPIDR_EL1; it never touches CNTVOFF_EL2 or CNTPOFF_EL2, which an earlier test image stalled this board with).
A test disassembles `psci.bin` and allows only `mrs`, exactly one `smc #0`, and none of `hvc`, `svc`, `msr`, `sys`,
`dc`, `ic`, `tlbi`, `at`, `eret`, `wfi`, `wfe`, the exclusives and the atomics.

**What it prints**, in this order; a hang is named by the last `NEXT` line, and each group's results are printed as
soon as the group is complete:

```
PAYLOAD PSCI MPIDR_EL1=0X..
PAYLOAD PSCI NEXT VERSION                       (before PSCI_VERSION, then MIGRATE_INFO_TYPE)
PAYLOAD PSCI VERSION PSCI_VERSION=0X..:V1.1 MIGRATE_INFO_TYPE=0X..:TOS_MP
PAYLOAD PSCI NEXT FEATURES                      (before the first of ten PSCI_FEATURES calls)
PAYLOAD PSCI FEATURES CPU_SUSPEND=0X0 CPU_OFF=0X0 ...      (as many lines as 100 characters need)
PAYLOAD PSCI NEXT AFFINITY                      (before the first of twelve AFFINITY_INFO calls)
PAYLOAD PSCI AFFINITY 0X0=0X0:ON 0X100=0X1:OFF ...         (the key is the MPIDR; as many lines as needed)
PAYLOAD PSCI NEXT SMCCC                         (before SMCCC_VERSION, asked last and alone)
PAYLOAD PSCI SMCCC SMCCC_VERSION=0X..:V1.1
```

Each result is `KEY=RAW` and, where the meaning is certain, `:DECODE`; `RAW` is the 64-bit `x0` as the runner's hex
op prints it. At most 30 lines for any answers at all (the ABI allows 40). The decode:

| `x0` | Decoded as |
| --- | --- |
| -1 .. -9 (the 32-bit `w0` for an SMC32 call, the whole `x0` for AFFINITY_INFO) | `NOT_SUPPORTED(-1)`, `INVALID_PARAMETERS(-2)`, `DENIED(-3)`, `ALREADY_ON(-4)`, `ON_PENDING(-5)`, `INTERNAL_FAILURE(-6)`, `NOT_PRESENT(-7)`, `DISABLED(-8)`, `INVALID_ADDRESS(-9)` |
| PSCI_VERSION, SMCCC_VERSION, bit 31 clear | `V<major>.<minor>` |
| MIGRATE_INFO_TYPE 0, 1, 2 | `TOS_UP_MIGRATE`, `TOS_UP_NO_MIGRATE`, `TOS_MP` |
| AFFINITY_INFO 0, 1, 2 | `ON`, `OFF`, `ON_PENDING` |
| PSCI_FEATURES, not an error | none: the raw value is the flags |
| anything else, garbage included | none: raw only |

**Four groups, not three, and why.** SMCCC_VERSION is not a PSCI function, and Linux asks PSCI_FEATURES whether it
exists before calling it; the fixed table of ten ids does not allow that question, so it is asked last and alone
under its own `NEXT SMCCC` line: whatever a PSCI-only firmware does with it, the PSCI answers are already on the
page. The helper is `static noinline`, not `static inline`: an inline copy at each call site would put several
`smc` instructions into the binary, and the build test demands exactly one.

**What each answer would mean for the port** (INFERRED; none of it is measured):

| Question | Line | An answer | What it would mean |
| --- | --- | --- | --- |
| Does PSCI answer here at all, and which version? | `PSCI_VERSION` | `0X10001:V1.1`, `0X10000:V1.0` | PSCI 1.x: PSCI_FEATURES exists, the FEATURES group is meaningful |
| | | `0X2:V0.2` | PSCI 0.2: PSCI_FEATURES does not exist (it answers -1), so FEATURES says nothing |
| | | `NOT_SUPPORTED(-1)` or any error | the SMC is not PSCI here, or not from this context |
| | | no further line after `NEXT VERSION`, or a fault page | a hang: SMC is not answered from this state; a fault page whose ELR lies in `psci.bin` (subtract the base printed in the `LOADED` note, disassemble the binary) says the `smc` itself raised an exception |
| Which functions exist? | `FEATURES` | `=0X0` or flags | implemented; `CPU_ON` present means a later payload can start the secondaries |
| | | `NOT_SUPPORTED(-1)` | not implemented; `CPU_ON` absent means no standard way to start a secondary |
| Where are the 11 secondaries? | `AFFINITY` | `:OFF` for the eleven | powered down: the state `CPU_ON` starts from |
| | | `:ON` | running or parked by the firmware: `CPU_ON` would answer `ALREADY_ON(-4)`; another mechanism would be needed |
| | | `:ON_PENDING` | a power-up is under way; ask again |
| | | `INVALID_PARAMETERS(-2)` | PSCI does not know that MPIDR: the MADT and PSCI disagree, or the conduit is not the platform's |
| Boot CPU sanity | `0X0=` | `0X0:ON` | expected (INFERRED: the CPU executing is on); anything else puts the whole table in doubt |
| Can PSCI reset the unit? | `SYSTEM_RESET` | `=0X0` | a PSCI reset exists, a possible deliberate way back to the firmware instead of a power cycle: using it would be a separate, authorized change, it is never called here |
| | | `NOT_SUPPORTED(-1)` | there is none |
| Which SMCCC? | `SMCCC_VERSION` | `V1.1` or later | the conduit speaks SMCCC 1.1+ |
| | | `NOT_SUPPORTED(-1)` | SMCCC 1.0, or a PSCI-only firmware: informational |

**QEMU** (OBSERVED, QEMU 11.1.3 with `virt,virtualization=on,gic-version=3`, `-cpu max -smp 1`, TCG, EDK2 AArch64):
`smc #0` at EL2 without an EL3 **does not fault**: QEMU's own PSCI emulation answers it. The answers (22 lines, the
text `tools/test-q1n1-sp11-payload-qemu-chain.py` compares): `PSCI_VERSION 0X10001` (V1.1), `MIGRATE_INFO_TYPE 0X2`
(TOS_MP), `PSCI_FEATURES` 0 for CPU_SUSPEND, CPU_OFF, CPU_ON, AFFINITY_INFO, MIGRATE_INFO_TYPE, SYSTEM_OFF,
SYSTEM_RESET and PSCI_FEATURES and -1 for SYSTEM_SUSPEND and SYSTEM_RESET2, `AFFINITY_INFO` 0 (ON) for MPIDR 0 and -2
for the other eleven (there is one CPU), `SMCCC_VERSION` -1. That proves the register convention against a real SMC
conduit, the decode, the group order, that the 22 lines and the `NEXT` lines fit the page and the budget, and that
`state` then `psci` run to the end in one boot. It proves **nothing** about the unit: its firmware, whether it
answers after the bounce, the MPIDRs it knows. A different QEMU may answer differently and the test then fails
rather than adapting; if `smc` had faulted, q1n1's fault page would have named it and the chain would have stopped
there.

**Status.** EXPERIMENTAL. Hardware NOT RUN: no value of this payload has been OBSERVED on the unit. INFERRED: the
boot CPU is ON. UNKNOWN: whether the firmware answers an SMC from this context, and everything else the payload
would print.
