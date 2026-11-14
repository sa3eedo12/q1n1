<!-- SPDX-License-Identifier: MIT -->
# SP11 payload `state`: the reference payload, EL2 state read with MRS only

`payloads/state.c` is the reference payload of the stick payload runner described in [SP11-PAYLOAD.md](SP11-PAYLOAD.md):
the manifest and the stick files, [the chain](SP11-PAYLOAD.md#the-chain-several-payloads-in-one-boot), ABI v1 and the
[line catalogue](SP11-PAYLOAD.md#line-catalogue) are defined there and not repeated. Evidence labels as there: VERIFIED,
OBSERVED, INFERRED, EXPERIMENTAL, UNIMPLEMENTED, UNKNOWN. **EXPERIMENTAL; hardware NOT RUN.**

Prints one line per register, `PAYLOAD STATE KEY=0XVALUE`, and nothing else. It executes `MRS` and no instruction
that writes a system register, a cache, a TLB or a device (a test disassembles the binary and refuses `MSR`, `SYS`,
`DC`, `IC`, `TLBI`, `AT`, `HVC`, `SMC`, `SVC`, `ERET`, `WFI`, `WFE`, exclusives and the rest). In particular it never
writes CNTKCTL_EL1, never reads CNTVOFF_EL2 or CNTPOFF_EL2, and does not depend on E2H (expected 0 on the unit,
OBSERVED through q1n1's page as HCR_EL2 0x88000010): TTBR1_EL2 is read exactly when HCR_EL2.E2H is set. CurrentEL
is read first and the EL2 block only when it says EL2, so the payload is also safe run any other way
(`EL2REGS=SKIPPED_NOT_AT_EL2`).

<!-- registers -->
| Key | Register | Readable at | Evidence |
| --- | --- | --- | --- |
| `CURRENTEL` | CurrentEL | EL1, EL2 | VERIFIED (architecture) |
| `MIDR_EL1` | MIDR_EL1 | EL1, EL2 | VERIFIED; unit value 0x512F0011 OBSERVED |
| `MPIDR_EL1` | MPIDR_EL1 | EL1, EL2 | VERIFIED |
| `ID_AA64MMFR0_EL1` | ID_AA64MMFR0_EL1 | EL1, EL2 | VERIFIED |
| `ID_AA64MMFR1_EL1` | ID_AA64MMFR1_EL1 | EL1, EL2 | VERIFIED |
| `ID_AA64MMFR2_EL1` | ID_AA64MMFR2_EL1 | EL1, EL2 | VERIFIED; read at EL2 by q1n1's X2 probe |
| `ID_AA64MMFR3_EL1` | S3_0_C0_C7_3 | EL1, EL2 | INFERRED: ID space, unallocated reads as zero, not UNDEFINED |
| `ID_AA64MMFR4_EL1` | S3_0_C0_C7_4 | EL1, EL2 | INFERRED: as above |
| `ID_AA64PFR0_EL1` | ID_AA64PFR0_EL1 | EL1, EL2 | VERIFIED |
| `ID_AA64PFR1_EL1` | ID_AA64PFR1_EL1 | EL1, EL2 | VERIFIED |
| `HCR_EL2` | HCR_EL2 | EL2 only | VERIFIED (architecture); value OBSERVED |
| `SCTLR_EL2` | SCTLR_EL2 | EL2 only | VERIFIED; value OBSERVED |
| `TCR_EL2` | TCR_EL2 | EL2 only | VERIFIED; value OBSERVED |
| `TTBR0_EL2` | TTBR0_EL2 | EL2 only | VERIFIED; value OBSERVED |
| `TTBR1_EL2` | S3_4_C2_C0_1 | EL2, only when E2H is set | VERIFIED (architecture); not expected to print |
| `MAIR_EL2` | MAIR_EL2 | EL2 only | VERIFIED; value OBSERVED |
| `VBAR_EL2` | VBAR_EL2 | EL2 only | VERIFIED; value OBSERVED |
| `CPTR_EL2` | CPTR_EL2 | EL2 only | VERIFIED; value OBSERVED |
| `CNTHCTL_EL2` | CNTHCTL_EL2 | EL2 only | VERIFIED; value OBSERVED |
| `CNTFRQ_EL0` | CNTFRQ_EL0 | EL0 and up | VERIFIED |
| `DAIF` | DAIF | EL1, EL2 | VERIFIED; 0x3C0 OBSERVED |
| `SPSEL` | SPSel | EL1, EL2 | VERIFIED |
| `EL2REGS` | (a note) | printed only when not at EL2 | `SKIPPED_NOT_AT_EL2` |
<!-- /registers -->

"VERIFIED (architecture)" means the Arm ARM says so, not that the unit was measured: **no hardware run exists**. The
values the unit showed on q1n1's own page are the only OBSERVED numbers.
