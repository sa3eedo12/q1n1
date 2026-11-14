<!-- SPDX-License-Identifier: MIT -->
# SP11 payload `timer`: a read-only probe of the generic timer and counter at EL2

`payloads/timer.c` is one payload of the stick payload runner described in [SP11-PAYLOAD.md](SP11-PAYLOAD.md): the
manifest and the stick files, [the chain](SP11-PAYLOAD.md#the-chain-several-payloads-in-one-boot), ABI v1 and the
[line catalogue](SP11-PAYLOAD.md#line-catalogue) are defined there and not repeated. Evidence labels as there:
VERIFIED, OBSERVED, INFERRED, EXPERIMENTAL, UNIMPLEMENTED, UNKNOWN. **EXPERIMENTAL; hardware NOT RUN.**

## Why it exists

`payloads/timer.c` isolates the accesses that stalled this board five times in the X2 test image's timer test (T03: footer
`RUNNING T03 TIMER` for about 12 s, no exception page, then a reset). T03 read CNTFRQ_EL0, CNTHCTL_EL2, CNTVOFF_EL2,
CNTPCT_EL0 and CNTVCT_EL0, polled CNTPCT_EL0 and, because ID_AA64MMFR0_EL1.ECV is 2 on this core (OBSERVED), read
CNTPOFF_EL2. The leading explanation is INFERRED and untested: with SCR_EL3.ECVEn = 0 the CNTPOFF_EL2 access traps to
EL3 and the firmware's monitor hangs or crashes, so the board resets after a watchdog interval; CNTVOFF_EL2 has no EL3
trap control, a weaker suspect (INFERRED too). Every hazardous read here is announced by a line printed **before** it,
so the last line on the panel names the access that hung, and a fault page with ELR inside `timer.bin` names the
instruction that faulted.

## Where it goes in a chain

**Put it last.** It may stall the whole board, so `timer.bin` goes **last** in a manifest chain, for example
`state.bin psci.bin timer.bin`, never first: a stall costs only the lines after it. Photograph the screen at once (the X2
stall lasted about 12 s before the reset; INFERRED the same here). The manifest tool and the runner need nothing for this
chain (a test runs it): the stick holds `SP11\STATE.BIN`, `SP11\PSCI.BIN`, `SP11\TIMER.BIN`, `SP11\PAYLOAD.MAN` and
`SP11\Q1N1-PAYLOAD.EFI`, built and written as described in
[On the stick](SP11-PAYLOAD.md#on-the-stick-and-the-one-command). The Snapintosh autorun staging is not touched here.

## It never writes

MRS only, no barrier (no ISB, DSB, DMB or SB), so the counter reads are not ordered against each other: see the bracket
below. A test disassembles `timer.bin` against an allow-list of exactly the twelve registers below. `timer` is the only
payload allowed to name CNTVOFF_EL2 and CNTPOFF_EL2, once each (`state` and `psci` are refused if they do), and the test
checks the compiled order: the two hazards are the last two reads, each right after the call that prints its NEXT line.
Both offsets are spelled by encoding in the source (the assembler accepts CNTPOFF_EL2's name only with FEAT_ECV), so that
a search for the two encodings finds exactly the two reads.

## Registers and evidence

VERIFIED here means an architectural fact (the register, its encoding and its fields; the test assembles every name and
every encoding and compares them), not a measurement of the unit: nothing of this payload has run on the unit.

<!-- timer-registers -->
| Register | Encoding | Group | Evidence |
| --- | --- | --- | --- |
| `CurrentEL` | `S3_0_C4_C2_2` | first | VERIFIED (architecture); at any other EL one line and nothing else |
| `ID_AA64MMFR0_EL1` | `S3_0_C0_C7_0` | context | VERIFIED; ECV is bits 63:60 (2: CNTPOFF_EL2 exists); 2 on the unit (OBSERVED) |
| `HCR_EL2` | `S3_4_C1_C1_0` | context | VERIFIED; 0x88000010 on the unit (OBSERVED): E2H 0, TGE 1; printed, never depended on |
| `CNTFRQ_EL0` | `S3_3_C14_C0_0` | SAFE | VERIFIED; the unit's value is UNKNOWN until read (19.2 MHz is the monitor's INFERRED expectation) |
| `CNTHCTL_EL2` | `S3_4_C14_C1_0` | SAFE | VERIFIED; ECV is bit 12; q1n1's own EL2 page reads it too |
| `CNTP_CTL_EL0` | `S3_3_C14_C2_1` | SAFE | VERIFIED; read only, never read on the unit before; INFERRED safe |
| `CNTV_CTL_EL0` | `S3_3_C14_C3_1` | SAFE | as above |
| `CNTHP_CTL_EL2` | `S3_4_C14_C2_1` | SAFE | as above |
| `CNTPCT_EL0` | `S3_3_C14_C0_1` | SAFE | VERIFIED; polled at most 200000 reads, never used as a clock |
| `CNTVCT_EL0` | `S3_3_C14_C0_2` | SAFE | VERIFIED |
| `CNTVOFF_EL2` | `S3_4_C14_C0_3` | HAZARD 1 | VERIFIED register; a weak suspect (INFERRED: no EL3 trap control); Linux treats it as broken on Oryon X1 (Snapintosh docs/SURFACE-PRO-11.md E17), the unit's MIDR is that part (OBSERVED) |
| `CNTPOFF_EL2` | `S3_4_C14_C0_6` | HAZARD 2 | VERIFIED register, exists when ECV >= 2; the leading suspect (INFERRED, untested); read last |
<!-- /timer-registers -->

The SAFE group is read first, each line printed as soon as its register is read. HAZARD 1 and HAZARD 2 come last, in that
order, and nothing but a line is printed after the last one.

## What it prints

16 lines when ECV >= 2, 15 below, 1 off EL2 (`KEY=0XVALUE`, page font, at most 100 characters; the ABI allows 40 per call):

```
PAYLOAD TIMER ID_AA64MMFR0_EL1=0X.. ECV=0X2
PAYLOAD TIMER HCR_EL2=0X.. E2H=0X0 TGE=0X1
PAYLOAD TIMER CNTFRQ_EL0=0X..                    (SAFE group: each line as soon as read)
PAYLOAD TIMER CNTHCTL_EL2=0X.. ECV=0X0           (bit 12)
PAYLOAD TIMER CNTP_CTL_EL0=0X..                  (likewise CNTV_CTL_EL0, CNTHP_CTL_EL2)
PAYLOAD TIMER CNTPCT_EL0=0X..
PAYLOAD TIMER POLL_ADVANCED=0X1 POLL_READS=0X1 POLL_DELTA=0X..
PAYLOAD TIMER CNTVCT_EL0=0X..
PAYLOAD TIMER NEXT CNTVOFF_EL2                   (HAZARD 1)
PAYLOAD TIMER CNTVOFF_EL2=0X..
PAYLOAD TIMER VCT_PLUS_VOFF_WITHIN_PCT=0X1 HELD=0X8 OF=0X8 OFFSET=0X..
PAYLOAD TIMER NEXT CNTPOFF_EL2                   (HAZARD 2: the last access, only if ECV >= 2)
PAYLOAD TIMER CNTPOFF_EL2=0X..                   (ECV < 2: CNTPOFF_EL2 N/A (ECV BELOW 2), no read)
PAYLOAD TIMER DONE
```

At any other EL: `PAYLOAD TIMER SKIPPED_NOT_AT_EL2` and nothing else. The page font has no `<` (the runner prints it as
`_`), hence BELOW.

**The bracket:** CNTVCT = CNTPCT - CNTVOFF_EL2, so CNTVCT + CNTVOFF_EL2 must lie between the CNTPCT reads around it
(modular arithmetic, as T03 does). With no ISB a round's three reads may run out of order, so there are eight rounds:
`WITHIN` is 1 only if every round held (`HELD` of `OF`: a few short is noise, 0 a real difference) and `OFFSET`, the first
round's CNTVCT + CNTVOFF - CNTPCT, equals CNTVOFF_EL2 when the offset is not applied.

## What each outcome would mean for the monitor

All of it INFERRED: nothing of the payload has run on the unit.

| Question | What the photograph shows | What it would mean for the monitor |
| --- | --- | --- |
| CNTVOFF_EL2 usable at EL2? | a value, `WITHIN=1` | readable, CNTVCT follows it (with 0, only that no offset is in effect: nothing here writes) |
| | a value, `WITHIN=0` | readable, CNTVCT does not follow it (`OFFSET` equal to the value: the offset is not applied) |
| | last line `NEXT CNTVOFF_EL2` | even a read stalls: the monitor must not touch CNTVOFF_EL2 |
| | a fault page, ELR in `timer.bin` | the access raised an exception at EL2 (UNDEFINED, or trapped to EL2) |
| CNTPOFF_EL2 readable, or an EL3 stall? | a value | readable: the EL3-trap explanation is wrong for a read (a write is untested) |
| | last line `NEXT CNTPOFF_EL2` | it stalls, as that explanation predicts: never access CNTPOFF_EL2 nor set CNTHCTL_EL2.ECV |
| | `CNTPOFF_EL2 N/A` | ECV below 2: no such register, nothing read |
| Counter frequency | `CNTFRQ_EL0` | Hz as the firmware programmed it: 0X124F800 is 19.2 MHz, 0X16E3600 24 MHz, 0X3B9ACA00 1 GHz; 0 means nothing programmed it |
| Counter running? | `POLL_ADVANCED=0` | CNTPCT_EL0 did not change in 200000 reads: not running or not readable |
| CNTVCT = CNTPCT - CNTVOFF_EL2? | `WITHIN=1`, `WITHIN=0` | 1: it holds in every round (with CNTVOFF_EL2 0 that cannot show that an offset would be applied); 0: it does not, `HELD` of `OF` rounds held and `OFFSET` says by how much |

## Line budget

Lines past the region's last row are not drawn, and the NEXT lines come last, so the whole chain must fit. The runner adds
13 lines (4 notes, then `VERIFY`, `CALL` and `DONE` per payload) to `state` (21; 22 with E2H set), `psci` (22 under QEMU,
30 at most) and `timer` (16; 15 below ECV 2): 72 lines under QEMU (counted by the QEMU test), 81 at most. The region is
89 rows on the unit's 2880x1920 panel (the layout function; NOT drawn on hardware) and 60 in the stock layout: eight rows
to spare at worst on the unit, too few for the stock layout (`state.bin timer.bin`, 47 at most, fits). The planning table
in [SP11-PAYLOAD.md](SP11-PAYLOAD.md#the-chain-several-payloads-in-one-boot) gives the same numbers per payload, for any
other chain.

## Under QEMU

OBSERVED, QEMU 11.1.3, `-cpu max`, EL2, no EL3: ID_AA64MMFR0_EL1.ECV is 2 and QEMU implements CNTPOFF_EL2 at EL2, so the
whole path runs: CNTFRQ_EL0 0X3B9ACA00 (1 GHz), CNTHCTL_EL2 0X3 (ECV 0), the three control registers 0, CNTVOFF_EL2 0,
CNTPOFF_EL2 0, the counter advances, WITHIN 1 (HELD 8 of 8), no fault, 16 lines. The test asserts what QEMU was observed to
do, not what was assumed; a different QEMU may differ and the test then fails. Copies of the payload whose hazardous read
is an endless loop or an undefined instruction leave the NEXT line last, after all the lines of `state` and `psci` (drawn
on the page by a copy of the runner that forces a region onto QEMU's 800x600 screen), or end in q1n1's fault page. That
proves the mechanism and the format, nothing about the unit's firmware: QEMU has no EL3 to trap to, so it cannot show a
CNTPOFF_EL2 stall.

## Status and open questions

**Status.** EXPERIMENTAL. Hardware NOT RUN: nothing of this payload is OBSERVED on the unit. UNKNOWN: whether CNTVOFF_EL2
and CNTPOFF_EL2 read, fault or stall there, the unit's CNTFRQ_EL0 (until it is read), and every value the payload would
print. INFERRED and untested: that SCR_EL3.ECVEn = 0 explains a CNTPOFF_EL2 stall (SCR_EL3 is not readable from EL2).

The photograph answers: which line is last. `NEXT CNTVOFF_EL2` or `NEXT CNTPOFF_EL2` with nothing after it (the board resets
after about 12 s) names the access that stalls; a fault page with ELR inside `timer.bin` names the instruction that
faulted; `PAYLOAD TIMER DONE` means both reads worked, and the lines above it say what they returned.
