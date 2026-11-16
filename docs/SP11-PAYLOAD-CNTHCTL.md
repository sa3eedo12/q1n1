<!-- SPDX-License-Identifier: MIT -->
# SP11 payload `cnthctl`: write CNTHCTL_EL2 with the monitor's value, read it back, put it back (T-HW1)

`payloads/cnthctl.c` is one payload of the stick payload runner described in [SP11-PAYLOAD.md](SP11-PAYLOAD.md): the manifest and
the stick files, [the chain](SP11-PAYLOAD.md#the-chain-several-payloads-in-one-boot), ABI v1 and the
[line catalogue](SP11-PAYLOAD.md#line-catalogue) are defined there and not repeated. Its closest relatives are
[`timer`](SP11-PAYLOAD-TIMER.md), which only reads the timer registers, and [`cpuon`](SP11-PAYLOAD-CPUON.md), the first payload
that wrote the machine. Evidence labels as there: VERIFIED, OBSERVED, INFERRED, EXPERIMENTAL, UNIMPLEMENTED, UNKNOWN.
**EXPERIMENTAL; ran once on the unit (2026-11-16, boot 11, in one boot with `el1trap`; one unit, one boot).** Which page is which:
[What it prints](#what-it-prints) and [What QEMU shows](#what-qemu-shows) are **models** (the host model and QEMU);
[What the unit showed](#what-the-unit-showed-boot-11) is **the unit's**, read by the coordinator from frames of a video. Its successor,
[`el1trap`](SP11-PAYLOAD-EL1TRAP.md), is T-HW2; the documents proposed it only after this one's page was read, and the operator ran both in that one boot.

`cnthctl` answers one question of the Surface Pro 11 monitor port (Snapintosh `docs/SP11-MONITOR-PORT.md`, section 6, experiment
T-HW1): **can `CNTHCTL_EL2` be written at EL2 with exactly the value the monitor writes, does the register read back bits 14
(`EL1TVCT`) and 13 (`EL1TVT`) as written, and can the old value be put back?** The monitor virtualises the guest's counter:
the host counter runs at 19.2 MHz, the guest is told 24 MHz, and the guest's reads of `CNTVCT_EL0` and of the virtual timer
are meant to be trapped to EL2 by those two bits (FEAT_ECV level 1). The monitor writes the value with an `ISB` and never reads
it back, and its gate only checks that `ID_AA64MMFR0_EL1.ECV` is not zero; on the unit that field is 2 (OBSERVED), which says
nothing about whether the two bits do anything. A "do not stick" answer here eliminates option O1 of the audit (the A16
recipe); a "stick" answer does **not** decide it, because a register can hold bits that trap nothing: that is
[T-HW2](SP11-PAYLOAD-EL1TRAP.md). Nothing here but the unit's own page says what the unit does: **no value of this payload was OBSERVED on the
unit before boot 11**, and the model pages are not the unit's.

It is the second payload that changes the machine, after `cpuon`, and it writes an **EL2 system register**: it needs the operator's
named, SHA-256-pinned authorisation before any run on the unit ([Authorisation](#authorisation-and-the-stop-rule)); boot 11's run had it
(about 11:20, for that one boot). This document asks for it; it is not it.

## What it does, in order

1. **Where it runs.** It reads CurrentEL first. Not at EL2 it prints `PAYLOAD CNTHCTL SKIPPED_NOT_AT_EL2` and returns: nothing
   is read but CurrentEL, nothing is written. At EL2 it refuses, with one `REFUSED=NO_COUNTER` line and nothing else done, a
   runner that gives it no counter op (it could not make the wait of step 3).
2. **Context.** It reads `HCR_EL2`, `ID_AA64MMFR0_EL1`, `CNTFRQ_EL0` and `CNTHCTL_EL2` (this is OLD) and prints three lines:
   CurrentEL, `HCR_EL2` and its `E2H` bit; `ID_AA64MMFR0_EL1` and its `ECV` field; OLD and `CNTFRQ_EL0`, with `FREQ=DEFAULT` if the
   frequency is not between 1 MHz and 1 GHz, in which case the wait uses 19.2 MHz. Then, still before any write, it refuses:
   `REFUSED=E2H` when `HCR_EL2.E2H` is set (the register then has the VHE layout and the monitor's formula would mean something
   else; the unit's `HCR_EL2` is `0x88000010`, E2H clear, OBSERVED), and `REFUSED=OLD_HAS_BITS_12_TO_14` when OLD already has bit 12, 13
   or 14 set (a write could then not show whether it makes a bit stick, and `ECV` would be on before this payload ran).
3. **Announce, then wait eight seconds.** `NEXT CNTHCTL_EL2 WRITE AFTER 8 S`, then eight seconds on the runner's counter, so that a
   hang or a reset at the write leaves a page that was already photographed. A counter that does not run (two million equal reads
   in a row) or that runs backwards (a read below the first, which would end the wait at once) ends
   the payload with `REFUSED=COUNTER_STUCK` before the write: the wait cannot be made.
4. **The window.** `V = (OLD & ~3) | (1 << 14) | (1 << 13)`, then: write V; `ISB`; read the register (R); write OLD; `ISB`; read
   it (R2). If R2 is not OLD it writes OLD **once more**, `ISB`, and reads (R3): the one retry. **Nothing is printed and nothing
   else is read between the first write and the last read**, and no other register is ever written.
5. **The report.** `OLD` and `V`, `R` and `R2`, `BITS13_14_STUCK=YES|NO|PARTIAL` (both, neither or one of the two bits are set in
   R) and `R_EQ_V=YES|NO`, `RESTORE_RETRY R3=...` if a retry was needed, then `RESTORED=YES`; or `RESTORED=NO` followed by the loud
   `NOT_RESTORED OLD=... NOW=...` and `POWER_CYCLE_BEFORE_ANY_OTHER_PAYLOAD`, and the payload returns **2**. A return value never stops
   the chain, but the page does say it, and the stop rule below does.

A write that is refused, ignored or only half held is reported by name, never as success; nothing is retried but the one restore.

## What it writes, and why the temporary value changes nothing else

<!-- cnthctl-write -->
| Register | Written | Value | When |
| --- | --- | --- | --- |
| `CNTHCTL_EL2` (`S3_4_C14_C1_0`) | first | V, the monitor's formula | after the eight seconds, once |
| `CNTHCTL_EL2` | second | OLD, as read | straight after the first read-back |
| `CNTHCTL_EL2` | third, only if R2 is not OLD | OLD again | the one retry |
<!-- /cnthctl-write -->

The monitor's formula is VERIFIED against its source: `guest_cnthctl = (save_cnthctl & ~3UL) | (1UL<<14) | (1UL<<13)` and
`msr cnthctl_el2, %0; isb` (`probes/xnuboot/prepare.c`, the Snapintosh tree; the test compares it when `SNAPINTOSH_DIR` names that
tree), and its model writes the same `0x6000` for a clear `0x3`. The bits, for the `HCR_EL2.E2H = 0` layout the unit runs in:

<!-- cnthctl-bits -->
| Bit | Name | In V | Source |
| --- | --- | --- | --- |
| 0 | `EL1PCTEN` (EL1 and EL0 access to the physical counter) | cleared | the monitor's comment: "withhold physical counter/timer access" |
| 1 | `EL1PCEN` (EL1 and EL0 access to the physical timer) | cleared | the same |
| 11:2 | the event stream and the rest of the layout | as found in OLD | `V` keeps them |
| 12 | `ECV` | **never set** | OLD with it set is refused; the payload never sets it |
| 13 | `EL1TVT` (traps the EL1 virtual timer registers) | set | `prepare.c`; FEAT_ECV level 1 |
| 14 | `EL1TVCT` (traps the EL1 virtual counter) | set | `prepare.c`; FEAT_ECV level 1 |
<!-- /cnthctl-bits -->

Why it cannot disturb anything, in the order of how sure each point is. (1) The runner calls a payload at EL2 with D, A, I and F masked
(`DAIF` `0x3C0`, OBSERVED on q1n1's page), so no interrupt arrives while the register holds V. (2) No EL1 or EL0 code runs on this
core: the payload and the runner are EL2 code, and the eleven secondaries read OFF (OBSERVED, `psci`, boot 5; no payload here starts
one). (3) `CNTHCTL_EL2` controls accesses made at EL0 and EL1 and the event stream (whose bits 11:2 V keeps as found); an EL2
access to a counter or a timer is not trapped by it when `E2H` is 0 (INFERRED from the architecture, which was not re-read). (4) The
register belongs to this core: no other core sees it. (5) The window is six short calls (nine with the retry); the payload prints
nothing inside it. None of these is measured as such; boot 11's run showed no disturbance (the page went on and the register was put back:
OBSERVED once), which fits the five points and proves none.

What it never touches, and a test checks the source and the binary for each: **`CNTPOFF_EL2`** (a read of it never returned on this
unit and the board restarted, boot 4, INFERRED from a line count), `CNTVOFF_EL2`, `CNTKCTL_EL1`, `CNTHCTL_EL2.ECV` (bit 12), the
timer control registers and every other register: they are not read either, but for the four of the context lines.

## The instructions it uses, and why

The binary is checked by `tools/sp11_payload_testlib.py`, by the disassembly and, independently, by the encoding of every aligned
word of its code. Its policy uses the allow-list key `allow` for one form, `msr cnthctl_el2` (any source register: the encoding
`0xd51ce100` under the mask `0xffffffe0`, one row of `ALLOW_WORDS`); no other payload may have it. The older policies are unchanged.

<!-- cnthctl-instructions -->
| Kind | Operands allowed | Where | Why |
| --- | --- | --- | --- |
| `MRS` | `CurrentEL`, `HCR_EL2`, `ID_AA64MMFR0_EL1`, `CNTFRQ_EL0` | the entry | the context lines and the frequency the wait is made with |
| `MRS` | `CNTHCTL_EL2`, 1 site | one helper, called for OLD, R, R2 and R3 | OLD and the three read-backs |
| `MSR` | `CNTHCTL_EL2`, 1 site | one helper, called for V, OLD and the retry | the only write |
| `ISB` | 1 site | one helper, called after each write | the write has taken effect before the read-back |
<!-- /cnthctl-instructions -->

Nothing else: no other `MSR`, no `DSB` or `DMB` (the policy forbids them), no `DC`, `IC`, `TLBI` or `AT`, no `HVC`, `SVC`, `SMC`,
`ERET`, `WFI`, `WFE` or `SEV`, no exclusive or atomic instruction, and **neither `CNTPOFF_EL2` nor `CNTVOFF_EL2` is named** by the
source or the binary. The payload has no stack beyond its frame and never reads memory but its arguments.

## What it prints

At most 11 lines (the ABI allows 40; the runner adds three more), each at most 100 characters in the page font and never cut:
a line holds at most two 64-bit values, so that four of them cannot overflow one. Every line begins `PAYLOAD CNTHCTL `. Values are
printed as the runner's hex op prints them (`0X` and capitals).

<!-- cnthctl-lines -->
| Line | Meaning |
| --- | --- |
| `SKIPPED_NOT_AT_EL2` | CurrentEL is not EL2: nothing else was done |
| `REFUSED=NO_COUNTER` | the runner gave no counter: nothing else was done |
| `CURRENTEL=0X8 HCR_EL2=0X.. E2H=0X0` | the exception level, `HCR_EL2` and its E2H bit |
| `ID_AA64MMFR0_EL1=0X.. ECV=0X..` | the ID register and its ECV field (2 on the unit: OBSERVED) |
| `CNTHCTL_EL2 OLD=0X.. CNTFRQ_EL0=0X..` + ` FREQ=DEFAULT` | the register as found, and the counter frequency; `FREQ=DEFAULT` if it is outside 1 MHz to 1 GHz and 19.2 MHz is used |
| `REFUSED=E2H` / `REFUSED=OLD_HAS_BITS_12_TO_14` | nothing was written: E2H is set / OLD has bit 12, 13 or 14 set |
| `NEXT CNTHCTL_EL2 WRITE AFTER 8 S` | the write follows eight seconds after this line |
| `REFUSED=COUNTER_STUCK` | the counter does not run or runs backwards: the wait cannot be made and nothing was written |
| `OLD=0X.. V=0X..` | the value found and the value written |
| `R=0X.. R2=0X..` | the read-back after the write, and after the restore |
| `BITS13_14_STUCK=YES\|NO\|PARTIAL R_EQ_V=YES\|NO` | whether bits 13 and 14 are both, neither or one of them set in R, and whether R is exactly V |
| `RESTORE_RETRY R3=0X..` | R2 was not OLD: the one retry, and what it read back |
| `RESTORED=YES` | the register holds OLD again |
| `RESTORED=NO`, `NOT_RESTORED OLD=0X.. NOW=0X..`, `POWER_CYCLE_BEFORE_ANY_OTHER_PAYLOAD` | it does not, after the retry: the payload returns 2 |
<!-- /cnthctl-lines -->

The pages of the host model for the machines the host test scripts (the unit-like world: EL2, `HCR_EL2` `0x88000010`, ECV 2, 19.2 MHz,
OLD `0x3`; **the values are the model's, not a unit's**: EXPERIMENTAL, the same program the host test pins line by line). First, the
machine whose register holds the bits:

<!-- cnthctl-page -->
```
PAYLOAD CNTHCTL CURRENTEL=0X8 HCR_EL2=0X88000010 E2H=0X0
PAYLOAD CNTHCTL ID_AA64MMFR0_EL1=0X2100032310201126 ECV=0X2
PAYLOAD CNTHCTL CNTHCTL_EL2 OLD=0X3 CNTFRQ_EL0=0X124F800
PAYLOAD CNTHCTL NEXT CNTHCTL_EL2 WRITE AFTER 8 S
PAYLOAD CNTHCTL OLD=0X3 V=0X6000
PAYLOAD CNTHCTL R=0X6000 R2=0X3
PAYLOAD CNTHCTL BITS13_14_STUCK=YES R_EQ_V=YES
PAYLOAD CNTHCTL RESTORED=YES
```
<!-- /cnthctl-page -->

The tails of the other worlds (the first four lines are the same). Bits that do not stick, RES0 (`R` has lost bits 1:0 and never had
13 and 14); only bit 14 sticks; the write that puts OLD back is ignored for ever; it is ignored once and the retry works:

<!-- cnthctl-pages -->
```
# bits do not stick
PAYLOAD CNTHCTL OLD=0X3 V=0X6000
PAYLOAD CNTHCTL R=0X0 R2=0X3
PAYLOAD CNTHCTL BITS13_14_STUCK=NO R_EQ_V=NO
PAYLOAD CNTHCTL RESTORED=YES
# only bit 14 sticks
PAYLOAD CNTHCTL OLD=0X3 V=0X6000
PAYLOAD CNTHCTL R=0X4000 R2=0X3
PAYLOAD CNTHCTL BITS13_14_STUCK=PARTIAL R_EQ_V=NO
PAYLOAD CNTHCTL RESTORED=YES
# restore fails
PAYLOAD CNTHCTL OLD=0X3 V=0X6000
PAYLOAD CNTHCTL R=0X6000 R2=0X6000
PAYLOAD CNTHCTL BITS13_14_STUCK=YES R_EQ_V=YES
PAYLOAD CNTHCTL RESTORE_RETRY R3=0X6000
PAYLOAD CNTHCTL RESTORED=NO
PAYLOAD CNTHCTL NOT_RESTORED OLD=0X3 NOW=0X6000
PAYLOAD CNTHCTL POWER_CYCLE_BEFORE_ANY_OTHER_PAYLOAD
# restore needs the retry
PAYLOAD CNTHCTL OLD=0X3 V=0X6000
PAYLOAD CNTHCTL R=0X6000 R2=0X6000
PAYLOAD CNTHCTL BITS13_14_STUCK=YES R_EQ_V=YES
PAYLOAD CNTHCTL RESTORE_RETRY R3=0X3
PAYLOAD CNTHCTL RESTORED=YES
```
<!-- /cnthctl-pages -->

A machine whose bits stick **but trap nothing** ("stuck but inert") prints exactly the first page: nothing this payload can read or
write shows the difference, and a host suite asserts that. That is why a "stick" answer does not decide O1.

## What each outcome means for the monitor's timer options

INFERRED throughout, except the row marked **OBSERVED** (boot 11); every other row was not reached. The options are those of section 6.3 of the monitor port audit: **O1**
the A16 recipe (24 MHz for the guest by trapping its counter and timer, plus a `CNTHCTL_EL2` read-back refusal and a `CNTVOFF_EL2` = 0
check; needs bits 13 and 14 effective at EL2), **O2** 19.2 MHz everywhere with no scaling (profile changes only), **O3** patching the
guest away from architectural counter reads, **O4** `CNTPOFF_EL2` / ECV level 2 ("never": a read of it stalls the board). The "next
step" is a proposal for a separate, authorised change, never something this payload does.

<!-- cnthctl-decisions -->
| Outcome on the page | What it means | O1 to O4, and the next step |
| --- | --- | --- |
| `BITS13_14_STUCK=YES R_EQ_V=YES`, `RESTORED=YES` | **OBSERVED (boot 11): `OLD=0X3 V=0X6000`, `R=0X6000 R2=0X3`.** The register holds the monitor's exact value and gives the old one back; whether the bits trap anything is not shown by this page | O1 is **not eliminated and not decided** by this payload: the bits may be stuck but inert. Next: `el1trap` (T-HW2), which the unit ran in the same boot ([its answer](SP11-PAYLOAD-EL1TRAP.md#what-the-unit-showed-boot-11)). O2 and O3 unchanged; O4 unchanged (never): this payload never set ECV nor touched `CNTPOFF_EL2` |
| `BITS13_14_STUCK=NO`, `RESTORED=YES` | bits 13 and 14 read back as zero: they are not implemented or are gated (INFERRED, for example by `SCR_EL3.ECVEn` clear, which no payload can read) | **O1 is eliminated**: the monitor's recipe cannot trap the guest's counter and timer on this unit. `el1trap` has nothing to test. Next: O2 (an A16 run at 19.2 MHz, the operator's decision) or, if that fails, O3 |
| `BITS13_14_STUCK=PARTIAL` | only one of `EL1TVT` and `EL1TVCT` is held | O1 as designed (both bits) is eliminated; a design that traps only the counter or only the timer is another design, UNKNOWN. Next: O2 or O3 first |
| `BITS13_14_STUCK=YES R_EQ_V=NO` | the bits are held but R is not exactly V: bits 1:0 or others differ | the monitor never reads the register back, and its planned refusal must compare bits 14 and 13 (not the whole register) to be of use; `el1trap` still decides O1 |
| `RESTORED=NO`, `RESTORE_RETRY`, `NOT_RESTORED`, return 2 | the register cannot be put back (a write after the first is ignored, or the value is write-once) | **stop** (below). The monitor saves the old value and restores it after a run: that cannot be relied on here, and the board must be power-cycled before any other payload. O1 is blocked until this is understood |
| the page ends at `NEXT CNTHCTL_EL2 WRITE AFTER 8 S` | a hang or a reset in the first write, an `ISB` or a read-back (the board restarts: [Residual risks](#residual-risks)) | INFERRED: the write of `CNTHCTL_EL2` is not usable at EL2 on this unit (for example, EL3 handles it); the monitor must not write it. **O1 is eliminated**. Photograph, power-cycle, report |
| q1n1's fault page, `ELR_EL2` inside `cnthctl.bin` | an exception at EL2 on the access (UNDEFINED, or a trap): `ESR_EL2` bits 31:26 are the class | the same as the line above, with a class: `0x18` a trapped system register access, `0x00` UNDEFINED |
| `REFUSED=E2H` | `HCR_EL2.E2H` is set: the register has the VHE layout and the monitor's formula is not what it would be | nothing was written; whether the monitor can run in that regime is the entry study's question (C1), and this payload needs a different design for it |
| `REFUSED=OLD_HAS_BITS_12_TO_14` | the firmware left bit 12, 13 or 14 set | nothing was written. Bits 13 and 14 already set: the register holds them (read, not written) and `el1trap` can start; bit 12 set: ECV is on, which is a finding on its own: stop and report |
| `REFUSED=COUNTER_STUCK` or `REFUSED=NO_COUNTER` | the counter does not run or runs backwards, or the runner gave none: no wait can be made | nothing was written; a runner or CPU question before any write |
| `SKIPPED_NOT_AT_EL2` | the runner was not at EL2 | nothing was done |
| `FREQ=DEFAULT` on the OLD line | `CNTFRQ_EL0` is outside 1 MHz to 1 GHz | the wait used 19.2 MHz; the value is the finding (the unit's is `0x124F800`, OBSERVED) |
<!-- /cnthctl-decisions -->

## What the unit showed (boot 11)

The unit's page (2026-11-16, 11:44): `cnthctl` and `el1trap` ran in one boot from one stick, `cnthctl` first. These are the eight lines between its
`CALL 0` and `DONE` lines, read by the coordinator from frames of a video (two frames agree on every line; not CRC-checked). **They are the unit's;
the pages above are the model's.** The whole page of 37 lines, `el1trap`'s included, is in
[the results](SP11-PAYLOAD-RESULTS.md#payloads-cnthctl-and-el1trap-boot-11).

<!-- cnthctl-unit-page -->
```
PAYLOAD CNTHCTL CURRENTEL=0X8 HCR_EL2=0X88000010 E2H=0X0
PAYLOAD CNTHCTL ID_AA64MMFR0_EL1=0X2100122100001024 ECV=0X2
PAYLOAD CNTHCTL CNTHCTL_EL2 OLD=0X3 CNTFRQ_EL0=0X124F800
PAYLOAD CNTHCTL NEXT CNTHCTL_EL2 WRITE AFTER 8 S
PAYLOAD CNTHCTL OLD=0X3 V=0X6000
PAYLOAD CNTHCTL R=0X6000 R2=0X3
PAYLOAD CNTHCTL BITS13_14_STUCK=YES R_EQ_V=YES
PAYLOAD CNTHCTL RESTORED=YES
```
<!-- /cnthctl-unit-page -->

Around it the runner printed `LOADED INDEX=0 BASE=0XCEA8D000 BYTES=3094 SHA=9F06B31DA4BDC395 TYPE=1` (the size and digest prefix of the binary this tree builds),
`VERIFY=OK`, `CALL 0 9F06B31DA4BDC395` and `DONE INDEX=0 RETURN=0X0 STACK=OK LOADS=0 FAULTS=0 REFUSED=0 LINES=8 DROPPED=0`. What it shows, OBSERVED once:

* **The page has the shape of the model's normal page** (`bits stick`, above): the lines are the same but for the unit's own value of `ID_AA64MMFR0_EL1`
  (`0X2100122100001024`, ECV 2, against the model's `0X2100032310201126`). `CURRENTEL=0X8` (EL2), `HCR_EL2` `0x88000010` with E2H clear, `CNTHCTL_EL2` as found
  `0x3` (bits 12 to 14 clear), `CNTFRQ_EL0` `0x124F800` (19.2 MHz): no refusal applied.
* **Bits 14 and 13 stuck, exactly.** V is `0x6000`, R reads `0x6000` (`BITS13_14_STUCK=YES R_EQ_V=YES`): the register held the monitor's value as written, bits 1:0
  cleared, bit 12 not set. The old value came back (`R2=0X3`, `RESTORED=YES`), the payload returned 0 and the write, the read-backs and the restore caused no fault,
  no hang and no restart (the video runs 61 s).
* **The row it matches** is the first of [the decision table](#what-each-outcome-means-for-the-monitors-timer-options), now marked OBSERVED. This payload does not
  say whether the bits trap anything: O1 stays not decided here, and [`el1trap`](SP11-PAYLOAD-EL1TRAP.md#what-the-unit-showed-boot-11) read what they do in the same boot.
* **Not shown, UNKNOWN:** any other value of `OLD`, another boot or unit (one unit, one boot), and the refusals (`E2H`, bits 12 to 14 set, a stuck counter), which
  did not apply. Whether bits 13 and 14 depend on `SCR_EL3.ECVEn` is UNKNOWN (the Arm ARM was not re-read).

## Authorisation and the stop rule

**Authorisation.** This payload writes `CNTHCTL_EL2`, an EL2 system register. The runner's rule for anything beyond a read applies
([SP11-PAYLOAD.md](SP11-PAYLOAD.md#what-the-next-payloads-need-from-this-abi), item 3, and the hardware rules of `AGENTS.md`): the
operator names the payload and its SHA-256 in writing before it runs on the unit, together with the register, its encoding
(`S3_4_C14_C1_0`), the value (V) and the fact that it is restored. **No run is authorised by this document, by its test, or by the
fact that the file is on the stick.** The digest is the manifest's: `python3 tools/test-q1n1-sp11-payload-cnthctl.py facts` prints
it, and the page shows its first eight bytes in `PAYLOAD LOADED` and `PAYLOAD CALL`.

**Stop rule.** After the run the operator reads the page before anything else is run. The sequence stops, and the unit is power-cycled,
on any of: `RESTORED=NO` or `NOT_RESTORED`; a page that ends at the `NEXT` line; a fault page; a board restart; `REFUSED=OLD_HAS_BITS_12_TO_14`
with bit 12 set; any value the decision table does not list. `el1trap` is staged only after `BITS13_14_STUCK=YES` with `RESTORED=YES`
was read and the operator has authorised it by name and digest in turn (boot 11 ran both in one boot by the operator's decision, [below](#staging-plan):
the rule stands for later runs, and no stop condition occurred). There is no retry of the payload in the same boot.

## Staging plan

**What was done.** Boot 11 (2026-11-16) ran `cnthctl` and `el1trap` in **one boot**: one stick, one manifest (624 bytes) listing `CNTHCTL.BIN` then `EL1TRAP.BIN`, under
slbounce's `SLBOUNCE-DEVHE-MARK.EFI` and the runner (`Q1N1-PAYLOAD.EFI --el2`), started by one autorun step and filmed from the Shell's countdown on. That is not
what this document proposed: `cnthctl` **alone** on its stick, so that its page is the only page, its risk the only risk and a restart costs nothing else, and `el1trap` on a
second stick only after a normal answer ([its staging plan](SP11-PAYLOAD-EL1TRAP.md#staging-plan)). The operator decided otherwise for that boot, naming both payloads and their SHA-256 (about 11:20), and `el1trap` ran behind
its own refusals without this page read first: **that changed the documented rule by the operator's decision for that boot**. The stop rules above stand for every later run,
and none was triggered. The one-payload form below remains the way to run `cnthctl` by itself, and a manifest of both is made the same way with both files. With the runner
and the payloads built as in [SP11-PAYLOAD.md](SP11-PAYLOAD.md#build):

```sh
python3 tools/sp11_payload_manifest.py --out-dir build/stick build/uefi/payloads/cnthctl.bin
```

writes `build/stick/SP11/PAYLOAD.MAN` and `build/stick/SP11/CNTHCTL.BIN`. The stick of the proposal holds exactly `SP11\Q1N1-PAYLOAD.EFI` (not written by the
tool), `SP11\PAYLOAD.MAN` and `SP11\CNTHCTL.BIN`, and the run is, from the UEFI Shell with slbounce loaded as for the other payloads,
`SP11\Q1N1-PAYLOAD.EFI --el2`. The conditions of every run: AC power or at least 50% battery, the page filmed or photographed from the
`NEXT` line on, one hardware client at a time. (The runner would take `cnthctl` after `psci`, and a test shows the validator accepts that chain.) Status of the staging:
**boot 11 ran both payloads in one boot by the operator's decision; the one-payload proposal was not run.**

## What QEMU shows

OBSERVED, QEMU 11.1.3 (`virt,virtualization=on,gic-version=3`, TCG, EDK2 AArch64, one CPU), by
`tools/test-q1n1-sp11-payload-qemu-cnthctl.py`, the real binary at a real EL2 with its MMU on. With `-cpu max` (ECV 2) the machine holds
the bits as written; with `-cpu cortex-a76` (ECV 0) they read back as zero. QEMU's counter is 1 GHz (`-cpu max`), so the wait is
eight real seconds of that counter. The page of `-cpu max`:

<!-- cnthctl-qemu-panel -->
```
CURRENTEL=0X8 HCR_EL2=0X8000038 E2H=0X0
ID_AA64MMFR0_EL1=0X2100032310201126 ECV=0X2
CNTHCTL_EL2 OLD=0X3 CNTFRQ_EL0=0X3B9ACA00
NEXT CNTHCTL_EL2 WRITE AFTER 8 S
OLD=0X3 V=0X6000
R=0X6000 R2=0X3
BITS13_14_STUCK=YES R_EQ_V=YES
RESTORED=YES
```
<!-- /cnthctl-qemu-panel -->

With `-cpu cortex-a76` the `R=` line reads `R=0X0 R2=0X3`, the `BITS13_14_STUCK=` line `BITS13_14_STUCK=NO R_EQ_V=NO`, and the ECV field `ECV=0X0`. What the suite
asserts, besides these pages: the wait is between 7 and 40 seconds of wall-clock time between the `NEXT` line and the result (the serial
log is read every 0.2 s); in a chain `state`, `cnthctl`, `state` every register the `state` payload prints (`HCR_EL2`, `SCTLR_EL2`,
`TCR_EL2`, `TTBR0_EL2`, `MAIR_EL2`, `VBAR_EL2`, `CPTR_EL2`, `CNTHCTL_EL2`, `CNTFRQ_EL0`, `DAIF`, `SPSEL`) is identical before and after; a copy
of the source that never writes OLD back (one edit, asserted to apply once) prints `RESTORED=NO`, `NOT_RESTORED OLD=0X3 NOW=0X6000` and returns 2, and
the second `state` page shows `CNTHCTL_EL2=0X6000`: the failure is seen by the next payload, not hidden; no file of the stick changes.

What QEMU cannot show: the unit's EL3, the unit's counter, any trap on the unit (QEMU's `-cpu max` holds the bits and, per the next payload's suite, traps with
them: that is QEMU, not the unit), and whether a write of `CNTHCTL_EL2` hangs the board. Boot 11 answered the last two ([above](#what-the-unit-showed-boot-11):
the next payload's traps worked and the write hung nothing: one unit, one boot); whether `SCR_EL3.ECVEn` lets the bits be held, or lets a write of them do anything,
stays UNKNOWN (no payload can read `SCR_EL3`). The unit's other rows of the decision table are UNKNOWN.

## Tests

Hardware: NOT RUN by these commands (they check a model, QEMU and this document; the unit's one run is [above](#what-the-unit-showed-boot-11)). Every command writes only under `build/`.

| Command | What it runs |
| --- | --- |
| `python3 tools/test-q1n1-sp11-payload-cnthctl.py` | the host program `tools/test-q1n1-sp11-payload-cnthctl.c` (six suites over a modelled machine whose register can hold the bits, lose them as RES0, hold one, or refuse the restore: the exact events, the wait to the read, the window, an independent oracle of the page, 6000 random worlds) under ASan and UBSan; 64 seeded-bug mutants and an unmutated control; the source audits; the allow-list on the binary with 37 seeded bad binaries and a flat binary patched behind the disassembly; the stick, the manifest tool and the runner's own validator |
| `python3 tools/test-q1n1-sp11-payload-qemu-cnthctl.py` | the QEMU boots above |
| `python3 tools/test-q1n1-sp11-payload-cnthctl-doc.py` | this document against the source, the host model and the binary, with 67 seeded mistakes in the document |
| `python3 tools/test-q1n1-sp11-payload-build.py` | `make payloads` builds `cnthctl.bin`, the ELF check, the allow-list of every payload, two builds byte-identical, the same bytes at another link address |
| `python3 tools/test-q1n1-sp11-payload-cnthctl.py facts` | the size, digest and instruction inventory of the built binary |

## Planning a chain's page

The formula is the one of [the runner's planning table](SP11-PAYLOAD.md#the-chain-several-payloads-in-one-boot): `LOADED` for each file and
`READY` (files + 1), `VERIFY`, `CALL` and `DONE` for each payload (3), and the payload's own most lines. The host test measures the most
`cnthctl` prints over every EL and every machine it scripts: 11.

<!-- cnthctl-chain-budget -->
| Chain | Lines | Fits the unit's 89 rows | Fits the 60 the layout asks for |
| --- | --- | --- | --- |
| `cnthctl` alone | (1 + 1) + 3 + 11 = 16 | yes | yes |
| `psci`, then `cnthctl` | (2 + 1) + 3 x 2 + 30 + 11 = 50 | yes | yes |
<!-- /cnthctl-chain-budget -->

A normal run is 8 lines, so even the first row has room to spare.

## Residual risks

* **The write was OBSERVED once on this unit (boot 11), which does not make it safe in general.** A write of `CNTHCTL_EL2` at EL2 is an ordinary EL2 access, and
  `state` and `timer` already read it; boot 11 wrote it (V, then OLD) and the page went on. The `CNTPOFF_EL2` stall is INFERRED to come from an EL3 gate
  (`SCR_EL3.ECVEn`); boot 11 neither confirms nor refutes that, and whether bits 13 and 14 depend on that gate is UNKNOWN
  ([the results](SP11-PAYLOAD-RESULTS.md#payloads-cnthctl-and-el1trap-boot-11)). A hang or a reset on another boot or unit is still the `NEXT`-line row of the table.
* **A board restart is not a surprise to plan for, and not one to blame on this payload.** Restarts of the board have been seen after the
  `cpuon` payload, INFERRED to be associated with its core power cycling (cause UNKNOWN), and a runner flow with a read-only `psci` payload
  stayed up for 224 s and 268 s in two boots ([the restart control](SP11-PAYLOAD-RESULTS.md#the-restart-control), 2026-11-16).
  `cnthctl` powers no core off. A restart in its run is a finding about its write, to be reported with the last line of the page; boot 11's video (61 s) shows none.
* **The restore is the payload's own claim** (R2 and R3 are read back, which is what `RESTORED=YES` says), and it covers the register,
  not the effect of the window, which is none (the temporary-value argument above, INFERRED).
* **The read-back says little about function.** A held bit is a stored bit; the next payload is the one that looks at what it does.
* **E2H.** The payload refuses `E2H` set; the unit's value is OBSERVED clear.
* The page attributes of the payload image and its stack at EL2 are as for every payload: this one only reads and writes registers
  and its own stack.

## Status

EXPERIMENTAL. Ran once on the unit (boot 11, 2026-11-16, one unit, one boot): OBSERVED, [above](#what-the-unit-showed-boot-11): bits 14 and 13 stuck, the old value
came back, no refusal, no fault page, no restart. Also OBSERVED on the unit by other payloads and by q1n1's page: `HCR_EL2` `0x88000010`, `CNTHCTL_EL2` `0x3` at handoff,
`CNTFRQ_EL0` `0x124F800`, `ID_AA64MMFR0_EL1.ECV` 2, `DAIF` `0x3C0` (Snapintosh `docs/SP11-MONITOR-PORT.md`, section 6.2, which cites its sources).
OBSERVED under QEMU only: the pages above and the behaviours listed under them. UNKNOWN: what this payload prints on another boot or unit, and the refusal paths on the unit.
