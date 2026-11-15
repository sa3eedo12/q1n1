<!-- SPDX-License-Identifier: MIT -->
# SP11 payload `el2mem`: what EL2's stage-1 map reaches, asked of the MMU, and the registers a monitor reads at launch

`payloads/el2mem.c` is one payload of the stick payload runner described in [SP11-PAYLOAD.md](SP11-PAYLOAD.md): the manifest
and the stick files, [the chain](SP11-PAYLOAD.md#the-chain-several-payloads-in-one-boot), ABI v1 and the
[line catalogue](SP11-PAYLOAD.md#line-catalogue) are defined there and not repeated. Its relatives are
[`state`](SP11-PAYLOAD-STATE.md), which reads EL2's registers, and [`cpuon`](SP11-PAYLOAD-CPUON.md), whose `NEXT` line and eight
seconds of counter it reuses before the reads that may go to EL3; its companion is [`hashbig`](SP11-PAYLOAD-HASHBIG.md), with
which it shares the code that asks the MMU and reads the memory map (`payloads/payload-mmu.h`) and a chain. Evidence labels as
there: VERIFIED, OBSERVED, INFERRED, EXPERIMENTAL, UNIMPLEMENTED, UNKNOWN. **EXPERIMENTAL; hardware NOT RUN.**

`el2mem` is **read only** and asks the machine two things the monitor port needs before it can place itself (the monitor-port
document of the Snapintosh repository, work item 2, unknowns U1 and U5):

1. **Does the EL2 stage-1 map that UEFI and slbounce left reach the conventional RAM a monitor would use**, in particular the
   30 GiB bank `0x880000000` to `0x1000000000`, and with which memory attributes? Nothing has shown it. `AT S1E2R` answers without
   touching the memory at the address: the MMU walks EL2's tables and reports in `PAR_EL1`.
2. **A handful of registers the monitor reads at launch** and no page has shown: `ID_AA64DFR1_EL1`, `ID_AA64ISAR2_EL1`,
   `ID_AA64MMFR1_EL1` (its PAN field was never read cleanly: a photographed value failed its CRC check), `ID_AA64PFR2_EL1`,
   `AIDR_EL1`, `REVIDR_EL1`, `MDCR_EL2`, `MDSCR_EL1`, `OSLSR_EL1` and `ICC_SRE_EL2`.

**No value of this payload has been OBSERVED on the unit.** What the design rests on, OBSERVED on earlier runs
([the results](SP11-PAYLOAD-RESULTS.md)): q1n1 runs at EL2 with `HCR_EL2` E2H 0, `SCTLR_EL2` `0x0000100030C5183D` (MMU and caches
on), `TCR_EL2` `0x80843514`, `MAIR_EL2` `0xFFBB4400` (attribute 0 `0x00` Device, 1 `0x44` non-cacheable, 2 `0xBB` write-through,
3 `0xFF` write-back) and `CNTFRQ_EL0` `0x124F800` (19.2 MHz); and the final memory map of boot 6 held 32,105 MiB of Conventional
memory, the 30 GiB bank among it (the monitor-port document). The largest low extent there is 590 MiB, which is why the bank matters.

## What it does, in order

1. **Where it runs.** `CurrentEL` first and the counter frequency (`CNTFRQ_EL0`; 19.2 MHz is used if it is outside 1 MHz to
   1 GHz). Not at EL2 it prints `REFUSED NOT_AT_EL2` and returns 2 with nothing else done: `AT S1E2R` and `MDCR_EL2` are
   UNDEFINED below EL2. The runner already refuses to call a payload below EL2; this is the second guard.
2. **The final memory map**, read in place through the pointer the arguments carry. It is refused, with one `MAP_REFUSED` line
   that names why and nothing of it read, when the stride is below 40 or not a multiple of 8, the size is not whole descriptors,
   the buffer is not aligned or leaves the 48-bit space, or it holds more than 1024 descriptors (return 3; the register reads below
   still run). Otherwise one `MAP` line: the descriptors, the stride, the **merged** extents of Conventional memory (type 7) and
   their MiB. A descriptor that is unaligned, empty or beyond 48 bits is counted (`IGNORED`) and never used.
3. **The scan.** Every Conventional extent, in address order (at most 64), is asked about with `AT S1E2R` at its first page, at every
   2 MiB boundary inside it and at its last page. The answers fold into **keys** (one key is one result: attribute, shareability,
   NS, identity or the fault code) and into **runs** (consecutive probes with one key). One `KEY` line for each distinct key (at most
   three), one `OUTLIER` line for each run of a key that is not the commonest (at most five), one `SCAN` summary. A hole narrower
   than the stride that is not at an edge of an extent is missed: that is the method's limit, not a finding.
4. **The bank on its own line**, whatever the map merges: `BANK` says how much Conventional memory lies in it, how many probes
   fell in it and whether they were all mapped with one result; the first fault and its fault code if not.
5. **The controls.** The first descriptor of each type 1 to 6 (the firmware's and the runner's own memory), the payload's own first page
   and the first page of its stack are asked about the same way, in one `CONTROL` line. Memory that is certainly in use must read as
   mapped; if it does not, the method is doubtful, and the page says so by itself.
6. **Four guarded loads**, the first and last 32-bit word of the bank's Conventional memory and of the largest Conventional extent
   below 4 GiB, through the runner's `load32`, **only if the AT of that very page said mapped**; otherwise `SKIPPED_NOT_MAPPED`.
   A load the runner reports as faulted prints `ERR<n>`. Nothing is read at an address taken from a descriptor except those four
   words.
7. **The ID registers that cannot trap** (INFERRED): one `ID` group with the registers above, and the three fields of
   `ID_AA64MMFR1_EL1` the monitor's launch checks ask about, decoded: `PAN` (bits 23:20), `VH` (11:8), `HAFDBS` (3:0).
8. **The three reads that may go to EL3**, last: `MDSCR_EL1`, `OSLSR_EL1`, `ICC_SRE_EL2` (INFERRED: `MDCR_EL3.TDA`, `MDCR_EL3.TDOSA`
   and `ICC_SRE_EL3.Enable` may route them there; none was ever tried on this unit). Each is preceded by `NEXT <REG> AFTER 8 S` and
   eight seconds of waiting on the counter, so a hang or a reset leaves a page that was photographed and names the register. A wait
   that cannot be made (no counter op, or a counter that does not run or runs backwards) means the read is **not** made
   (`SKIPPED=NO_COUNTER` or `SKIPPED=COUNTER_STUCK`).
9. **The end.** One `DONE` line: how the scan ended, how many of the four loads were made and read, how many hazard reads were made,
   and `SUPPRESSED=<n>` if the page budget dropped lines. The return value is 0, or 1 for a bad argument block, 2 below EL2, 3 for a
   refused map. A scan that found faults still returns 0: the answer is on the page.

Never read: `CNTPOFF_EL2` and `CNTVOFF_EL2` (a read of `CNTPOFF_EL2` never returned on this unit; tested: neither name is in the
source or the binary). Never written: nothing but the payload's own stack.

**One deviation from the request.** `MDSCR_EL1` was listed with the reads that cannot trap. It is announced and waited for like
`OSLSR_EL1` and `ICC_SRE_EL2`, because `MDCR_EL3.TDA` is INFERRED to route it to EL3 as well; it costs eight seconds and one line.

## What `AT S1E2R` is, and what it clobbers

`AT S1E2R, <Xt>` translates the address in `Xt` through the **EL2 stage-1 tables** as a load at EL2 would, and leaves the answer in
`PAR_EL1`. It makes no access at the address. A missing mapping, or a walk that ends in an external abort, is reported in
`PAR_EL1.F` and `PAR_EL1.FST`, not taken as an exception (INFERRED from the architecture; the Arm ARM was not re-read for this
work). An `ISB` must separate the `AT` from the read of `PAR_EL1`, or the read may see the old value: the payload has exactly one
`AT`, one `ISB` and one read of `PAR_EL1`, in one function (`pl_at_s1e2r`), and the host tests replace that function by a model.

<!-- mmu-par -->
| `PAR_EL1` field | Bits | Decoded as | Evidence |
| --- | --- | --- | --- |
| `F` | 0 | 0 mapped, 1 fault | VERIFIED against Linux `arch/arm64/include/asm/sysreg.h` (read on 2026-11-16) |
| `FST` | 6:1, when `F` is 1 | the fault code, printed raw with its class and level: `0X5:TRANS_L1` | VERIFIED as above; the names of the classes are INFERRED from the architecture |
| `SH` | 8:7, when `F` is 0 | `NSH`, `RES` (the reserved encoding), `OS`, `IS` | VERIFIED as above |
| `NS` | 9, when `F` is 0 | shown as `.NS1` when set, never interpreted | VERIFIED as a field; what it means for a Non-secure EL2 translation is UNKNOWN |
| output address | 51:12, when `F` is 0 | compared with the input page: `.NONIDENT` when they differ | VERIFIED as above |
| `ATTR` | 63:56, when `F` is 0 | the MAIR attribute byte of the mapping itself (not an index): `DEVICE`, `NC`, `WT`, `WB`, or `OTHER=0XNN` | VERIFIED as above |
<!-- /mmu-par -->

The attribute names: Device is a high nibble 0 with no bits 1:0 (nGnRnE, nGnRE, nGRE, GRE); Normal memory has one cacheability
per nibble, `0100` non-cacheable (`NC`), `10xx` write-through (`WT`), `11xx` write-back (`WB`), all non-transient; anything else
(transient hints, differing nibbles, tagged memory) is `OTHER=0XNN` with the byte.

**`PAR_EL1` is clobbered, and that is harmless.** `AT` writes it and the payload does not restore it. It is the scratch result of
`AT`: nothing reads it without its own `AT` and `ISB` first. Nothing of the runner image touches it: a search of the tree finds
`PAR_EL1` only in `src/hv_vm.c` and `src/arm_cpu_regs.h`, and `platform/uefi/Makefile` builds no file of `src/` (VERIFIED, a host
fact). After the last payload the runner prints its page and waits for a power cycle.

## What it may issue

The binary is checked by `tools/sp11_payload_testlib.py`, by the disassembly and, independently, by the encoding of every aligned
word of its code, with the memory discipline of `tools/sp11_payload_memcheck.py` (next section). Its policy is the first to use
the allow-list key `read_only` and, with `allow` for exactly the form `at s1e2r`, to name an `AT`. The policies of the older
payloads do not use these keys and are checked exactly as before: a test compares the new engine with the base commit's on a
corpus of binaries under every older policy.

<!-- el2mem-instructions -->
| Kind | Operands allowed | Where | Why |
| --- | --- | --- | --- |
| `MRS` | `CurrentEL`, `CNTFRQ_EL0`, once each | `payload_entry` | where it runs; the counter frequency of the waits |
| `MRS` | `ID_AA64MMFR1_EL1`, `ID_AA64DFR1_EL1` (`S3_0_C0_C5_1`), `ID_AA64ISAR2_EL1` (`S3_0_C0_C6_2`), `ID_AA64PFR2_EL1` (`S3_0_C0_C4_2`), `AIDR_EL1`, `REVIDR_EL1`, `MDCR_EL2`, once each | `report_ids` | the registers the monitor reads at launch, which cannot trap (INFERRED) |
| `MRS` | `MDSCR_EL1`, `OSLSR_EL1`, `ICC_SRE_EL2`, once each | `report_hazards` | the reads that may go to EL3, each behind a `NEXT` line and eight seconds |
| `MRS` | `PAR_EL1`, once | `pl_at_s1e2r` | the answer of the `AT` |
| `AT` | `S1E2R`, one site, **no other form** | `pl_at_s1e2r` | asks the MMU, makes no access |
| `ISB` | one site | `pl_at_s1e2r` | `PAR_EL1` must not be read before the `AT` is done |
| loads | the stack, the image, the arguments and the pointers they hold (the memory map) | everywhere | the discipline below |
| stores | the payload's own stack only | everywhere | the discipline below |
| `BL`, `BLR`, `B`, `RET` | `BLR` is the runner's ops (`puts`, `hex`, `counter`, `load32`) | everywhere | the ABI |
<!-- /el2mem-instructions -->

Nothing else: no `MSR`, `DC`, `IC`, `TLBI`, `SYS`, no other `AT` (`S1E2W`, `S1E1R`, `S12E1W` and the rest are each a seeded bad
binary the check must refuse), no `SMC`, `HVC`, `SVC`, `ERET`, `WFI`, `WFE`, `SEV`, no `DSB` or `DMB`, no exclusive or atomic. The
binary is **12,834 bytes**, 2,996 instructions.

## Memory rules

| # | Rule | Why |
| --- | --- | --- |
| 1 | The **only** stores are to the payload's own stack: the page, the scan's tables and the lines. | A read-only payload cannot change what it measures. |
| 2 | The final memory map is read in place, through the pointer in the arguments, **reloaded for every descriptor** and kept nowhere else; a map that fails the checks is not read at all. | The map is in the runner's memory and stays readable; checking before reading keeps a bad size or stride from walking off its buffer. |
| 3 | Every other read of RAM or of a device is the runner's guarded `load32`, and only at a page an `AT` of that very page said mapped. | A read the MMU cannot translate is not made; a faulting read is the runner's to catch. |
| 4 | The payload reads no memory at an address taken from a descriptor but those four words. The `AT` scan reads none: it asks the MMU. | The point of the method. |
| 5 | The source passes `a` to every helper that prints, keeps no pointer in a structure and returns none. | The binary check follows each register from the arguments or the stack to every load and store, and a pointer it cannot follow is a violation. |

`tools/sp11_payload_memcheck.py` reads the disassembly and gives every register one provenance class (the stack, a stack pointer a
caller passed, the image, the arguments, a pointer the arguments hold, or unknown), joined at control-flow merges and followed
through calls and through the 64-bit stack slots the compiler spills to. For a policy with `read_only` every store must have a
base that is provably the stack and every load a base that is provably the stack, the image, the arguments or a pointer they hold.
It proves the **base** of an access, never its offset: the host tests bound the offsets. It assumes that a callee does not
overwrite its caller's spill slots and that the runner's ops, outside the binary, do what the ABI says. It may refuse a safe
binary (the source is then written differently); it must never pass an unsafe one. The seeded tests include a store through the
arguments, through a descriptor's address and through the map pointer, and a load through a descriptor's address.

## What it prints

At most **26 lines** (the page is shared: the runner's own lines and the other payloads' take the rest of its 60), each at most 100
characters in the page font. Every line begins `PAYLOAD EL2MEM `. Values are printed as the runner's hex op prints them (`0X` and
capitals). The last four lines the payload may print are reserved for the three `NEXT` lines and the last line, so a long report
can never push them out: another line that would leave less room is dropped and counted in `SUPPRESSED=` on the last line. A
group that does not fit a line continues on another with the same label; an entry is never cut. `<walk>` is one AT answer:
`WB.IS`, or `DEVICE`, `NC`, `WT`, `OTHER=0XNN`, then `.NSH`, `.OS`, `.IS` or `.RES`, then `.NS1` and `.NONIDENT` if they apply; a fault
is `FAULT=0X<code>:TRANS_L1` (class `ADDR`, `TRANS`, `ACCESS` or `PERM`, and the level).

<!-- el2mem-lines -->
| Line | Meaning |
| --- | --- |
| `START CURRENTEL=0X.. FREQ=<n>` | the exception level and the counter frequency the waits use |
| `REFUSED NOT_AT_EL2` | CurrentEL is not EL2: nothing else was done (return 2) |
| `MAP_REFUSED STRIDE_BELOW_40` / `STRIDE_NOT_A_MULTIPLE_OF_8` / `SIZE_NOT_WHOLE_DESCRIPTORS` / `BUFFER_OUT_OF_RANGE` / `TOO_MANY_DESCRIPTORS` | the final map was not read, and why (return 3); the register reads go on |
| `MAP DESC=<n> STRIDE=<n> CONV_EXTENTS=<n> CONV_MIB=<n>` + ` IGNORED=<n>` + ` NOT_SCANNED=<n>` | descriptors, stride, merged Conventional extents and their MiB; descriptors unusable; extents beyond the 64 it scans |
| `SCAN SKIPPED_NO_CONVENTIONAL_EXTENT` / `SCAN NO_PROBES` | there was nothing to scan / no probe was made |
| `KEY RESULT=<walk> PROBES=<n> FIRST=0X.. LAST=0X..` | one line for each distinct result (at most three): the answer, how many probes gave it, the first and last address asked |
| `OUTLIER RESULT=<walk> FROM=0X.. TO=0X.. PROBES=<n>` | a run of consecutive probes whose answer is not the commonest one (at most five lines) |
| `SCAN EXTENTS=<n> PROBES=<n> ALL=MAPPED ATTR=WB SH=IS` + ` NS=1` + ` NONIDENT` | every probe was mapped with one result |
| `SCAN EXTENTS=<n> PROBES=<n> MAPPED=<n> FAULT=<n> KEYS=<n> RUNS=<n>` + ` OUTLIERS_NOT_LISTED=<n>` + ` RUNS_NOT_RECORDED=<n>` | the results differ; how many outlier runs were not listed and how many runs the payload had no room to record |
| `BANK NOT_CONVENTIONAL_IN_THE_MAP` | the map has no Conventional memory in `0x880000000` to `0x1000000000` |
| `BANK CONV_MIB=<n> PROBES=<n> ALL=MAPPED RESULT=<walk>` | every probe in the bank was mapped with one result |
| `BANK CONV_MIB=<n> PROBES=<n> FAULT=<n> SAME_AS_FIRST=<n>` + ` FIRST_FAULT=0X.. AT=<walk>` | the bank has a hole or a different answer: how many faulted, how many agree with the first, where the first fault is and what the MMU said there |
| `CONTROL T1=<walk> ... T6=<walk> CODE=<walk> STACK=<walk>` | one page of each firmware type 1 to 6 (`Tn=ABSENT` if the map has none), the payload's first page and its stack's |
| `LOAD BANK_FIRST(0X..)=0X.. BANK_LAST(0X..)=0X.. LOW_FIRST(0X..)=0X.. LOW_LAST(0X..)=0X..` | the words read, each as `NAME(address)=value`; `SKIPPED_NOT_MAPPED`, `SKIPPED_NO_LOAD32` or `ERR<n>` instead of a value |
| `LOAD BANK=SKIPPED_NOT_CONVENTIONAL` / `LOW=SKIPPED_NO_EXTENT` | there is no such memory, so no load |
| `ID DFR1=0X.. ISAR2=0X.. MMFR1=0X.. PAN=<n> VH=<n> HAFDBS=<n> PFR2=0X.. AIDR=0X.. REVIDR=0X.. MDCR_EL2=0X..` | the registers that cannot trap, and the three decoded fields (the page wraps the group where it must) |
| `NEXT MDSCR_EL1 AFTER 8 S` | the read of `MDSCR_EL1` follows eight seconds after this line; the same for `OSLSR_EL1` and `ICC_SRE_EL2` |
| `MDSCR_EL1 SKIPPED=NO_COUNTER` / `SKIPPED=COUNTER_STUCK` | the wait could not be made, so the read was not (the same for the other two) |
| `MDSCR_EL1 RAW=0X..` | the value of `MDSCR_EL1` |
| `OSLSR_EL1 RAW=0X.. OSLK=<n>` | the value, and bit 1, the OS lock |
| `ICC_SRE_EL2 RAW=0X.. SRE=<n> ENABLE=<n>` | the value, bit 0 and bit 3 |
| `DONE SCAN_ALL_MAPPED` / `SCAN_HAS_FAULTS` / `SCAN_NOT_RUN` / `MAP_REFUSED` ` LOADS_OK=<n> OF=<n> HAZARD_READS=<n>` + ` SUPPRESSED=<n>` | how the scan ended, the loads read of those made, the hazard reads made, the lines dropped |
<!-- /el2mem-lines -->

**A normal run**, as the host model prints it (17 lines; the values are the model's, **not** a unit's: a map of eight Conventional
extents with the bank, all mapped write-back inner-shareable, and an ID register file made up for the test; EXPERIMENTAL):

<!-- el2mem-page -->
```
PAYLOAD EL2MEM START CURRENTEL=0X8 FREQ=19200000
PAYLOAD EL2MEM MAP DESC=16 STRIDE=48 CONV_EXTENTS=8 CONV_MIB=32081
PAYLOAD EL2MEM KEY RESULT=WB.IS PROBES=16051 FIRST=0X80000000 LAST=0XFFFFFF000
PAYLOAD EL2MEM SCAN EXTENTS=8 PROBES=16051 ALL=MAPPED ATTR=WB SH=IS
PAYLOAD EL2MEM BANK CONV_MIB=30720 PROBES=15361 ALL=MAPPED RESULT=WB.IS
PAYLOAD EL2MEM CONTROL T1=WB.IS T2=WB.IS T3=WB.IS T4=WB.IS T5=WB.IS T6=WB.IS CODE=WB.IS STACK=WB.IS
PAYLOAD EL2MEM LOAD BANK_FIRST(0X880000000)=0X25A50008 BANK_LAST(0XFFFFFFFFC)=0X5A5AFFF3
PAYLOAD EL2MEM LOAD LOW_FIRST(0X80000000)=0X25A50000 LOW_LAST(0XA4DFFFFC)=0X17AFFFC
PAYLOAD EL2MEM ID DFR1=0X0 ISAR2=0X21 MMFR1=0X311122 PAN=3 VH=1 HAFDBS=2 PFR2=0X0 AIDR=0X0
PAYLOAD EL2MEM ID REVIDR=0X0 MDCR_EL2=0X0
PAYLOAD EL2MEM NEXT MDSCR_EL1 AFTER 8 S
PAYLOAD EL2MEM MDSCR_EL1 RAW=0X0
PAYLOAD EL2MEM NEXT OSLSR_EL1 AFTER 8 S
PAYLOAD EL2MEM OSLSR_EL1 RAW=0X8 OSLK=0
PAYLOAD EL2MEM NEXT ICC_SRE_EL2 AFTER 8 S
PAYLOAD EL2MEM ICC_SRE_EL2 RAW=0X9 SRE=1 ENABLE=1
PAYLOAD EL2MEM DONE SCAN_ALL_MAPPED LOADS_OK=4 OF=4 HAZARD_READS=3
```
<!-- /el2mem-page -->

The worst page the host tests measure over every world they script is the full 26 lines (a bank with eight alternating Device,
non-cacheable and faulting runs, a page that is not an identity map, a fault in the low extent and a load that aborts); a page built
with only 14 or 10 lines drops lines and counts them, and never drops a `NEXT` line or the last one.

## What each outcome means for the monitor

INFERRED throughout: nothing below has been observed on the unit. The "next step" is a proposal for a separate, authorized change,
never something this payload does.

<!-- el2mem-decisions -->
| Outcome on the page | What it means | Next step |
| --- | --- | --- |
| `BANK CONV_MIB=30720 ... ALL=MAPPED RESULT=WB.IS`, and `LOAD BANK_FIRST(...)=0X..` with a value | EL2's stage-1 reaches the whole bank as Normal write-back inner-shareable memory and a load there answers: U1 is answered yes for the bank, and a monitor placed there needs no map of its own | placement in the bank (the monitor-port decision D1) is open; U7 (a guest in the bank) still needs its own run |
| `BANK NOT_CONVENTIONAL_IN_THE_MAP` | the final map has no free memory in the bank on this boot: the premise of the bank placement is false for this firmware state | read the `MAP` line against the map page of the earlier boots; the low extents are the only candidate |
| `BANK ... FAULT=<n> SAME_AS_FIRST=<n> FIRST_FAULT=0X.. AT=FAULT=0X..:TRANS_L<n>` | part of the bank is not mapped at EL2; the level in the fault code says which table level has no entry (INFERRED) | the monitor must install its own EL2 mapping for what it uses, or place elsewhere; the stage-1 of EL2 is today someone else's |
| `OUTLIER RESULT=DEVICE...` or `RESULT=NC...` inside Conventional memory | some Conventional memory is mapped Device or non-cacheable at EL2 | the monitor must not put code, tables or bulk-hashed data there; `hashbig` shows the attributes of the loaded file itself |
| `KEY RESULT=WB.IS.NS1` (or `NS=1` on the `SCAN` line) | the PAR_EL1 NS bit is set for the translations; its meaning for a Non-secure EL2 translation is UNKNOWN, QEMU shows it set too | none: it is shown as it reads, not interpreted |
| `NONIDENT` on a result | the output page is not the input page: the map is not an identity map there | the monitor's address arithmetic must not assume identity |
| `CONTROL Tn=FAULT=...` for a type 1 to 6 page, or `CODE=FAULT` / `STACK=FAULT` | memory that is certainly in use reads as unmapped: the method is wrong, or the map the payload reads is not the one EL2 uses | distrust every `MAPPED` of this page; compare with the loads; do not decide U1 from it |
| `LOAD ...=ERR<n>` after the AT said mapped | the translation exists but the access aborted (an unpopulated or protected region, or an external abort) | treat the range as unusable until explained; the AT answer is a translation answer, not a promise that memory answers |
| `LOAD ...=SKIPPED_NOT_MAPPED` | the AT said the page is not mapped, so no load was made | as for a fault in the bank |
| `ID ... PAN=<n>` | `ID_AA64MMFR1_EL1` bits 23:20 (INFERRED field position): 0 would fail the monitor's PAN requirement; 1 to 3 meet it | if 0, the launch gate must change; if not, the value of `MMFR1` replaces the photographed one that failed its CRC check |
| `ID ... VH=<n> HAFDBS=<n>` | whether `FEAT_VHE` (1) and hardware access/dirty updates (1 or 2) exist | the monitor reads them at launch; the page shows what it will find |
| `ID DFR1=... ISAR2=... PFR2=... MDCR_EL2=...` | the first values seen for these registers | compare with what the monitor's launch checks require (unknown U5) |
| `OSLSR_EL1 ... OSLK=1` | the OS lock is set: debug register writes may not take effect until it is cleared (INFERRED) | the monitor's debug programming must clear it first, or the probe must be left out |
| `OSLSR_EL1 ... OSLK=0` | the OS lock is clear | none |
| `MDSCR_EL1 RAW=0X..` | the debug control as it stands | compare with what the monitor's debug probe expects before it writes it |
| `ICC_SRE_EL2 ... SRE=1 ENABLE=1` | the GIC system-register interface is enabled at EL2 and lower levels may use it (bit 3, INFERRED) | none; `SRE=0` means the monitor must set it before it uses `ICC_*` registers |
| the page ends at `NEXT MDSCR_EL1 AFTER 8 S`, `NEXT OSLSR_EL1 ...` or `NEXT ICC_SRE_EL2 ...`, or the board resets seconds after one | that register's read hangs or resets the board: it traps to EL3 and EL3 does not handle it (INFERRED) | photograph the page, power-cycle, and do **not** read that register at EL2 in the monitor without a handler; a second boot without that read is a change of this payload and a decision of its own |
| `<REG> SKIPPED=NO_COUNTER` / `SKIPPED=COUNTER_STUCK` | the eight-second wait could not be made, so the read was not | the counter op is missing or the counter does not run: nothing about the register is learned |
| `MAP_REFUSED <reason>`, `DONE MAP_REFUSED` | the final map the runner passed is not one this payload reads: nothing of it was read | the register groups still stand; the map itself is the finding (return 3) |
| `DONE SCAN_HAS_FAULTS` | at least one probe was not mapped: see the `KEY`, `OUTLIER` and `BANK` lines for where | as for a hole in the bank |
| `SUPPRESSED=<n>` on the last line | the page budget dropped `<n>` lines of the report | read what is there; the `NEXT` lines and the last line are never dropped |
| the page ends before the first `NEXT` line | a hang or a reset in the scan or a guarded load (INFERRED: an `AT` whose table walk reaches memory that does not answer could do it) | photograph the page, power-cycle; the last line says which group to suspect |
<!-- /el2mem-decisions -->

## What QEMU shows

OBSERVED, QEMU 11.1.3 (`virt,virtualization=on`, `-cpu max`, `-smp 1`, TCG, EDK2 AArch64), once per run of
`tools/test-q1n1-sp11-payload-qemu-el2mem.py`: the payload runs at EL2 behind the runner after a real `ExitBootServices`, alone
and in the chain, and returns 0. QEMU has no 30 GiB bank and no EL3, so the page below is the shape of a run, not the unit's. The
addresses of the loads vary from run to run; the test asserts the shape and the cross-checks, not these values.

<!-- el2mem-qemu -->
```
PAYLOAD EL2MEM START CURRENTEL=0X8 FREQ=1000000000
PAYLOAD EL2MEM MAP DESC=38 STRIDE=48 CONV_EXTENTS=10 CONV_MIB=469
PAYLOAD EL2MEM KEY RESULT=WB.IS.NS1 PROBES=252 FIRST=0X40000000 LAST=0X5FFFE000
PAYLOAD EL2MEM SCAN EXTENTS=10 PROBES=252 ALL=MAPPED ATTR=WB SH=IS NS=1
PAYLOAD EL2MEM BANK NOT_CONVENTIONAL_IN_THE_MAP
PAYLOAD EL2MEM CONTROL T1=WB.IS.NS1 T2=WB.IS.NS1 T3=WB.IS.NS1 T4=WB.IS.NS1 T5=WB.IS.NS1 T6=WB.IS.NS1
PAYLOAD EL2MEM CONTROL CODE=WB.IS.NS1 STACK=WB.IS.NS1
PAYLOAD EL2MEM LOAD BANK=SKIPPED_NOT_CONVENTIONAL LOW_FIRST(0X48000000)=0X0 LOW_LAST(0X5C0F6FFC)=0X0
PAYLOAD EL2MEM ID DFR1=0X0 ISAR2=0X1120000000110012 MMFR1=0X110112010312122 PAN=3 VH=1 HAFDBS=2
PAYLOAD EL2MEM ID PFR2=0X100000111 AIDR=0X0 REVIDR=0X0 MDCR_EL2=0X6
PAYLOAD EL2MEM NEXT MDSCR_EL1 AFTER 8 S
PAYLOAD EL2MEM MDSCR_EL1 RAW=0X0
PAYLOAD EL2MEM NEXT OSLSR_EL1 AFTER 8 S
PAYLOAD EL2MEM OSLSR_EL1 RAW=0XA OSLK=1
PAYLOAD EL2MEM NEXT ICC_SRE_EL2 AFTER 8 S
PAYLOAD EL2MEM ICC_SRE_EL2 RAW=0XF SRE=1 ENABLE=1
PAYLOAD EL2MEM DONE SCAN_ALL_MAPPED LOADS_OK=2 OF=2 HAZARD_READS=3
```
<!-- /el2mem-qemu -->

What the test checks beyond the shape: the descriptors the payload read in place are the ones the runner parsed
(`SP11 EBS: map ... entries=<n>`); the counter frequency is the one the runner printed for `CNTFRQ_EL0`; the attribute of every
page is a byte of the `MAIR_EL2` the runner printed (`PAR_EL1.ATTR` is a MAIR byte); `PAN`, `VH`, `HAFDBS`, `OSLK`, `SRE` and
`ENABLE` are the fields of the raw values printed beside them; the runner counted the lines the payload printed and dropped none;
no file on the stick changed.

**What QEMU cannot show**, UNKNOWN on the unit: whether the bank is mapped, and with what; what the unit's firmware map looks like at
EL2; whether `MDSCR_EL1`, `OSLSR_EL1` or `ICC_SRE_EL2` trap to EL3 (QEMU has no EL3 here); the values of the unit's ID registers; what
`NS` means on the unit. Under QEMU `FREQ` is 1 GHz, the upper end of what the payload accepts.

## The proposed staging plan (not run)

One boot, three files, the runner's own limits (at most 5 files, each at most 256 MiB; [the manifest](SP11-PAYLOAD.md#the-manifest)).
The plan is the coordinator's; nothing here has been run on hardware and no file has been written to a stick.

<!-- el2mem-staging -->
```sh
dd if=/dev/urandom of=BIG.DAT bs=1048576 count=144
python3 tools/sp11_payload_manifest.py --out-dir build/stick build/uefi/payloads/el2mem.bin build/uefi/payloads/hashbig.bin BIG.DAT
# copy build/stick/SP11 to the stick with SP11\Q1N1-PAYLOAD.EFI and SP11\SLBOUNCE-DEVHE-MARK.EFI, then from the UEFI Shell:
load SP11\SLBOUNCE-DEVHE-MARK.EFI
SP11\Q1N1-PAYLOAD.EFI --el2
```
<!-- /el2mem-staging -->

`BIG.DAT` is 144 MiB, 150,994,944 bytes, of random bytes (the rate of SHA-256 does not depend on the content; random bytes keep any
shortcut out). The manifest lists `EL2MEM.BIN`, `HASHBIG.BIN` and `BIG.DAT`, the first two payloads called in that order and the
third data that `hashbig` finds through the preload table. The page: `(3 + 1) + 3 x 2 + 26 + 12 = 48` lines at the most (see below).

**Order.** The runner's order rule is that what may stall the board goes last, and `el2mem`'s three hazard reads may. The plan keeps
`el2mem` first as asked; a reset at one of its reads then loses `hashbig`'s page, and a run of the manifest tool with the two
payloads swapped puts the read-only payload first. That is the operator's call and changes nothing else.

**Proposed stop rule.** One boot, and no retry of the step that ended it. If the page ends at a `NEXT <REG> AFTER 8 S` line, or the
board resets within seconds of one: photograph, power-cycle, and do not run `el2mem` again as it is. If q1n1's own fault page appears
(an exception at EL2 from a read-only payload): stop and read `ELR` against the payload's base on the `LOADED` line. `ERR<n>`,
`FAULT`, `SKIPPED` and `SCAN_HAS_FAULTS` are results, not stops. The runner reads the whole of `BIG.DAT` from the stick and hashes it
before the bounce; how long that takes is UNKNOWN, and a refusal before the bounce leaves the stick as it was.

OBSERVED (a restart control of 2026-11-16, reported to this work; no page of it is in this tree): the runner flow with a read-only PSCI
payload alive at `UPTIME` 224 S and 268 S in two boots. A long-running read-only payload (this one waits 24 s on the counter) is
not expected to restart the board by itself.

## Tests

Hardware: NOT RUN. Every command writes only under `build/`.

| Command | What it runs |
| --- | --- |
| `python3 tools/test-q1n1-sp11-payload-el2mem.py` | the host program `tools/test-q1n1-sp11-payload-el2mem.c` (ten suites over a modelled machine: AT as a list of ranges with attributes and faults, a scripted register file, a clock, a guarded load, a memory map pressed against `PROT_NONE` pages, random worlds) under ASan and UBSan, and again with a 14-line page; 48 seeded-bug mutants in `el2mem.c` and the shared headers, each of which it must reject; the allow-list on the binary with 23 seeded bad binaries; the five older payloads byte for byte what the hardware runs pinned; the source audits |
| `python3 tools/test-q1n1-sp11-payload-memcheck.py` | the policy engine: the frozen base-commit engine against the new one on 120 binaries under the five older policies; the memory checker on 57 synthetic disassembly cases, with 31 seeded bugs in the checker; the AT encoding space |
| `python3 tools/test-q1n1-sp11-payload-qemu-el2mem.py` | the QEMU boots above, and `hashbig`'s |
| `python3 tools/test-q1n1-sp11-payload-mmu-doc.py` | this document and the `hashbig` one against the sources, the host models, the binaries and the chain arithmetic, with seeded mistakes in each document |
| `python3 tools/test-q1n1-sp11-payload-build.py` | `make payloads` builds `el2mem.bin` and `hashbig.bin`, the ELF check, the allow-list of every payload, two builds byte-identical |
| `python3 tools/test-q1n1-sp11-payload-el2mem.py facts` | the size, digest and instruction inventory of the built binary |

## Planning a chain's page

The formula is the one of [the runner's planning table](SP11-PAYLOAD.md#the-chain-several-payloads-in-one-boot): `LOADED` for each
file and `READY` (files + 1), `VERIFY`, `CALL` and `DONE` for each payload (3), and the payload's own most lines, here its budget of
26 (the host tests reach it and never pass it).

<!-- el2mem-chain-budget -->
| Chain | Lines | Fits the unit's 89 rows | Fits the 60 the layout asks for |
| --- | --- | --- | --- |
| `el2mem` alone | (1 + 1) + 3 + 26 = 31 | yes | yes |
| `el2mem`, `hashbig` and `BIG.DAT`: the staging plan | (3 + 1) + 3 x 2 + 26 + 12 = 48 | yes | yes |
| `psci`, `el2mem`, `hashbig` and `BIG.DAT` | (4 + 1) + 3 x 3 + 30 + 26 + 12 = 82 | yes | no |
<!-- /el2mem-chain-budget -->

## Residual risks

* **Whether the three reads trap to EL3 is UNKNOWN**; they are last and announced for that. A reset leaves the lines before it.
* **`AT` is a translation answer.** A mapped page may still abort when read (an unpopulated region): that is what the four guarded
  loads are for, and they are only four words.
* **The method's resolution is 2 MiB.** A hole narrower than that, not at an edge of an extent, is missed; a bank mapped with
  4 KiB pages and holes would show only if a probe lands on one.
* **What `NS` means** for a Non-secure EL2 translation is UNKNOWN; it is shown, never used.
* **The field positions of `ID_AA64MMFR1_EL1`** (`PAN`, `VH`, `HAFDBS`) and of `OSLSR_EL1`, `ICC_SRE_EL2` are INFERRED from the
  architecture and were not re-read; the raw value is always printed beside the decoded field.
* **QEMU shows the shape only** (no bank, no EL3): the unit's first run is the first observation of any value.
* **The memory checker is conservative and assumes** what is stated above; a binary it passes was checked at the level of the base
  register of each access, with the offsets bounded by the host tests.

## Status

EXPERIMENTAL. Hardware NOT RUN. OBSERVED on the unit by other payloads: the EL2 state values quoted at the top. OBSERVED under QEMU
only: the page above and the behaviours listed under it. UNKNOWN: everything else this payload would print on the unit.
