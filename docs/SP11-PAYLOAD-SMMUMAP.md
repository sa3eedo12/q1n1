<!-- SPDX-License-Identifier: MIT -->
# The runner's mapping step: one level-3 descriptor for the PCIe SMMU's register page

`platform/uefi/sp11-smmumap.c`, `sp11-smmumap.h` and `sp11-smmumap-el2.c` are an opt-in step of the stick payload runner described in
[SP11-PAYLOAD.md](SP11-PAYLOAD.md): the manifest, the stick files, [the chain](SP11-PAYLOAD.md#the-chain-several-payloads-in-one-boot), ABI v1 and the
[line catalogue](SP11-PAYLOAD.md#line-catalogue) are defined there and not repeated. The step runs once at EL2, after the runner has replayed its notes, verified the
first payload where it now is (`PAYLOAD VERIFY=OK`) and seen every other payload of the chain verify too, and before the first payload is called ([where it
runs](#where-it-runs)). It writes **one 64-bit descriptor into one level-3 table of the firmware's EL2 stage-1 tables** so that the 4 KiB page
`0x15400000`, register page 0 of the PCIe SMMUv3, is mapped as Device memory. The payload that wants the page, [`smmuprobe`](SP11-PAYLOAD-SMMUPROBE.md), is **not
changed**: it asks the MMU about the page with its own `AT S1E2R`, as it did when the answer was a fault, and reads the SMMU only if the answer is a Device page.
Evidence labels as there: VERIFIED, OBSERVED, INFERRED, EXPERIMENTAL, UNIMPLEMENTED, UNKNOWN. **EXPERIMENTAL; hardware NOT RUN: the mapping has never run on the
unit, and this document authorises no run.**

The gate is `Q1N1_SP11_SMMUMAP` (default 0), built with `SMMUMAP=1` on top of `PAYLOAD=1`. With it at 0 the three new files compile to nothing and the runner is the
pinned runner byte for byte ([Building it](#building-it)).

## Why

The first storage session on the unit (boot 22, nvmesnap then smmuprobe) read the NVMe at EL2 and asked the MMU about the PCIe SMMU's page: `AT S1E2R` answered a
level-3 translation fault, `MAP SMMU=FAULT=0X7:TRANS_L3`, and smmuprobe printed `VERDICT STREAM=0X60100 MODE=UNKNOWN WHY=SMMU_PAGE_UNMAPPED` and `DONE SMMU_GROUP_SKIPPED`
(OBSERVED once, one unit). A level-3 translation fault means the levels above are valid tables and the level-3 slot is invalid: the firmware's tables have a table
for the range and **no entry for the page**. Nothing of the SMMU was accessed, so what the SMMU does with the SSD's stream (bypass, stage 2, translate, abort) is
UNKNOWN, and every later storage step that moves data by DMA is gated on that answer. The cheapest read-only way to ask is to map the page and read it, with the
reads guarded and announced, which needs one store into a page table. A payload makes no store outside its own stack, no `TLBI` and no `MSR` (its binary is checked against
that), and the monitor owns no EL2 stage 1 yet, so the one place that can make this store is the runner. (The X2 test image's read of the same page faulted at EL2 in two
boots, [SP11-PAYLOAD-SMMUPROBE.md](SP11-PAYLOAD-SMMUPROBE.md); INFERRED to be the same gap.)

## Where it runs

The runner's loop verifies each payload where it now is just before calling it (`PAYLOAD VERIFY=OK`), because an earlier payload is code at EL2 and may have damaged a later one.
The step is made **once, inside that loop, right after the first payload's own check passed and before its `PAYLOAD CALL`**, and only when the other payloads verify too: the
runner first checks every other payload of the chain in place, without a line, and if one does not verify it gives the refusal the loop would give that payload later
(`PAYLOAD REFUSED=HASH_AT_EL2 INDEX=<n> WANT= HAVE=`, then `PAYLOAD CHAIN STOPPED INDEX=<n> REASON=HASH_AT_EL2`), calls **no** payload (not even the first, which the loop
would have called) and writes nothing. So no descriptor is written for a chain that is already known not to run, and a payload that is already damaged when the step is about
to be made can no longer be the reason for a `HASH_AT_EL2` stop after `DONE MAPPED=1`. What this does not cover: a payload that damages a later one while it runs; the loop's own
check before the later payload then stops the chain after `MAPPED=1`. A refusal of the step writes no device and leaves no descriptor in place, except that `CHECK_FAILED` wrote one
and undid it (`STORES=2`) and `ROLLBACK_FAILED` is `UNSAFE`; the chain goes on, and only `UNSAFE` stops it
(`PAYLOAD CHAIN STOPPED INDEX=<n> REASON=SMMUMAP`, `<n>` the first payload's index in the manifest, and no payload is called). With the gate at 0 none of this exists: the loop is the base
commit's.

## What it does, in order

Every line below is one of the [lines](#what-it-prints); every refusal writes no device and leaves no descriptor in place, except that `CHECK_FAILED` wrote one and undid it (`STORES=2`) and
`ROLLBACK_FAILED` is `UNSAFE`; the chain runs after every refusal but `ROLLBACK_FAILED`, which stops it. The order is the
order of the questions, cheapest and most reversible first:

1. **`START`**: the page asked for and its template are looked up in a one-row allow-list (`q1n1_smmumap_specs`); any other pair is `REFUSED=SPEC`. The five
   translation registers are read (`MRS`) and printed (`START`, `REGS`) before anything is asked of the tables.
2. **The root and the regime.** `TTBR0_EL2` must be exactly `0xA7F2E000`, the root every boot that printed it showed (`REFUSED=TTBR0_UNPINNED`); `SCTLR_EL2.M`
   set and `EE` clear, `HCR_EL2.E2H` clear, a 4 KiB granule and `T0SZ` from 16 to 39 (`REFUSED=REGIME`). `WXN` is printed in `SCTLR` and is not a refusal: step 7 asks the
   hardware.
3. **The walk to the page** (`WALK`). A software walk of the 4 KiB-granule tables reads one descriptor per level with the runner's guarded 64-bit load. It must
   end at a level-3 slot that is invalid and zero. The refusals: a read that aborts (`WALK_FAULT`, `LEVEL=` the level of the read that aborted), a table address beyond the
   physical address size of `TCR_EL2.PS` (`TABLE_ADDRESS`), a valid page already there (`ENTRY_VALID`: reported, never overwritten), a hole, a block, a reserved form or a page
   beyond the VA range above the slot (`NO_L3_TABLE`), a table descriptor on the path with `NSTable`, `APTable`, `UXNTable` or `PXNTable` set (`UPPER_FLAGS`), an invalid but
   non-zero entry (`ENTRY_NOT_ZERO`), a slot that is not the page's own index in its table (`DESCRIPTOR`), a level-3 table that is also a table of a higher level of this
   path (`TABLE_SHARED`), and a table page that is not RAM (`TABLE_NOT_RAM`, [step 4](#what-it-does-in-order): refused before the load from it).
4. **Every table the step loads from is RAM, proven before the load.** Every load of a table word (the root, each table of the walk to the page and of the walk to the template, the level-3
   table **before its slot**, each word of the scan, the slot once more before the store) goes through one function that first asks the memory map the runner kept about the word's 4 KiB
   page: it must lie inside one descriptor of an EFI type that the payloads call RAM (1 to 7 and 9: loader, boot services, runtime services and conventional memory, ACPI reclaim),
   with no overlapping descriptor of another type. A page that does not is `REFUSED=TABLE_NOT_RAM TABLE= TYPE= LEVEL=` with **nothing loaded from it**: `LEVEL=` the level of the table,
   `TYPE=` the EFI type of the descriptor that decides (`0XFF` when none holds the page; `0XFE` when the map cannot be read: no map, a stride below 40 or not a multiple of 8, a size that
   is not whole descriptors, more than 1,024 of them), and, for a real descriptor, ` ATTR=` its attribute word (UEFI `EFI_MEMORY_*` bits: `WB` 0x8 for cacheable DRAM, `UC` 0x1 with `RUNTIME`,
   bit 63, for a device window: reserved DRAM and reserved MMIO differ there; INFERRED reading), printed whole or not at all so that the line stays within 100 columns. The decisions are those
   of the payloads' `map_type_of` (`nvmesnap`, `smmuprobe`) and of their map check on the descriptors; the two rules of that check about the buffer itself (8-byte alignment, inside 2^48)
   are not repeated: the descriptors are read byte by byte and the buffer is the runner's own allocation (INFERRED to be in the physical space). So **no device is read or written by the
   step's own loads and stores, by construction**: `read64` has one call site in the whole step, in that function after the proof, and the descriptor and its put-back go to the slot of
   a page that was proven RAM when it was read and again just before the store. The scope is the step's own loads and stores: the `AT`s ask the hardware, whose walks read tables the step
   does not, and the payloads that follow read what they read. What pins it: the host model judges every load of every world, the fuzz included, against its own reading of
   the map (`stray_reads`, none allowed), and the source audit pins the one call and its four callers. That the map tells the truth about the unit's RAM is INFERRED (it is what the firmware
   reported at the exit from boot services); which type the unit's table pages have is UNKNOWN until a run prints it, and **a refusal here is plausible and benign** (`TYPE=0X0`, reserved memory,
   which the firmware may keep its tables in): it is an answer, with the table, its level and the attribute word, and no experiment was made.
5. **The hardware agrees with the walk.** `AT S1E2R` of the page must give a level-3 translation fault of stage 1: `FST 0x07` with `PAR_EL1` bit 8 (`PTW`) and bit 9 (`S`) both
   clear, either set being a stage-2 fault, which this regime cannot have (`PTW` is bit 8 and `S` bit 9 of `PAR_EL1` when `F` is 1: Linux `asm/sysreg.h`, `SYS_PAR_EL1_PTW` and
   `SYS_PAR_EL1_S`). The same answer boot 22 saw. Anything else is `AT_DISAGREES`.
6. **The template** (`TEMPLATE`). The attributes come from an existing entry that the runner's payloads already read as Device memory: the page of the root port's
   configuration space, the ECAM page `0x70000000` (a 2 MiB block or a page: all three levels are handled). Its leaf must be valid (`TEMPLATE_UNMAPPED`), its
   `AttrIndx` must name a MAIR byte of `0x00` (Device-nGnRnE) or `0x04` (Device-nGnRE), never a gathering or reordering form (`TEMPLATE_NOT_DEVICE`), and its access flag must be
   set, its `AP[2]` clear (writable at EL2) and its execute-never bit set (`TEMPLATE_NOT_USABLE`); the template's own `AT S1E2R` must give the page and the MAIR byte the
   walk gave (`AT_DISAGREES`). The template's walk must not use the level-3 table that is about to be written (`TABLE_SHARED`).
7. **The table page takes a store.** `AT S1E2W` of the level-3 table's own page must succeed, give that same page and ordinary (not Device) memory
   (`TABLE_NOT_WRITABLE`). Nothing is assumed: not the tables' attributes, not `WXN`, not that the tables are where a model of them would put them.
8. **What else is in the table, and who points at it** (`TABLE`). With guarded loads of RAM (each through the same proof, so none touches a page the map does not call RAM), the other 511 slots of
   the level-3 table, and every entry of the level-0, level-1 and level-2 tables of the path (32 entries for the start table of a 44-bit VA, 512 for the others), at most 2,047 loads
   (511 + 3 x 512; 1,567 on the unit's regime: 511 + 32 + 512 + 512), no write. **No path table is skipped**: each was proven RAM by the walk and is proven again by the scan, so a table that is
   not RAM at that moment is `TABLE_NOT_RAM` with its level, never a silent skip; a `-` in `REFS` means only that this regime's walk starts below that level, so the path has no table there. The line says how many of the 511 are valid (`VALID`, bit 0) and how many table descriptors point at the level-3 table in each table of the path (`REFS=<l0>/<l1>/<l2>`; the page's own level-2 entry is the one in `0/0/1`). A pointer from the root or the level-1 table is refused (`TABLE_SHARED`): the page would be
   read as a table of that level, and the descriptor written here as a table descriptor of the SMMU's page. Further pointers from the level-2 table are only printed. An abort is `SCAN_FAULT`.
9. **The descriptor** (`STORE`): the page's address, type `0b11`, the template's attribute bits `[11:2]` and `[54:53]` and nothing else (not the contiguous hint, not the
   dirty-bit modifier, not the software bits, not the template's address), checked once more to be one 4 KiB page descriptor of exactly that page
   (`DESCRIPTOR`).
10. **`NEXT STORE AFTER 8 S`** and the wait: the line is drawn, the counter runs for eight seconds, then the store. A counter that is missing, stands still, goes
    back or does not finish in 2^32 - 1 reads is `NO_COUNTER`, `COUNTER_UNUSABLE` or `SPIN_BOUND` and nothing is written.
11. **The slot is read once more, then the store.** The slot was read as zero eight seconds and a few thousand reads ago; **it is read once more just before the store**, with the same guarded load.
    An abort is `WALK_FAULT LEVEL=0X3`, a value that is no longer zero is `ENTRY_NOT_ZERO DESC=` (another agent wrote it during the wait; it is not overwritten), and nothing is
    written. Then one guarded 64-bit store (`ldr` then `str` through the recoverable-fault copy, so never in halves) of the descriptor into the slot. An abort is `STORE_FAULT`:
    nothing was written.
12. **The publication** ([below](#the-publication)): `DC CVAC` of the slot, `DSB ISH`, `TLBI VALE2IS` of the page, `DSB ISH`, `ISB`.
13. **The check** (`CHECK`): `AT S1E2R` and `AT S1E2W` of the page must both give that page, with the memory type, shareability and NS of the template's own `AT`. If
    not, **the zero is put back** (a second store, published the same way, and the page must fault again): `REFUSED=CHECK_FAILED UNDONE=1`. If it cannot be put back or still
    translates, the status is `UNSAFE`: `REFUSED=ROLLBACK_FAILED`, the chain stops (`PAYLOAD CHAIN STOPPED INDEX=<n> REASON=SMMUMAP`) and no payload is called.
14. **`DONE MAPPED=1 STORES=1`**, and smmuprobe runs. After the last payload of the chain, one poll for a pending SError prints its [line](#the-line-after-the-chain).

The only write is that one descriptor in firmware RAM (and its put-back). **Nothing is written to any device**, no register of the SMMU, no doorbell, no
`SMC`: a reset takes the descriptor with it, because the firmware builds its tables again.

## The page, the template, the root

| Constant | Value | Where it comes from | Label |
| --- | --- | --- | --- |
| `Q1N1_SMMUMAP_PAGE_PA` | `0x15400000` | Linux `hamoa.dtsi`, `pcie_smmu: iommu@15400000`, `reg = <0 0x15400000 0 0x80000>`, status "reserved", "Controlled by Gunyah." (the pinned copy, lines 8544 to 8556, checked by `tools/test-q1n1-sp11-payload-nvmesnap-refs.py`, a SKIP without the copy); the unit's IORT names the same base ([SP11-PAYLOAD-SMMUPROBE.md](SP11-PAYLOAD-SMMUPROBE.md)) | VERIFIED as the platform address; that EL2's stage 1 has no entry for it: OBSERVED once (boot 22) |
| `Q1N1_SMMUMAP_TEMPLATE_PA` | `0x70000000` | segment 6's ECAM base from the unit's MCFG (OBSERVED on two boots); `AT S1E2R` says Device, outer shareable, NS there: `MAP RP=DEVICE.OS.NS1` (boot 22) | OBSERVED |
| `Q1N1_SMMUMAP_TTBR0_EL2` | `0xA7F2E000` | every boot that printed it (boots 4, 5, 7 and the M2 survey of Snapintosh `docs/SP11-EL2-ENTRY.md`) | OBSERVED |
| `Q1N1_SMMUMAP_WAIT_S` | 8 | the payloads' idiom (`el2mem`) | design |

The registers of the regime, as printed on those boots (OBSERVED): `HCR_EL2 0x88000010` (`E2H` 0, `TGE` 1), `SCTLR_EL2 0x0000100030C5183D` (`M`, `C`, `I` set, `WXN` and `EE`
clear), `TCR_EL2 0x80843514` (`T0SZ` 20, a 44-bit VA starting at level 0 with 32 entries, 4 KiB granule, inner shareable write-back, `PS` 44 bits), `MAIR_EL2
0xFFBB4400`. **`MAIR_EL2` has no Device-nGnRE entry** (OBSERVED in the printed value: attribute 0 is `0x00`, Device-nGnRnE; the others are `0x44`, `0xBB`, `0xFF`): the mapping the step
builds is therefore Device-nGnRnE, which is stricter than the nGnRE that was first asked for, and it is whatever the template's `AttrIndx` says (INFERRED for the unit's
ECAM entry until a run prints it), so the page is mapped exactly as the ECAM page that the payloads already read.

## The descriptor

A level-3 descriptor of the EL2 stage-1 regime (`HCR_EL2.E2H` 0, one VA range): bits 1:0 `0b11`, `AttrIndx` `[4:2]`, `NS` 5, `AP` `[7:6]`, `SH` `[9:8]`, `AF` 10, `nG` 11,
output address `[47:12]`, the execute-never bit 54 (`UXN`, the one execute-never bit of this regime) and 53. The step takes bits `[11:2]` and `[54:53]` of the template and
sets the type and the page's address. Why copy: a descriptor that is the same as the one that already works for a Device page cannot disagree with the firmware's
regime in a bit that this document has no way to check. Why the checks on the template: a copy of a bad template is a bad descriptor (an access flag clear faults on the
first read, a read-only page cannot be written, an executable Device page lets the CPU fetch from registers).

For the host model's good world the template block `0x0040000070000641` gives `0x0040000015400643`. `q1n1_smmumap_descriptor` builds it and
`q1n1_smmumap_descriptor_ok` accepts only a page descriptor of exactly the page, with no bit but the address, the type and the attribute bits `[11:2]` and `[54:53]`.

## The publication

A descriptor written into a table is seen by the table walker only after the store is made visible to it and the TLB holds no stale answer. The step does, in order:

| Step | Instruction | Why |
| --- | --- | --- |
| 1 | `DC CVAC` of the slot's line | the walk is cacheable and inner shareable on this unit (`TCR_EL2 0x80843514`), so a coherent walker needs nothing; the clean is for a walker that does not snoop, which is "never assume" |
| 2 | `DSB ISH` | the clean and the store are complete before the invalidation |
| 3 | `TLBI VALE2IS`, operand `VA[55:12]` in bits 43:0 | **by VA, last level, EL2, inner shareable**: only a level-3 entry changed, so the entries of the upper levels, which are cached as walk caches, did not; the regime is stage 1 of EL2 with no ASID, so `VALE2` is the form that names one VA there; inner shareable because the tables are shared by every CPU that runs EL2 on them. An entry that was invalid is not cached, so the invalidation is belt and braces for the page itself, and it is what makes the next two steps sound |
| 4 | `DSB ISH` | the invalidation is complete |
| 5 | `ISB` | the next instruction, the `AT`, sees the new translation regime state |

`ALLE2IS` would also be correct and costs every other translation of the runner and of the page it draws; no correctness argument asks for it. The host model sees a store
only after exactly this sequence in this order and answers with the previous descriptor otherwise, so a step that leaves out or reorders one of them fails its own
check: in the model that is `UNSAFE`, because the put-back cannot be proven either.

## The line after the chain

smmuprobe's first read of the SMMU's page is where a hang, a synchronous abort or an asynchronous SError can happen. A synchronous abort is taken by the guard and is
smmuprobe's own `FAULT`; **an asynchronous SError stays pending while `DAIF.A` is masked, as it is all through the chain, and nothing shows it**. So when the page was mapped, the runner polls once, after
the last payload has returned, with the proxy's own routine (`q1n1_platform_serror_poll` in `platform/uefi/main.c`: with the RAS extension a deferral by `ESB` into `DISR_EL1`,
otherwise a short window with `DAIF.A` clear in which a pending SError is taken by q1n1's handler, which records `ESR_EL2`), and prints one line:
`PAYLOAD SMMUMAP SERROR=NONE PENDING=0 BEFORE=0`, or `PAYLOAD SMMUMAP SERROR=FOUND SYNDROME=0X<hex> PENDING=<0|1> BEFORE=<0|1>`.

* `FOUND`: an asynchronous SError was pending when the poll ran: **raised by a payload of the chain (nvmesnap or smmuprobe) or later**, not necessarily by smmuprobe's read of the SMMU's
  page; `BEFORE=1` separates only the step's own past (one was already pending when the step finished, before any payload ran). **A record must not conclude from `FOUND` alone** what raised it.
  `SYNDROME` is `DISR_EL1` (bit 31 `A` set) from the RAS path, or `ESR_EL2` of the SError taken in the window.
* `NONE`: none was pending when the poll ran. **It does not mean the read was error-free**: EL3 may take an SError itself (`SCR_EL3.EA` is UNKNOWN on this unit), and `DISR_EL1` and `ISR_EL1`
  then read zero here.
* **The poll consumes what it finds**: with the RAS extension `ESB` defers a pending SError into `DISR_EL1`, which the poll reads and clears; otherwise, or if one is still pending, `DAIF.A` is
  unmasked for two instructions, the exception is taken by q1n1's handler (`q1n1_exception`), which records `ESR_EL2` and swallows it, and `A` is masked again. An SError is reported once, here,
  and nothing after the poll sees it.
* `PENDING=1`: one is still pending after the poll (the poll could not take it).
* The runner catches or clears nothing else: the poll is made only after the chain and only for a page that was mapped, so a run that refused, stopped or ended in `UNSAFE` prints no
  such line. What the operator sees is the line after the last payload's `PAYLOAD DONE`, within seconds, and the uptime ticking; a hang before it leaves the last line of smmuprobe as the last line
  on the page, and a hang in the poll itself leaves no `SERROR` line and a stopped uptime ([the hang rule](#hazards)).

Whether the poll works in the runner's flow on the unit is UNKNOWN: it is the proxy's routine, which has not run in this flow (INFERRED to work, the same EL2 vectors being installed
for the guarded loads); the host model only proves what the step does with its answers. A `PENDING=1`, or a hang in the poll itself, is a result to report as it is.

## What it prints

The step prints at most ten lines in a run (`LINES_MAX=10` in the host program): nine on the way to a mapped page, and the `SERROR` line after the chain; the longest refusal is the
put-back's ten. Every value is hexadecimal with the page's `0X`, capitals only.

<!-- smmumap-lines -->
| Line | Fields | When |
| --- | --- | --- |
| `PAYLOAD SMMUMAP START` | name, `PAGE`, `TEMPLATE`, `TTBR0` | always first |
| `PAYLOAD SMMUMAP REGS` | `TCR`, `MAIR`, `SCTLR`, `HCR` | after the allow-list |
| `PAYLOAD SMMUMAP WALK` | `L0`, `L1`, `L2` (the descriptors read), `SLOT` (where the level-3 slot is), `OLD` (what it held) | after the regime; zeros for levels not read |
| `PAYLOAD SMMUMAP TEMPLATE` | `LEVEL`, `DESC`, `ATTR` (its MAIR byte), `PAR` (its own `AT`) | after the template's walk |
| `PAYLOAD SMMUMAP TABLE` | `VALID` (valid slots among the other 511 of the level-3 table), `REFS` (table descriptors that point at it in the level-0, 1 and 2 tables of the path; `-` for a level the regime's walk does not start at, which has no table) | after the table page's check, before the descriptor is built |
| `PAYLOAD SMMUMAP STORE` | `SLOT`, `DESC`, `TABLEW=OK` (the table page took the `AT` for a write) | before the wait |
| `PAYLOAD SMMUMAP NEXT STORE AFTER 8 S` | | before the wait and the store |
| `PAYLOAD SMMUMAP CHECK` | `PARR`, `PARW`, `ATTR=SAME` or `ATTR=DIFFERENT` | after the publication |
| `PAYLOAD SMMUMAP REFUSED=<NAME>` | up to two numbers that say where; four for `TABLE_NOT_RAM` (`TABLE`, `TYPE`, `LEVEL`, `ATTR`); `ATTR=` is the MAIR byte on `TEMPLATE` and its refusals, the EFI attribute word on `TABLE_NOT_RAM` | instead of the next steps; see the table below |
| `PAYLOAD SMMUMAP DONE` | `MAPPED=0` or `1`, `STORES=<n>`, and `UNSAFE` when it is | last of the step |
| `PAYLOAD SMMUMAP SERROR=NONE` or `SERROR=FOUND` | `SYNDROME` (found only), `PENDING`, `BEFORE` | after the last payload of the chain, only when the page was mapped |
<!-- /smmumap-lines -->

### What the host model prints

The page of the good world of `tools/test-q1n1-sp11-payload-smmumap.c`. **The tables are the model's, an invention that has the shape the boot 22 fault says the unit's
has (a level-3 table for the range and no entry for the page); the values are not the unit's**, and a real run will print other table addresses.

<!-- smmumap-page -->
```
PAYLOAD SMMUMAP START PCIE_SMMU0 PAGE=0X15400000 TEMPLATE=0X70000000 TTBR0=0XA7F2E000
PAYLOAD SMMUMAP REGS TCR=0X80843514 MAIR=0XFFBB4400 SCTLR=0X100030C5183D HCR=0X88000010
PAYLOAD SMMUMAP WALK L0=0XA7F2F003 L1=0XA7F30003 L2=0XA7F31003 SLOT=0XA7F31000 OLD=0X0
PAYLOAD SMMUMAP TEMPLATE LEVEL=0X2 DESC=0X40000070000641 ATTR=0X0 PAR=0X70000B00
PAYLOAD SMMUMAP TABLE VALID=2 REFS=0/0/1
PAYLOAD SMMUMAP STORE SLOT=0XA7F31000 DESC=0X40000015400643 TABLEW=OK
PAYLOAD SMMUMAP NEXT STORE AFTER 8 S
PAYLOAD SMMUMAP CHECK PARR=0X15400B00 PARW=0X15400B00 ATTR=SAME
PAYLOAD SMMUMAP DONE MAPPED=1 STORES=1
```
<!-- /smmumap-page -->

Legend: `PAR` is `PAR_EL1` as `AT S1E2R` left it: bits 63:56 the memory type (`0X00` Device-nGnRnE), bits 47:12 the page, bits 9:7 `NS` and `SH` (a Device page is always outer
shareable), bit 11 set, bit 0 clear (a fault sets it, with the fault status in bits 6:1, `PTW` in bit 8 and `S` in bit 9). `TABLE VALID=2 REFS=0/0/1`: the model's level-3 table has two valid slots besides the page's own, and only the page's own level-2 entry points at it.

## Outcomes

Every token the step can print, with what is written and what the runner then does. "Chain" is whether the payloads run.

<!-- smmumap-outcomes -->
| What is on the page | Meaning | Written | Chain |
| --- | --- | --- | --- |
| `REFUSED=SPEC PAGE=` | the pair is not on the allow-list (a caller's bug, not a unit's answer) | nothing | runs |
| `REFUSED=TTBR0_UNPINNED TTBR0= TCR=` | `TTBR0_EL2` is not `0xA7F2E000`: a table this logic was not reviewed against | nothing | runs |
| `REFUSED=REGIME TTBR0= TCR=` | MMU off, big-endian walks, `E2H`, a granule that is not 4 KiB, or `T0SZ` outside 16 to 39 | nothing | runs |
| `REFUSED=WALK_FAULT LEVEL=` | a guarded read of a table word aborted: `LEVEL=` is the level of the read that aborted, in either walk, and `0X3` for the read of the slot just before the store | nothing | runs |
| `REFUSED=TABLE_ADDRESS TABLE=` | a table address beyond the physical address size of `TCR_EL2.PS` | nothing | runs |
| `REFUSED=ENTRY_VALID DESC=` | the page's entry is already valid: not overwritten (this is also what a second call finds) | nothing | runs |
| `REFUSED=NO_L3_TABLE LEVEL= DESC=` | the walk does not end at an invalid level-3 slot: a hole, a block or a reserved form above or at it, or a page beyond the VA range | nothing | runs |
| `REFUSED=UPPER_FLAGS FLAGS=` | a table descriptor of the path has `NSTable`, `APTable`, `UXNTable` or `PXNTable` set | nothing | runs |
| `REFUSED=ENTRY_NOT_ZERO DESC=` | the slot is invalid but not zero: in the walk, or when it was read once more just before the store (another agent wrote it during the wait; it is not overwritten) | nothing | runs |
| `REFUSED=DESCRIPTOR SLOT=` or `DESC=` | the slot is not the page's own index in its table, or the descriptor is not one 4 KiB page descriptor of exactly that page | nothing | runs |
| `REFUSED=TABLE_SHARED TABLE= LEVEL=` | the level-3 table is also the table of a higher level on the path to the page or to the template, or an entry of the root or of the level-1 table points at it (`LEVEL=` that table's level) | nothing | runs |
| `REFUSED=TABLE_NOT_RAM TABLE= TYPE= LEVEL= ATTR=` | a table page that the step was about to load from is not inside one descriptor of the memory map whose EFI type is RAM (1 to 7, 9): the root, a table of either walk, the level-3 table before its slot, a page of the scan, or the slot's page at the re-read; `TABLE=` that page, `LEVEL=` the table's level, `TYPE=` the type of the descriptor that decides (`0XFF` none holds the page, `0XFE` the map cannot be read), `ATTR=` its attribute word (only for a real descriptor, and only when the line stays within 100 columns); `TYPE=0X0` (reserved memory) is the plausible benign one; **no experiment was made** | nothing | runs |
| `REFUSED=AT_DISAGREES PAGE= PAR=` | the page's `AT` is not a level-3 translation fault of stage 1 (`PTW` or `S` of `PAR_EL1` set is one too), or the template's `AT` is not the walk's page and memory type | nothing | runs |
| `REFUSED=TEMPLATE_UNMAPPED LEVEL= DESC=` | the template has no valid leaf | nothing | runs |
| `REFUSED=TEMPLATE_NOT_DEVICE DESC= ATTR=` | its MAIR byte is not `0x00` or `0x04` | nothing | runs |
| `REFUSED=TEMPLATE_NOT_USABLE DESC= ATTR=` | its access flag is clear, it is read-only at EL2, or it can execute | nothing | runs |
| `REFUSED=TABLE_NOT_WRITABLE TABLE= PAR=` | `AT S1E2W` of the level-3 table's page faults, gives another page, or says Device | nothing | runs |
| `REFUSED=SCAN_FAULT AT= LEVEL=` | a guarded read of the scan aborted: `AT=` the address, `LEVEL=0X3` in the level-3 table, else the level of the path's table | nothing | runs |
| `REFUSED=NO_COUNTER`, `REFUSED=COUNTER_UNUSABLE`, `REFUSED=SPIN_BOUND` (after the `NEXT` line) | the eight seconds cannot be made: no counter, a counter that stands still or goes back, or one that moves but did not finish in 2^32 - 1 reads (the two last are different tokens on purpose) | nothing | runs |
| `REFUSED=STORE_FAULT SLOT=` | the guarded store aborted | nothing | runs |
| `REFUSED=CHECK_FAILED UNDONE=1` (after `CHECK`) | the `AT` check after the store failed; the zero was put back and the page faults again | the slot is zero again (`STORES=2`) | runs |
| `REFUSED=ROLLBACK_FAILED SLOT=` and `DONE MAPPED=0 STORES=<n> UNSAFE`, then `PAYLOAD CHAIN STOPPED INDEX=<n> REASON=SMMUMAP` | the put-back store aborted or the page still translates after it: **a descriptor may be in place and unchecked** | possibly the descriptor | **stops: no payload is called** |
| `PAYLOAD VERIFY=OK`, then `PAYLOAD REFUSED=HASH_AT_EL2 INDEX=<n>` and `PAYLOAD CHAIN STOPPED INDEX=<n> REASON=HASH_AT_EL2`, with no `PAYLOAD SMMUMAP` line | another payload of the chain does not verify where it now is: the step is not made | nothing | **stops: no payload is called** |
| `DONE MAPPED=1 STORES=1` | the descriptor is in place and both `AT`s agree | one descriptor | runs |
| `DONE MAPPED=0 STORES=0` after a `REFUSED` | every refusal above ends with it | nothing | runs |
| `SERROR=NONE PENDING=0 BEFORE=0` after the last payload's `PAYLOAD DONE` | the page was mapped; no SError was pending when the poll ran | as it was | the chain has ended |
| `SERROR=FOUND SYNDROME= PENDING= BEFORE=` after the last payload's `PAYLOAD DONE` | the page was mapped and the poll took a pending asynchronous SError (`PENDING=1`: one more is pending): raised by a payload of the chain (nvmesnap or smmuprobe) or later; `BEFORE=1` separates only the step's own past; **`FOUND` alone does not say that smmuprobe's read of the SMMU's page raised it** | as it was | the chain has ended |
| the last line is `NEXT STORE AFTER 8 S` for more than ten minutes | a hang in the store, the publication or one of the three `AT`s (UNKNOWN which; a slow counter can stretch the wait itself to minutes, INFERRED: 2^32 - 1 reads are about 7 minutes at 100 ns a read) | possibly the descriptor | the film shows it |
| after the last `PAYLOAD DONE`, no `SERROR` line and no ticking uptime for two minutes | a hang in the poll (it can hang; UNKNOWN) or in the return of the last payload | possibly the descriptor | the film shows it |
| smmuprobe's `PAYLOAD DONE` is on the page and the uptime ticks, but there is no `SERROR` line | the page was not mapped (a refusal prints no such line), or the panel was full and the count of rows overflowed: the last line, this one, goes first; **not a hang** | as it was | the chain has ended |
| the panel ends at `START`, `REGS`, `WALK`, `TEMPLATE` or `TABLE` | a hang in a register read, a guarded read, an `AT`, or the drawing (UNKNOWN which); the same reads the payloads make, the `MRS` and the `AT` the survey made, so unlikely (INFERRED); a panel that ends at `TEMPLATE` hung in the table page's `AT` or in the scan's guarded reads of RAM (at most 2,047) | nothing | the film shows it |
| a q1n1 fault page, or the unit restarts by itself | an abort the guard did not take (an asynchronous SError is neither caught nor printed while the chain runs; the one poll after it is the `SERROR` line), or a watchdog (INFERRED) | possibly the descriptor, in RAM the reset discards | boot the stick again |
| the lines of smmuprobe follow `DONE MAPPED=1` | the page was mapped; what smmuprobe prints next is its own answer ([SP11-PAYLOAD-SMMUPROBE.md](SP11-PAYLOAD-SMMUPROBE.md#what-each-outcome-means)) | | |
<!-- /smmumap-outcomes -->

**Recovery from every row that is not `DONE`:** nothing was written to any device, so there is nothing to undo on the unit. Hold the power button until the screen is dark
(FORCE OFF), wait, and boot the stick again; the firmware rebuilds its tables and the descriptor is gone.

## Hazards

* **The store itself** writes firmware RAM only, in a page that the memory map calls RAM and that `AT S1E2W` has just said is writable ordinary memory, into a slot that was read as zero
  again just before it, with one 64-bit `str`. An abort is taken by the recoverable-fault guard and is `STORE_FAULT`. The step does not hold a lock; the runner is one CPU, and the
  invalidation is inner shareable. The scan before it reads at most 2,047 words (1,567 on the unit's regime), each proven RAM by the map before its load; it writes nothing.
* **The first read of the page is where a hang or an abort can happen, and it is smmuprobe's, after `DONE MAPPED=1`.** A read of the SMMU's page could stall
  (nothing answers), fault (a firewall, a stage 2 of the monitor, the hypervisor the node's "Controlled by Gunyah" comment names: the pinned device tree marks the node
  "reserved", so that the firmware leaves exactly this page unmapped may be deliberate, INFERRED; the pinned EL2 overlay of the Linux tree, `x1-el2.dtso`, enables the same node for
  Linux at EL2 (VERIFIED in the pinned copy), which makes a plain read plausible, not shown on this unit), or raise an asynchronous SError. The
  guarded load recovers a synchronous abort only; **q1n1 keeps `DAIF.A` masked (`msr daifset, #15` at its entry points, `platform/uefi/entry.S`), so an SError is neither
  caught nor printed** while the chain runs and would look like a hang, a q1n1 fault page or a reset; the one poll after the chain
  ([the `SERROR` line](#the-line-after-the-chain)) is the only look, it consumes what it finds, and it is not reached by a hang. What the operator sees is the last line: smmuprobe's `NEXT SMMU_REGISTERS AFTER 8 S`
  with nothing after it means the read of the page is where it stopped. Which of these is real is UNKNOWN. The precedent: the A1 session's xHC boots 16, 17 and 19 went dark at the first
  run-register store, cause UNKNOWN; a stalled access of the SMMU is a hypothesis for that, not a finding.
* **The mapping is a Device-nGnRnE, execute-never, read/write-at-EL2 page** (the template's attributes). A Device mapping is not cached and does not fill a line around a
  register, and execute-never keeps the CPU from fetching from it; that this is enough to keep the page out of speculation is INFERRED, not checked here.
* **The descriptor stays for the rest of the boot.** Nothing unmaps the page (UNIMPLEMENTED: a put-back exists but is used only after a failed check). Any later EL2 code
  that touches `0x15400000` reaches the SMMU. The chain is not a sandbox: another payload could read it too. A payload that damages a later one while it runs can still be
  followed by a `HASH_AT_EL2` stop after `DONE MAPPED=1` ([where it runs](#where-it-runs)).
* **A table that is shared between levels** (`TABLE_SHARED`) is refused for the two walks' paths and for a pointer from the root or the level-1 table (the scan finds those); further level-2
  pointers are counted and printed (`REFS=`), not refused (UNKNOWN whether the unit has one; it would map the same page at another address, which is not another page).
* **The table the step writes may not be the firmware's original**: if the bounce replaced it by a copy, the descriptor goes into a copy that the walker may or may not use. The pinned
  `TTBR0_EL2` and the hardware `AT` agreeing with the software walk before the store are the guard; whether the table is the original is UNKNOWN.
* **A refusal is an answer about the step, not about the SMMU:** `TTBR0_UNPINNED`, `REGIME`, `TABLE_NOT_RAM` and the other refusals mean no experiment was made, and smmuprobe then
  says the page is unmapped as it did in boot 22.
* **Watchdog and the box.** A hang after the store is a hang with a descriptor in RAM and no device written. The runner's own rule applies: film continuously from the first line of the page
  (the step's block follows the first payload's `PAYLOAD VERIFY=OK`) until two minutes after the last `PAYLOAD DONE`, ten minutes when there is none. **The hang rule after the chain:** after the last
  `PAYLOAD DONE` expect the `SERROR` line and a ticking uptime within seconds; neither for two minutes is a hang (the poll can hang). Before it, the page is a hang after ten minutes with no new line after
  a `NEXT` line (the step's wait is eight seconds; the same box as [the nvmesnap doc](SP11-PAYLOAD-NVMESNAP.md#tests)). Whether a watchdog resets a hung unit, and when, is UNKNOWN (boot 3's
  `T06` hang was followed by a restart, operator report; a watchdog is INFERRED). Use AC power or at least 50 % battery, with one hardware client.

## What this does not establish

* That the level-3 table page is writable and ordinary memory on the unit: asked of the hardware at run time, and refused (`TABLE_NOT_WRITABLE`) if not. UNKNOWN.
* Which EFI type the unit's table pages have in the memory map the runner kept: a table page (the root, a table of either walk, the level-3 table) that is not RAM is a refusal (`TABLE_NOT_RAM`, with the
  table, its level, the type and the attribute word) and an answer too. UNKNOWN until a run prints it. The host model's map is a model: an extent of boot services data of 231 pages at `0xA7F19000`, which a third-party report from another SoC (a Surface Pro 12,
  quoted in Snapintosh `docs/SP11-Q1N1-BOOT-STUDY.md`) names and which contains the root `0xA7F2E000` this unit printed; the unit's own extent is not known to this document.
* That the memory map the runner kept describes the unit's RAM truthfully: INFERRED (the firmware's own report at the exit from boot services).
* That the table at `TTBR0_EL2` is the one the firmware's walker keeps using, or that the mapping survives a later EL2 transition (the monitor's takeover re-creates its own
  tables). UNKNOWN.
* What smmuprobe finds once the page is mapped, and whether reading it is safe. UNKNOWN: it is the experiment.
* Whether the one poll for an SError works in the runner's flow on the unit: UNKNOWN (see [the line after the chain](#the-line-after-the-chain)).
* That `TLBI VALE2IS` plus the barriers are enough on this core: architecturally the sequence is the recommended one (INFERRED from the Arm ARM, not checked on the unit);
  the host model enforces the order, not the micro-architecture.
* That a copied attribute is accepted for an SMMU page: the template is the ECAM page of the root port, an interconnect window; the SMMU's page may sit behind an
  access control that the ECAM does not. UNKNOWN. That the copied bits that this regime does not define (`nG`, `NS`, bit 53 with `E2H` clear) do no harm is INFERRED: they are a
  copy of a descriptor the walker already uses.
* What the other 511 slots of the level-3 table hold and whether other entries point at it: the `TABLE` line answers on the run; until then UNKNOWN.

## What the record of a run must say

Quotable; each point is true of this step and is pinned by `tools/test-q1n1-sp11-payload-smmumap-doc.py`.

1. **Every refusal means no experiment was made** (no device was written and no descriptor is left in place, except that `CHECK_FAILED` wrote one and undid it, `STORES=2`, and `ROLLBACK_FAILED`
   is `UNSAFE`, which stops the chain; otherwise smmuprobe answers as in boot 22, `SMMU_PAGE_UNMAPPED`). The outcomes this version adds are answers, to be reported as printed and
   none an error of the tools: `TABLE_NOT_RAM` (`TYPE=0X0`, reserved memory, is the plausible benign one: the firmware may keep its tables there; `LEVEL=` and `ATTR=` say which table and what kind of
   memory), `SCAN_FAULT` and `TABLE_SHARED`. When the `TABLE` line is printed it is expected to read `REFS=0/0/1` on the unit's regime (the page's own level-2 entry only: INFERRED from the shape the boot 22
   fault says the tables have, UNKNOWN until printed); another count is a finding for the record, and a pointer from the root or the level-1 table is refused.
2. **`SERROR=FOUND` and `SERROR=NONE`**: as [above](#the-line-after-the-chain): `FOUND` is not smmuprobe's read by itself, `NONE` is not an error-free read, and the poll consumes what it finds.
3. **The budget.** The chain of this record is expected near 68 lines (the most any panel has shown is 58, boot 4, plus the step's ten at most: INFERRED, not measured for this chain; the 89 rows of the
   planning table are every part at its maximum). A line is at most 100 characters and the region is laid out for 101 columns (`NEED_COLS`, or below the page at column 0), so only the count can overflow,
   and then the last line, the `SERROR` line, goes first. **No `SERROR` line with smmuprobe's `DONE` on the page and the uptime ticking is an overflow, or a page that was not mapped, not a hang.**
4. **Where the block is.** The step's block (`START` to `DONE`) follows the first payload's `PAYLOAD VERIFY=OK` and precedes its `PAYLOAD CALL`: film from the first line of the page.
5. **The staged image's stamp.** The staged runner is built from the committed tree with its own stamp, so its sha256 is not the gate-on row's and the record names it; the build of the committed tree with the pinned
   stamp must equal the gate-on row, which is what shows that the staged image has this code.
6. **What identifies what runs** (N6). Point 1 above carries the `CHECK_FAILED` and `ROLLBACK_FAILED` exception, and the record names the staged image's SHA-256 and the stamp of point 5 as the identity of
   what runs: the test suite's digest of the gated glue is a review tripwire, not an identity.
7. **A `TABLE_NOT_RAM` refusal is a likely first outcome** (N7): the unit's table-page types are UNKNOWN and the root and the template's tables must be RAM too, so one boot may end with no SMMU datum.
   The `REFUSED` line with `TABLE`, `TYPE`, `LEVEL` and `ATTR` **is** that boot's datum; relaxing the RAM rule is a new review, not an edit.

## Removal, and how it generalises without a second implementation

* **Removing it** is deleting the `SMMUMAP` block of `platform/uefi/Makefile`, the `#if Q1N1_SP11_SMMUMAP` hunks (`sp11-payload.h`, `sp11-payload-run.c`, `main.c`),
  `sp11-smmumap*.{c,h}` and the tests. Nothing else refers to them, and the runner without the gate is unchanged by construction.
* **A second page** (the PCIe SMMU's other pages, or the Wi-Fi endpoint's if it needs a mapping the SMMU's stream table or its registers decide) is **one row** of
  `q1n1_smmumap_specs`: a name, the page, the template page, plus its row of the [tables](#the-page-the-template-the-root) and host worlds for its path. The logic
  (`q1n1_smmumap_page`) takes the row; nothing in it names the SMMU, and the RAM check, the scan and the `SERROR` line need no row. The Wi-Fi and the SSD's stream both go through the same PCIe SMMU (INFERRED from the platform's device
  tree), so a Wi-Fi consumer of this page needs no row; one that needs another page needs one.
* **The monitor** that will own an EL2 stage 1 needs the same service on its own tables: `sp11-smmumap.c` is pure (every effect goes through `q1n1_smmumap_env`), so the
  monitor builds the same file with its own environment (its guarded loads and stores, its `AT` and its barriers) and does not carry a second walker or a second
  descriptor rule. `main.c`'s glue and `sp11-smmumap-el2.c` are the runner's side only.
* **Why a walker of its own and not `q1n1_mmu_attr`** (`platform/uefi/live-battery.c`): that function returns only the attribute byte, and it is part of the pinned runner,
  so changing it would change the pinned bytes. The two share no code today. **Retirement condition:** when the pinned runner is replaced, `q1n1_mmu_attr` becomes a caller of
  this walker (or of a descriptor-returning variant of it) and the duplicate arithmetic goes. Until then this is the one place a second walker exists, on purpose.
* **Unmapping** (UNIMPLEMENTED): `remove_descriptor` already stores zero, publishes and proves the page faults again; exposing it as an end-of-run step is a few lines
  and a new refusal list, not done because nothing needs it yet.

## Building it

```
make -f platform/uefi/Makefile SP11=1 PAYLOAD=1 SMMUMAP=1 SP11_BUILD_STAMP=A9F00F9CCBB5 \
    SP11_USB_TABLE_C=tools/testdata/sp11-usb-table-fixture.c SP11_STAGE_TABLE_C=tools/testdata/sp11-stage-table-fixture.c \
    'LD=lld-link /Brepro' payload-runner
```

`SMMUMAP=1` without `PAYLOAD=1` is an error; `SMMUMAP=0` (the default) leaves every recipe, prerequisite and object as it was. The define goes on the runner's own compile
lines only (`main-payload.obj`, `sp11-payload-*.obj` and the two new objects), never on `q1n1.efi`, the stages or the survey. `SP11_BUILD_STAMP` is drawn on the page;
the pinned runner's stamp is used here so that the gate's code is the only difference.

<!-- smmumap-digests -->
| Image | Size | sha256 |
| --- | --- | --- |
| the pinned runner (base commit 241b7ca, and this tree with the gate off, the recipe above without `SMMUMAP=1`) | 776,192 B | `c20579093ec7b1506faca3c0d33520561716510d7932ac1c9d340f432c88bf6e` |
| this tree with the gate on (`SMMUMAP=1`, stamp `A9F00F9CCBB5`) | 787,968 B | `9e9579e3cbc02b34759c8b5d9651dc0f8a1ff1356e42442dac6e621d2f5ad6db` |
<!-- /smmumap-digests -->

OBSERVED on one host (Homebrew clang and LLD 23.1.5, `/Brepro`): each built twice to the same bytes. **The stamp.** The pinned stamp is what makes the gate-off proof a proof that the
code is equal: the runner built from this tree with the gate off is the pinned runner byte for byte. The runner that is staged is built from the committed tree with its own stamp (the
Makefile's default, twelve hex digits of `git describe`, which names that commit), so it is another image with another sha256: **a runner built from a commit that carries this gate has its own
stamp, and so its own hash**, and the record must name the hash of the image that is staged, not the gate-on row above (record the hash of the image that is staged and let the stage tool check
it). The page's `BUILD` line then names the new commit; if an image built with the pinned stamp were staged instead, its `BUILD` line would read `A9F00F9CCBB5`, the stamp of the pinned gate-off
runner, and only the `PAYLOAD SMMUMAP` lines would tell the two runners apart. `tools/test-q1n1-sp11-payload-smmumap.py` builds the base commit and this tree and compares them.

## Planning a chain's page

The formula is the one of [the runner's planning table](SP11-PAYLOAD.md#the-chain-several-payloads-in-one-boot): `LOADED` for each file and `READY` (files + 1), `VERIFY`,
`CALL` and `DONE` for each payload (3), each payload's own most lines, and the step's, at most ten (nine on the way to a mapped page and then the `SERROR` line, or the put-back's ten).

<!-- smmumap-chain-budget -->
| Chain | Lines | Fits the unit's 89 rows | Fits the 60 the layout asks for |
| --- | --- | --- | --- |
| `smmuprobe` alone with the step | (1 + 1) + 3 + 10 + 36 = 51 | yes | yes |
| `nvmesnap` and `smmuprobe` with the step | (2 + 1) + 3 x 2 + 10 + 34 + 36 = 89 | yes | no |
| `el2mem`, `nvmesnap` and `smmuprobe` with the step | (3 + 1) + 3 x 3 + 10 + 26 + 34 + 36 = 119 | no | no |
<!-- /smmumap-chain-budget -->

The second chain is the S1 chain with the step: 89 of 89 rows in the worst case of every part, with no margin (INFERRED: that the region holds 89 rows on the unit has not been measured, the
most seen on the panel is 58); a refusal prints fewer, and a line past the last row is mirrored to the serial port and not drawn. The third does not fit: the step runs with `nvmesnap` and
`smmuprobe`, or with `smmuprobe` alone.

## Tests

| Command | What it holds |
| --- | --- |
| `python3 tools/test-q1n1-sp11-payload-smmumap.py` | the host program (`tools/test-q1n1-sp11-payload-smmumap.c`, `-scan.c` and `-world.h`: eighteen suites over a modelled set of translation tables and memory map, an `AT` model that sees a store only after the whole publication, faults at each read, a slot that another agent writes during the wait, the store and the put-back, a missing, stuck, backwards, slow or odd counter, and a fuzz of 6,000 corrupted worlds against properties: nothing but the page's level-3 slot changes, what is stored is a descriptor of exactly that page into a table page that is RAM by the map, after a read of that slot, with no pointer to the table in the root or the level-1 table, a put-back restores the tables, a mapped page is Device, and no load of any run is made into a page that the model's own reading of the map does not call RAM: `stray_reads`, none allowed; a map that changes under the step, which the real one cannot do, reaches the scan's and the re-read's refusals) under ASan and UBSan, built again with lowered bounds on the reads of a wait; the loads, walk and scan (`-walk.c`, by including the source); the hook in the runner (`-run.c`); the source audits with seeded bad variants of the instructions and of the loads and the store; the code the gate adds to `main.c` and `sp11-payload-run.c`, pinned by a golden SHA-256 of its text, so that a change other than comments and blanks fails until the glue is audited again by hand and the digest updated (the scanner is literal-aware, so a comment marker inside a string hides nothing; a review tripwire, not the identity of what runs); the proof that the gate at zero changes nothing (the new files empty, the runner's files preprocessed as at the base commit, only the gate's files changed, the Makefile's lines the base's); the runner built from the base commit and from this tree; 162 seeded bugs, each rejected for its own reason |
| `python3 tools/test-q1n1-sp11-payload-smmumap-doc.py` | this document against the source and the host program: the constants, the printed page, every reason and every line token, the outcome table, the evidence labels, the budget arithmetic, the link targets, the sizes |
| `python3 tools/test-q1n1-sp11-payload-smmumap-ops.py` | the object of `sp11-smmumap-el2.c` run by an interpreter (what each `env` field executes) and the `PAR_EL1` fault bit (`-par.c`), each against thirteen edits of the sources |

What the tests cannot show: what the unit does at these addresses, whether the table page is writable on the unit, whether the table at `TTBR0_EL2` is the one the walker
uses, whether the barriers suffice on the core, whether the poll for an SError works there, or what the SMMU does with a read. Hardware: NOT RUN.
