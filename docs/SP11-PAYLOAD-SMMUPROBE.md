<!-- SPDX-License-Identifier: MIT -->
# SP11 payload `smmuprobe`: what the PCIe SMMUv3 does with the internal SSD's stream, and the state of the SSD's link

`payloads/smmuprobe.c` is one payload of the stick payload runner described in [SP11-PAYLOAD.md](SP11-PAYLOAD.md): the manifest
and the stick files, [the chain](SP11-PAYLOAD.md#the-chain-several-payloads-in-one-boot), ABI v1 and the
[line catalogue](SP11-PAYLOAD.md#line-catalogue) are defined there and not repeated. Its relative is [`el2mem`](SP11-PAYLOAD-EL2MEM.md),
whose guarded reads, `NEXT` line and eight seconds of counter it reuses, and with which it shares the code that asks the MMU and reads the
memory map (`payloads/payload-mmu.h`) and the page helper (`payloads/payload-page.h`). Evidence labels as there: VERIFIED, OBSERVED,
INFERRED, EXPERIMENTAL, UNIMPLEMENTED, UNKNOWN. **EXPERIMENTAL; hardware NOT RUN: it has never run on the unit, and this document
authorises no run.**

`smmuprobe` is **read only**. It asks the one question the Snapintosh NVMe window cannot answer from a host (Snapintosh
`docs/SP11-NVME-WINDOW.md`, questions D5 to D7 and D14, and kill criterion K4): **what does the PCIe SMMUv3 do with the DMA of the
internal SSD's controller?** and, on the way, **what state are the SSD's link and its two PCIe functions in?** It makes no write of any
kind: no store to a device, no doorbell, no `CC` write, no admin command, no `DC`, no `IC`, no `TLBI`, no `MSR`, no `SMC`. Every word of
a device or of RAM it reads comes from the runner's guarded `load32`.

## What is known, and what is not

OBSERVED on one unit, in one boot (run 7 of the X2 test image, 2026-11-15, Snapintosh `docs/SP11-NVME-WINDOW.md` section 7.1), and nothing
here repeats it as a distribution: at EL2 after the bounce the NVMe's PCIe root answered: segment 6 (ECAM base `0x70000000`, buses 0 and 1),
the root port at 00:00.0 and the endpoint at 01:00.0 (class `0x010802`), the link up at Gen4 x4, the controller's CAP, VS, CC, CSTS, AQA,
ASQ and ACQ readable. Its read of the PCIe SMMUv3 at `0x15400000` **faulted at EL2 in two boots** (runs 6 and 7, test T07 of Snapintosh
`docs/SP11-X2-TESTS.md`, OBSERVED): whether the SMMU translates, bypasses
or aborts the SSD's DMA is UNKNOWN, and so is whether the DMA window of the monitor can be reached at all.

INFERRED from the unit's firmware tables (the IORT, read offline; Snapintosh `config/boards/sp11.json` `storage.nvme`): segment 6's
requester ids `0` to `0xffff` map to StreamIDs `0x60000` and up through the one SMMUv3 node at `0x15400000`, so the endpoint, whose id is
`0x0100`, is **StreamID `0x60100`**. What the SMMU does with that stream is not in any table: it is in the SMMU's registers and its stream
table, which is what this payload reads.

## What it may issue

<!-- smmuprobe-instructions -->
| Instruction | Why | Where it is checked |
| --- | --- | --- |
| `MRS` of `CurrentEL`, `CNTFRQ_EL0` | where it runs; the counter frequency for the waits | the binary check: the registers read are exactly these and `PAR_EL1` |
| `AT S1E2R` and one `ISB`, then `MRS` of `PAR_EL1` | ask EL2's stage 1 about the pages it is about to read (it makes no access at them) | one of each in the binary |
| a call of the runner's `load32` | every word of a PCIe configuration page, of the SMMU register page and of the stream table | `rd()` is the one place a load is made; the memory check proves no other load of a device or of RAM exists |
| stores to its own stack only | the page lines and its counters | the memory check proves the base of every store is the payload's own stack |
<!-- /smmuprobe-instructions -->

No barrier, no exclusive or atomic instruction, no `SMC`, no `HVC`. The binary is checked against this list by `tools/sp11_payload_testlib.py`'s
engine and `tools/sp11_payload_memcheck.py` with a policy that lives in `tools/test-q1n1-sp11-payload-smmuprobe.py` (the shared registry is not
extended, so the shared build test does not audit this payload).

## What it does, in order

1. **Where it runs.** `CurrentEL` and `CNTFRQ_EL0` (19.2 MHz is used if it is outside 1 MHz to 1 GHz). Not at EL2 it prints
   `REFUSED NOT_AT_EL2` and returns 2 with nothing else done; with no `load32` in the arguments it prints `REFUSED NO_LOAD_OP` and returns 3.
2. **`MAP`: three questions to the MMU.** `AT S1E2R` of the root port's page, the endpoint's page and the SMMU's page: mapped in EL2's
   stage 1 or not, and with which attributes. It makes no access at them. **The answer is obeyed:** a device page the MMU says is
   unmapped, or maps as anything but Device (Normal memory, in any cacheability, or an attribute that is not one of the four Device
   encodings), is never loaded from: a Normal mapping could fill a cache line around the register that was asked for, and no register of this
   set is known to be harmless to read around (INFERRED); an unmapped page would only fault. `rd()` refuses such a load before it reaches
   the runner, with code 126 (`REFUSED:126`).
3. **The headers** of the root port and of the endpoint: ids, command and status, class, header type, then the bridge's bus numbers or the
   endpoint's BARs, and the capability pointer. These are the dwords the X2 image already read at EL2 (OBSERVED in one boot: run 7), so they
   have no `NEXT` line of their own. A function whose page was refused in step 2 shows `ID=REFUSED:126` and nothing else.
4. **`NEXT PCIE_CAPS AFTER 8 S`, eight seconds, then the PCI Express capability and the Advanced Error Reporting capability of both
   functions** (link, device and error status): the first reads of this unit's configuration space above offset `0x40`.
5. **`NEXT SMMU_REGISTERS AFTER 8 S`, eight seconds, then the SMMUv3 registers** in the order of the next section. The first read that does
   not return a value stops the group: the registers after it print `NOT_ATTEMPTED` and nothing else of the SMMU or of RAM is read. If the
   MMU refused the SMMU's page in step 2 the group is not run at all (no `NEXT` line, no wait, no read) and the verdict is `UNKNOWN` with
   `SMMU_PAGE_UNMAPPED` or `SMMU_PAGE_NOT_DEVICE`.
6. **The stream table, only if the registers say it is in use, the memory map says its words are RAM and the MMU says their page is
   mapped:** `STRTAB` (the format and where the table is), `L1` (the level-1 descriptor of a two-level table), `STE` (the four doublewords of
   the entry of StreamID `0x60100`) and `S2` (the stage-2 fields, only for an entry that has a stage 2). RAM may be mapped as anything: only
   a missing mapping refuses (`L1_UNMAPPED`, `STE_UNMAPPED`).
7. **`VERDICT`** and **`DONE`**.

The two `NEXT` lines and the waits are `el2mem`'s idiom: the line is drawn, the counter runs for eight seconds, then the reads that may stall
the board; a board that hangs leaves the group's name as the last line on the panel (INFERRED from the earlier boots of the other payloads).
If the counter cannot be used (`NO_COUNTER`, or `COUNTER_UNUSABLE` for a counter that stands still or goes back) the group is announced, said
to be skipped, and **never read**. Total loads: at most 139 on any page the host test can build (two functions of at most 57 each, 15
registers, 2 words of descriptor, 8 words of entry); the payload's own cap is 400 and the runner's is 4096.

## The registers, in the order they are read

<!-- smmuprobe-registers -->
| # | Register | Offset | Words | What it says here (decoded as q1n1's `tools/nvme_m3.py` `class Smmu` decodes it; INFERRED for this SoC) |
| --- | --- | --- | --- | --- |
| 1 | `IDR0` | `0x00` | 1 | first read: it answers if the page is readable at all (a read-only ID register); printed raw |
| 2 | `IDR1` | `0x04` | 1 | printed raw (stream id width, queue sizes) |
| 3 | `IDR2` | `0x08` | 1 | printed raw |
| 4 | `IDR3` | `0x0c` | 1 | printed raw |
| 5 | `IDR4` | `0x10` | 1 | printed raw |
| 6 | `IDR5` | `0x14` | 1 | printed raw (output address size, granules) |
| 7 | `IIDR` | `0x18` | 1 | the implementer, printed raw |
| 8 | `AIDR` | `0x1c` | 1 | the architecture revision, printed raw |
| 9 | `CR0` | `0x20` | 1 | bit 0 `SMMUEN`: 0, every stream follows `GBPA`; 1, every stream is looked up in the stream table |
| 10 | `CR0ACK` | `0x24` | 1 | the acknowledgement of `CR0`: `SMMUEN` is decided from it, and only if `CR0` (what was asked) has the same value; a value that differs in any bit means an update is pending or was refused, and the verdict is `UNKNOWN` (`CR0_ACK_DISAGREE`) |
| 11 | `GBPA` | `0x44` | 1 | bit 20 `ABORT`, used only with `SMMUEN` 0: 1 aborts every stream, 0 lets it through |
| 12 | `GERROR` | `0x60` | 1 | the global errors, printed raw (non-zero: an error is active) |
| 13 | `STRTAB_BASE` | `0x80` | 2 | bits 51:6 the table's address; read as two words, low first |
| 14 | `STRTAB_CFG` | `0x88` | 1 | bits 17:16 `FMT` (0 linear, 1 two levels), 10:6 `SPLIT` (6, 8 or 10), 5:0 `LOG2SIZE` (the table holds `2^LOG2SIZE` streams) |
<!-- /smmuprobe-registers -->

Nothing above offset `0x90` is read, and nothing is written: not `CR0`, not `GBPA`, not an event or command queue, not a stream table
entry. A register is reported as `NAME=0X<value>`, `NAME=FAULT` (the guarded load aborted), `NAME=REFUSED:<code>` (the op or this payload
refused the address; code 127 is the payload's own guard for an address in no window, code 126 its guard for a page the MMU did not approve)
or `NAME=NOT_ATTEMPTED`.

## What it reads of PCIe configuration space

<!-- smmuprobe-config -->
| Group | Dwords (offsets in the function's 4 KiB page) | Stops when |
| --- | --- | --- |
| header | `0x00` id, `0x04` command and status, `0x08` class, `0x0c` header type, then `0x10` and `0x14` (type 0: BAR0, BAR1) or `0x18` (type 1: bus numbers), then `0x34` if status bit 4 says there is a capability list | the id is `0xffffffff` or its vendor is `0xffff` (`ABSENT`); any read does not return |
| PCI Express capability | the list from the pointer at `0x34` (pointers masked to dwords, kept in `0x40` to `0xff`, at most 16 steps), then from the capability `+0x08` (device control and status), `+0x0c` (link capabilities), `+0x10` (link control and status), and for version 2 or later `+0x2c` and `+0x30` (link capabilities 2, link control 2 and status 2) | the capability is not found; any read does not return |
| Advanced Error Reporting | the extended list from `0x100` (at most 24 steps, pointers masked to dwords, kept in `0x100` to `0xffc`), then from the capability `+0x04` (uncorrectable status), `+0x08` (mask), `+0x10` (correctable status), `+0x14` (mask) and, for a root port only, `+0x30` (root error status) | the capability is not found; any read does not return; only for a function that has a PCI Express capability |
<!-- /smmuprobe-config -->

The link is printed decoded (`LINK=GEN4.X4`: the speed code and the width of the Link Status register) next to the raw dwords. Whether the
data link layer is active (`DLLA=1`) is printed only where Link Capabilities bit 20 says the function reports it: on an endpoint that bit of
the Link Status is reserved, and reading it as "down" would say something the device did not. A register that is a write-1-to-clear status
(the AER status registers) is read, never cleared.

## Memory rules

The memory map is read in place, as `el2mem` does (`payloads/payload-mmu.h`: a map with a stride below 40 or not a multiple of 8, a size that
is not whole descriptors, a buffer that is unaligned or leaves the 48-bit space, or more than 1024 descriptors is refused and nothing of it
is read). The stream table is in RAM the payload did not allocate, and a read of the wrong physical address can be an abort the runner cannot
recover, so:

* A word of the table is read only if the **whole word lies in a descriptor of type 1 to 7 or 9** (loader, boot services, runtime services,
  conventional and ACPI reclaim memory): not reserved memory, not unusable, not ACPI NVS, not memory-mapped I/O, not anything else.
* **Any descriptor that overlaps the word and is not one of those types refuses it**, wherever it is in the map and whatever else holds the
  word: a map that disagrees with itself is never read through. A descriptor that is unaligned, empty or beyond 48 bits is not used.
* **One extent is open at a time**, exactly the bytes about to be read (8 for a descriptor, 32 of the 64 of an entry), and `rd()` refuses every
  other address: the three device windows (the root port's page, the endpoint's, the SMMU's registers below `0x90`) and that extent.
* **The MMU is asked first and obeyed.** The three device pages are asked of the MMU in the `MAP` step, and `rd()` refuses a load in a
  device page the MMU said is unmapped or not a Device mapping (code 126). The page of the descriptor and the page of the entry are asked
  after the memory map approves them and before the first word is read, and a page the MMU does not map is not read (`L1_UNMAPPED`,
  `STE_UNMAPPED`); RAM may be mapped as anything. The answer is EL2's stage 1 as the AT reports it, which is not a proof that a load will
  not fault.
* A refusal is not a fault: it prints `MEMMAP_TYPE=<type>` (or `NOT_IN_MAP`, or `MAP_UNUSABLE`), `NOT_READ`, and the verdict `UNKNOWN` with the
  reason `TABLE_NOT_RAM`. **A stream table in reserved memory (type 0), which is where a firmware or a hypervisor that owns the SMMU would
  put it, is therefore reported, not read.**
* A read that does not return stops that function (or the SMMU group, and with it the RAM) for good.

## What it decodes of the stream table

The lookup is the Arm SMMUv3 architecture's (IHI 0070, INFERRED from the specification, not observed on this unit):

* `SMMUEN` is read from `CR0ACK`, what the SMMU acknowledged, and only when `CR0`, what was asked, has the same value: a `CR0` that differs
  from `CR0ACK` in any bit is an update that is pending or was refused, and the verdict is `UNKNOWN` (`CR0_ACK_DISAGREE`; a `CR0ACK` that
  was not read is `CR0ACK_NOT_READ`). Comparing the whole register is conservative: it can say `UNKNOWN` for a difference in a bit that
  does not matter here, and never says bypass for a state it did not see.
* `SMMUEN` 0: every stream follows `GBPA`: `ABORT_GLOBAL` if bit 20 is set, else `BYPASS_GLOBAL`.
* `SMMUEN` 1: StreamID `0x60100` must be below `2^LOG2SIZE` (else `NO_STE`, `SID_BEYOND_TABLE`). `FMT` 0: the entry is at
  `base + 64 * StreamID`. `FMT` 1 with `SPLIT` 6, 8 or 10 (else `STRTAB_SPLIT`): the level-1 descriptor is at
  `base + 8 * (StreamID >> SPLIT)`; its `Span` (bits 4:0) of 0 means no level-2 table (`NO_STE`, `NO_L2_TABLE`); the entry index
  `StreamID & (2^SPLIT - 1)` must be below `2^(Span - 1)` (else `NO_STE`, `BEYOND_L2_SPAN`); the entry is at `L2Ptr + 64 * index`. Any other
  `FMT` is `STRTAB_FORMAT`.
* The entry: `V` (bit 0) 0 is `INVALID`; otherwise `Config` (bits 3:1): 0 `ABORT`, 4 `BYPASS`, 5 `S1`, 6 `S2`, 7 `S1S2`, the others `RESERVED`.
  For `S2` and `S1S2` the stage-2 fields are printed: `VMID` (DW2 bits 15:0), `T0SZ` (37:32), `SL0` (39:38), `TG` (47:46), `AA64` (51) and
  `TTB` (DW3 bits 51:4).

The addresses are 52-bit fields (bits 51:6 and 51:4); an address that leaves the 48-bit space is not in the memory map and is reported as
such. A base that is not aligned to the table's size is **not** corrected (UNKNOWN whether the hardware ignores the low bits): the printed
`BASE` is the field as read.

## What it prints

<!-- smmuprobe-lines -->
| Line | Entries | When |
| --- | --- | --- |
| `START` | `CURRENTEL`, `FREQ`, `ECAM`, `SMMU` | always |
| `REFUSED` | `NOT_AT_EL2` or `NO_LOAD_OP` | not at EL2, or no load op |
| `MAP` | `RP`, `EP`, `SMMU`: the walk of each page (`DEVICE.NSH`, `WB.IS`, ... or `FAULT=<code>`); a page that is not `DEVICE...` or is a fault is not read | always |
| `RP`, `EP` | `ID`, `CMDSTS`, `CLASSREV`, `HDR`, `BAR0` and `BAR1` or `BUSES`, `CAPPTR`; or `ID` and `ABSENT`; or `ID=REFUSED:126` | always (wraps) |
| `NEXT` | `PCIE_CAPS AFTER 8 S`, `SMMU_REGISTERS AFTER 8 S` (not printed when the MMU refused the SMMU's page) | before each hazardous group; never dropped |
| `PCIE_CAPS`, `SMMU_REGISTERS` | `SKIPPED=NO_COUNTER` or `SKIPPED=COUNTER_UNUSABLE` | the wait could not be made |
| `RP.PCIE`, `EP.PCIE` | `AT`, `HDR`, `TYPE`, `DEVCTLSTA`, `LNKCAP`, `LNKCTLSTA`, `LINK`, `DLLA`, `LNKCAP2`, `LNKCTL2STA2`; or `PCIE=NONE` or `PCIE=NOT_READ` | after the first `NEXT` |
| `RP.AER`, `EP.AER` | `AT`, `UESTA`, `UEMASK`, `CESTA`, `CEMASK`, `ROOTERR` (root port); or `AER=NONE`, `AER=FAULT`, `AER=NOT_READ`, `AER=NO_PCIE_CAP` | after the first `NEXT` |
| `SMMU` | the fourteen registers of the table above | after the second `NEXT` |
| `STRTAB` | `FMT`, `SPLIT`, `LOG2SIZE`, `BASE`, `SID` | the SMMU is enabled and both table registers were read |
| `L1` | `AT`, `MAP`, `DESC` or `MEMMAP_TYPE` | a two-level table |
| `STE` | `AT`, `MAP`, `V`, `CONFIG`, `DW0` to `DW3`; or `MEMMAP_TYPE` and `NOT_READ`; or `MAP` and `NOT_READ` (the page is unmapped) | the entry's address was derived |
| `S2` | `VMID`, `T0SZ`, `SL0`, `TG`, `AA64`, `TTB` | the entry has a stage 2 |
| `VERDICT` | `STREAM`, `MODE`, `WHY`; never dropped | always |
| `DONE` | `SMMU_GROUP_RAN` or `SMMU_GROUP_SKIPPED` (the wait could not be made, or the MMU refused the SMMU's page), `LOADS`, `FAULTS`, `REFUSED`, `SMMU_TRIED`, `SUPPRESSED` (only if lines were dropped); never dropped | always |
<!-- /smmuprobe-lines -->

At most 36 lines (the runner draws 40 per payload); the host test measures at most 30 over its worst world and its fuzz, and every line is at most
100 characters. The lines that are not essential are dropped, and counted in `SUPPRESSED`, once they would leave no room for the four that
are (the two `NEXT` lines, the verdict and the last line).

### What the host model prints

The page of the good world of the host test (`tools/test-q1n1-sp11-payload-smmuprobe.c`): a **made-up but self-consistent unit**, with
values chosen to tell fields apart, NOT read from any unit; two levels, `SPLIT` 10, stage 2. EXPERIMENTAL (host model only); every value was
checked by hand against the scripted words.

<!-- smmuprobe-page -->
```
PAYLOAD SMMUPROBE START CURRENTEL=0X8 FREQ=19200000 ECAM=0X70000000 SMMU=0X15400000
PAYLOAD SMMUPROBE MAP RP=DEVICE.NSH EP=DEVICE.NSH SMMU=DEVICE.NSH
PAYLOAD SMMUPROBE RP ID=0X11117CB CMDSTS=0X100007 CLASSREV=0X6040001 HDR=0X10010 BUSES=0X10100
PAYLOAD SMMUPROBE RP CAPPTR=0X40
PAYLOAD SMMUPROBE EP ID=0XA80B144D CMDSTS=0X100406 CLASSREV=0X1080200 HDR=0X10 BAR0=0X60800004
PAYLOAD SMMUPROBE EP BAR1=0X0 CAPPTR=0X40
PAYLOAD SMMUPROBE NEXT PCIE_CAPS AFTER 8 S
PAYLOAD SMMUPROBE RP.PCIE AT=0X70 HDR=0X420010 TYPE=4 DEVCTLSTA=0X2810 LNKCAP=0X100C44
PAYLOAD SMMUPROBE RP.PCIE LNKCTLSTA=0X20440040 LINK=GEN4.X4 DLLA=1 LNKCAP2=0X1E LNKCTL2STA2=0X4
PAYLOAD SMMUPROBE EP.PCIE AT=0X80 HDR=0X20010 TYPE=0 DEVCTLSTA=0X2810 LNKCAP=0XC44
PAYLOAD SMMUPROBE EP.PCIE LNKCTLSTA=0X440040 LINK=GEN4.X4 LNKCAP2=0X1E LNKCTL2STA2=0X4
PAYLOAD SMMUPROBE RP.AER AT=0X140 UESTA=0X4000 UEMASK=0X400000 CESTA=0X2000 CEMASK=0X0 ROOTERR=0X0
PAYLOAD SMMUPROBE EP.AER AT=0X100 UESTA=0X0 UEMASK=0X400000 CESTA=0X0 CEMASK=0XE000
PAYLOAD SMMUPROBE NEXT SMMU_REGISTERS AFTER 8 S
PAYLOAD SMMUPROBE SMMU IDR0=0X5A000000 IDR1=0X5A000004 IDR2=0X5A000008 IDR3=0X5A00000C
PAYLOAD SMMUPROBE SMMU IDR4=0X5A000010 IDR5=0X5A000014 IIDR=0X5A000018 AIDR=0X5A00001C CR0=0XD
PAYLOAD SMMUPROBE SMMU CR0ACK=0XD GBPA=0X1000 GERROR=0X0 STRTAB_BASE=0X400000008A000000
PAYLOAD SMMUPROBE SMMU STRTAB_CFG=0X10294
PAYLOAD SMMUPROBE STRTAB FMT=1 SPLIT=10 LOG2SIZE=20 BASE=0X8A000000 SID=0X60100
PAYLOAD SMMUPROBE L1 AT=0X8A000C00 MAP=WB.IS DESC=0X8A40000B
PAYLOAD SMMUPROBE STE AT=0X8A404000 MAP=WB.IS V=1 CONFIG=6 DW0=0XD DW1=0X0 DW2=0XD409000000007
PAYLOAD SMMUPROBE STE DW3=0X8C000000
PAYLOAD SMMUPROBE S2 VMID=7 T0SZ=16 SL0=2 TG=1 AA64=1 TTB=0X8C000000
PAYLOAD SMMUPROBE VERDICT STREAM=0X60100 MODE=S2 WHY=NONE
PAYLOAD SMMUPROBE DONE SMMU_GROUP_RAN LOADS=67 FAULTS=0 REFUSED=0 SMMU_TRIED=14
```
<!-- /smmuprobe-page -->

## What each outcome means

The verdict is about **StreamID `0x60100` as the SMMU is at the moment of the read**, in the firmware's state after the bounce. Each row
names what the monitor port and the NVMe window do next. "S2" and "S3" are the steps of Snapintosh WS-D (the takeover, and the per-machine
questions); X6 is the gate; K4 is the kill criterion whose first bullet is an SMMU write that needs its own authorisation.

<!-- smmuprobe-decisions -->
| Mode (reasons) | What it says | What it means for S2, S3 and X6 | What comes next |
| --- | --- | --- | --- |
| `S2`, `S1`, `S1S2` (`NONE`) | the stream is translated: the SSD's DMA goes through the tables the entry names (and `TTB`, `VMID` and the shape of stage 2 are printed) | the DMA window exists only through those tables: whether they map the window read/write is D14, and a table that lives in memory the monitor will not keep, or that does not cover the window, means the monitor needs **a stream table of its own**: an SMMU write, K4's first bullet, its own authorisation | a read-only walk of the stage-2 tables over the window (the `Smmu.reaches` of q1n1's `nvme_m3.py`), which needs the table memory to be readable RAM (this payload says so) |
| `BYPASS` (`NONE`), `BYPASS_GLOBAL` (`SMMU_DISABLED`) | the SSD addresses physical memory directly: nothing translates, nothing confines | **the window model's DMA rules are all there is**: the shadow queues and the checks of `compat/nvme-host.c` are the only confinement, and the controller can reach all of DRAM, so D14 holds by construction and the model's allow-lists are the whole safety argument | S2 may proceed on the host-verified contract; a read-only takeover (the second hardware session) |
| `ABORT`, `INVALID`, `RESERVED` (`NONE`), `ABORT_GLOBAL` (`SMMU_DISABLED`), `NO_STE` (`SID_BEYOND_TABLE`, `NO_L2_TABLE`, `BEYOND_L2_SPAN`) | every DMA of the stream is terminated (the architecture's `C_BAD_STE` and `C_BAD_STREAMID`, INFERRED from IHI 0070): **the controller cannot DMA at all** | the window cannot work until the SMMU is changed: a write to `GBPA` or to a stream table entry, K4's first bullet, its own authorisation; if the monitor cannot write the SMMU, K4 | stop; report; the owner decides (no write is attempted by any payload of this series) |
| `UNKNOWN` with `CR0_NOT_READ`, `CR0ACK_NOT_READ`, `GBPA_NOT_READ`, `STRTAB_NOT_READ` | a read of the SMMU's page faulted or was refused: **the SMMU cannot be read at EL2** (as the X2 image's read did) | nothing is decided: do not treat it as bypass; the `MAP` line says whether EL2's stage 1 maps the page at all, and the `FAULT=` code says how it ended | find out why (an unmapped page is a stage-1 question for the monitor; an abort that EL2 cannot take is the SMMU's owner's): a design question, not a write |
| `UNKNOWN` with `SMMU_PAGE_UNMAPPED`, `SMMU_PAGE_NOT_DEVICE` | the MMU said, before any read, that EL2's stage 1 does not map the SMMU's register page, or maps it as something that is not Device memory: **nothing of the SMMU was read** (no `NEXT` line, no wait) | nothing is decided: the read would only fault (unmapped), or could fill a cache line around a register (a Normal mapping, INFERRED) | the same stage-1 question for the monitor, now answered without a fault: the `MAP` line shows the walk's answer (INFERRED, not shown: an unmapped page may be what faulted the X2 image's read, whose T07 listed the SMMU's base as not in the UEFI memory map) |
| `UNKNOWN` with `CR0_ACK_DISAGREE` | `CR0` and `CR0ACK` were both read and differ: an update of `CR0` is pending or was refused, so there is no settled state to name | nothing is decided and no table word is read | read it again later by hand, or find out who is changing the SMMU while the stick runs |
| `UNKNOWN` with `STRTAB_FORMAT`, `STRTAB_SPLIT` | the registers were read and describe a table this payload does not decode (a reserved format, a `SPLIT` that is not 6, 8 or 10) | UNKNOWN, with the raw `STRTAB_CFG` printed | read the register fields by hand against IHI 0070; extend the decode only with evidence |
| `UNKNOWN` with `TABLE_NOT_RAM`, `L1_NOT_READ`, `STE_NOT_READ`, `L1_UNMAPPED`, `STE_UNMAPPED` | the table is where the registers say, but its words are not memory this payload may read (`MEMMAP_TYPE` says what the map calls them), a guarded read of them aborted, or EL2's stage 1 does not map their page (the `MAP` entry says so) | the SMMU is enabled and has a table the payload cannot show: the entry is unknown, and **a table in reserved memory (type 0) is the likely owner's**: a hypervisor's or the firmware's | a later payload that reads that memory only after the operator names the extent, or the owner's call that the monitor will not rely on a table it did not write |
| `UNKNOWN` with `GROUP_SKIPPED` | the wait could not be made: no counter, or a counter that is stuck or goes back | nothing was read of the SMMU | fix the counter question first (it is the runner's) |
<!-- /smmuprobe-decisions -->

None of the outcomes authorises anything. A verdict other than `BYPASS` and `BYPASS_GLOBAL` can end at a **write to the SMMU**, which this series
has never done and which needs the operator's own, named authorisation before any run.

## The first three storage hardware sessions

Snapintosh `docs/SP11-STORAGE-PROVISIONING.md` plans the three sessions with their stop rules; this payload is the first. The whole of session 1
is: boot the stick with the runner and `smmuprobe.bin` last in its chain, photograph the page, and stop. The payload writes nothing to the
internal disk, to the SMMU or to any device register (it has no store but to its own stack). What a run does write is outside the payload:
the stick's Shell script puts its marker file `SP11\DONE<n>.TXT` on the stick, as every autorun step does, and the runner draws its page on the
framebuffer. A run still needs the operator's explicit authorisation, which nothing here gives.

## The next payload

If the entry translates (`S2`, `S1`, `S1S2`): **a read-only walk of the stage-2 tables** over the DMA window, in the manner of `Smmu.reaches`,
that reports for each page of the window whether the SSD could read and write it (D14). It needs the `TTB`, `T0SZ`, `SL0`, `TG` this payload
prints and table memory the map lets it read. If the SMMU cannot be read: the runner's `load32` returns `FAULT` with no syndrome, so a later
runner op that returns `ESR_EL2` after a fault (a runner change, not a payload) would say whether it was a stage-1 translation fault, an
external abort or a permission fault. If the entry is bypass or abort, nothing more of the SMMU is read: the next step is not a payload.

## Staging (not authorised)

`make -f platform/uefi/Makefile payloads` builds `smmuprobe.elf` and `smmuprobe.bin` with every other payload, and the manifest tool
(`tools/sp11_payload_manifest.py`) takes 8.3 names only and refuses `SMMUPROBE.BIN` (nine letters): stage a copy of the same bytes as
`SMMUPRB.BIN`. It goes **last** in its chain: a read that hangs takes every earlier line of the
chain with it ([SP11-PAYLOAD.md](SP11-PAYLOAD.md#the-chain-several-payloads-in-one-boot), "Order"). Running it needs the operator's explicit
authorisation; this document, its tests and its build are not that authorisation.

## Planning a chain's page

The formula is the one of [the runner's planning table](SP11-PAYLOAD.md#the-chain-several-payloads-in-one-boot): `LOADED` for each file and
`READY` (files + 1), `VERIFY`, `CALL` and `DONE` for each payload (3), and the payload's own most lines, here its budget of 36 (the host tests
reach 30 and never pass 36; the runner draws at most 40 per payload).

<!-- smmuprobe-chain-budget -->
| Chain | Lines | Fits the unit's 89 rows | Fits the 60 the layout asks for |
| --- | --- | --- | --- |
| `smmuprobe` alone | (1 + 1) + 3 + 36 = 41 | yes | yes |
| `el2mem` and `smmuprobe` | (2 + 1) + 3 x 2 + 26 + 36 = 71 | yes | no |
| `usbsmmu`, `el2mem` and `smmuprobe` | (3 + 1) + 3 x 3 + 24 + 26 + 36 = 99 | no | no |
<!-- /smmuprobe-chain-budget -->

The third chain does not fit the unit's panel: `smmuprobe` is run alone or with one other payload.

## Tests

| Command | What it holds |
| --- | --- |
| `python3 tools/test-q1n1-sp11-payload-smmuprobe.py` | the host program (`tools/test-q1n1-sp11-payload-smmuprobe.c`, thirteen suites under ASan and UBSan: the good world's exact page and 67 loads in order, a fault at each register, every outcome of the lookup, `CR0` against `CR0ACK`, every kind of answer of the MMU for each device page and for the table's pages (nothing is read where it says no, judged by a rule of the model's own), every memory map type and edge, the counter, the arguments, the line and load budgets, a fuzz against an oracle written another way), built again with a 14-line and a 10-line page and with a load cap of 20; 134 seeded-bug mutants and an unmutated control, 5 seeded page-budget bugs and 3 seeded load-cap bugs; the source audit; the allow-list and the memory check on `smmuprobe.bin` with 27 seeded bad binaries (writes to the SMMU, to configuration space and to a doorbell, unguarded reads, every forbidden instruction) |
| `python3 tools/test-q1n1-sp11-payload-smmuprobe-doc.py` | this document against the source and the host test: the register table, the printed page, the reasons and modes, the link targets, the labels, the sizes |

What the tests cannot show: what the unit does at these addresses, what an EL3 does with a read that hangs, whether a `load32` abort at an SMMU
register is recoverable, or what a real firmware's stream table holds.

## Residual risks

* **A read that hangs, not faults.** The runner's `load32` recovers an abort, not a hang; the `NEXT` lines and the order (the SMMU last) are
  the only mitigation, and the reads of the SMMU are the ones the X2 image already saw fault. INFERRED: a fault is more likely than a hang.
* **The decode is the architecture's, not this SoC's.** Qualcomm's SMMUv3 may differ in what an entry means; the raw doublewords are printed
  so that the page can be re-read by hand.
* **The StreamID is from the IORT, not from the SMMU.** A different mapping would make the verdict about another stream.
* **A table in reserved memory is reported, not read.** That is the safe answer and may be the usual one.
* **Reading configuration space above `0x40` is new on this unit.** The ECAM window answered at EL2 in one boot (run 7 of the X2 image; in run 6
  a read of segment 3's window did not return and the board reset itself, OBSERVED once).

## Status

EXPERIMENTAL; hardware NOT RUN. Nothing in this document is VERIFIED for the unit.
