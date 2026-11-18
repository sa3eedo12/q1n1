<!-- SPDX-License-Identifier: MIT -->
# SP11 payload `nvmesnap`: the state of the internal SSD's link, its NVMe controller and the admin queues the firmware left

`payloads/nvmesnap.c` is one payload of the stick payload runner described in [SP11-PAYLOAD.md](SP11-PAYLOAD.md): the manifest and the
stick files, [the chain](SP11-PAYLOAD.md#the-chain-several-payloads-in-one-boot), ABI v1 and the
[line catalogue](SP11-PAYLOAD.md#line-catalogue) are defined there and not repeated. Its relatives are [`smmuprobe`](SP11-PAYLOAD-SMMUPROBE.md),
which reads the PCIe SMMU that this payload does not touch and runs after it in the same chain, and [`el2mem`](SP11-PAYLOAD-EL2MEM.md), whose
guarded reads, `NEXT` line and eight seconds of counter it reuses, and with which it shares the code that asks the MMU and reads the memory map
(`payloads/payload-mmu.h`) and the page helper (`payloads/payload-page.h`). Evidence labels as there: VERIFIED, OBSERVED, INFERRED,
EXPERIMENTAL, UNIMPLEMENTED, UNKNOWN. **EXPERIMENTAL; hardware NOT RUN: it has never run on the unit, and this document authorises no run.**

`nvmesnap` is **read only**. It asks the question a takeover of the internal SSD's controller has to answer before it may touch the controller
(Snapintosh `docs/SP11-NVME-WINDOW.md`, questions D8 and D15, and `docs/SP11-STORAGE-PROVISIONING.md`): **in what state did the firmware leave
the link, the endpoint and the NVMe controller, and what were the two commands of the firmware's 2-entry admin queue (its slots 0 and 1)?** It makes no write of
any kind: no store to a device, no doorbell, no `CC` write, no admin command, no `DC`, no `IC`, no `TLBI`, no `MSR`, no `SMC`. Every word of a
device or of RAM it reads comes from the runner's guarded `load32`, except the descriptors of the memory map, which are read in place once the map
has been checked (below, "Memory rules").

## What is known, and what is not

OBSERVED on one unit, in one boot (run 7 of the X2 test image, 2026-11-15, Snapintosh `docs/SP11-NVME-WINDOW.md` section 7.1), and nothing here
repeats it as a distribution: at EL2 after the bounce the NVMe's PCIe root answered: segment 6 (ECAM base `0x70000000`, buses 0 and 1), the root
port at 00:00.0 and the endpoint at 01:00.0 (class `0x010802`, command `0x0006`, BAR0 at `0x70300000`), the link up at Gen4 x4 with the data link
layer active, and the controller's registers read as `CAP` `0x303C0301FF`, `VS` `0x00010400` (1.4.0), `CC` `0x00460001` (enabled), `CSTS` `0x1` (ready),
`AQA` `0x00010001` (two entries in each admin queue), `ASQ` `0xCF3E7000` and `ACQ` `0xCF3E8000`, each the same at EL2 as in the firmware's own
reading before ExitBootServices. The two queue addresses lie in the boot services data extent of the memory map (INFERRED from that map).

**New on this unit, and so UNKNOWN until a run:** the endpoint's header dword `0x0c` and capability pointer `0x34`, its capability chain (the power
management capability's `PMCSR`, its PCI Express link dwords), the port's link capabilities (`+0x0c` of its PCI Express capability), `CSTS` read a
second time, what the MMU says of the controller's page, and **the two admin queue pages**, which no earlier image read. The same image read the
root port's `0x00`, `0x04` (its memory-space bit decided whether the registers were read), `0x08`, `0x0c`, `0x18`, `0x20` to `0x2c` and `0x34`, the
first dword of each capability it walked and the PCI Express capability's `+0x10` (the link), and the endpoint's `0x00`, `0x04` (its memory-space bit
as well), `0x08`, `0x10` and `0x14`: the table sets them against what this payload reads. A read of an address that the firmware's own reading did
not use may fault or hang (INFERRED: nothing of the kind has been seen on this unit), which is why every group is announced and why each block of
registers starts with one Linux's driver reads and ends with the ones it never reads. The X2 image read the controller's registers in the order
`CAP`, `VS`, `CC`, `CSTS`, `AQA`, `ASQ`, `ACQ`; this payload reads the same seven, in another order and `CSTS` twice, as the section below says.

<!-- nvmesnap-x2 -->
| Function | Dwords this payload reads that the X2 image read (OBSERVED once) | Dwords it reads that the image did not (UNKNOWN until a run) |
| --- | --- | --- |
| root port 00:00.0 | `0x00`, `0x04`, `0x08`, `0x0c`, `0x18`, `0x20`, `0x34`, the first dword of each capability, PCI Express `+0x10` | PCI Express `+0x0c` |
| endpoint 01:00.0 | `0x00`, `0x04`, `0x08`, `0x10`, `0x14` | `0x0c`, `0x34`, the first dword of each capability, power management `+0x04`, PCI Express `+0x0c`, PCI Express `+0x10` |
<!-- /nvmesnap-x2 -->

From the pinned Linux device tree (reference evidence, `hamoa.dtsi:3451-3452`: the non-prefetchable window of `pcie6a` is `0x70300000` and
`0x3d00000` bytes; `hamoa.dtsi:3455`: `dma-coherent`; `hamoa.dtsi:8555`: the PCIe SMMU is `status = "reserved"`, "Controlled by Gunyah"): a BAR
outside that window is not reached through this root complex, which is the platform window the second gate checks. The SMMU is not read here.

## What it may issue

<!-- nvmesnap-instructions -->
| Instruction | Why | Where it is checked |
| --- | --- | --- |
| `MRS` of `CurrentEL`, `CNTFRQ_EL0` | where it runs; the counter frequency for the waits | the binary check: the registers read are exactly these and `PAR_EL1` |
| `AT S1E2R` and one `ISB`, then `MRS` of `PAR_EL1` | ask EL2's stage 1 about the pages it is about to read (it makes no access at them) | one of each in the binary |
| a call of the runner's `load32` | every word of a PCIe configuration page, of the controller's registers and of the two queue pages | `rd()` is the one place such a load is made; the memory check proves no other load of a device or of RAM exists but the next row's |
| plain loads of the memory map's descriptors | the type, start and size of each descriptor of the map the runner passes, read in place once the map's shape was checked (`pl_desc_read` in `payloads/payload-mmu.h`, as in `el2mem` and `smmuprobe`) | the memory check allows loads through the pointers of the arguments, which is how these are made; they read the map and never a device |
| stores to its own stack only | the page lines and its counters | the memory check proves the base of every store is the payload's own stack |
<!-- /nvmesnap-instructions -->

No other barrier, no exclusive or atomic instruction, no `SMC`, no `HVC`. The binary is checked against this list by `tools/sp11_payload_testlib.py`'s
engine and `tools/sp11_payload_memcheck.py` with the policy `POLICIES['nvmesnap']` of that shared registry, which the shared build test
(`tools/test-q1n1-sp11-payload-build.py`) applies to this binary as to every other payload.

## What it does, in order

1. **Where it runs.** `CurrentEL` and `CNTFRQ_EL0` (19.2 MHz is used if it is outside 1 MHz to 1 GHz). Not at EL2 it prints
   `REFUSED NOT_AT_EL2` and returns 2 with nothing else done; with no `load32` in the arguments it prints `REFUSED NO_LOAD_OP` and returns 3.
2. **`MAP`: two questions to the MMU.** `AT S1E2R` of the root port's configuration page and of the endpoint's: mapped in EL2's stage 1 or not,
   and with which attributes. It makes no access at them. **The answer is obeyed:** a device page the MMU says is unmapped, or maps as anything
   but Device (Normal memory in any cacheability, or an attribute that is not one of the four Device encodings), is never loaded from: a Normal
   mapping could fill a cache line around the register that was asked for, and no register of this set is known to be harmless to read around
   (INFERRED); an unmapped page would only fault. `rd()` refuses such a load before it reaches the runner, with code 126 (`REFUSED:126`).
3. **The headers** of the root port and of the endpoint: ids, command and status, class, header type, then the bridge's bus numbers and memory
   window or the endpoint's two BAR words, and the capability pointer. **The endpoint's header is read first, with no proof of the link:** it
   follows the port's directly, before the first `NEXT` and whatever the port says of the link, as the X2 image read it (its link row was only
   printed); only the endpoint's capability list waits for the port's `RP.LINK` line (step 4). They are the dwords the X2 image read at EL2
   (OBSERVED in one boot) but for the endpoint's `0x0c` and `0x34` (the table above). **The first gate** follows: both functions answer, the port
   is a bridge (class `0x0604`, header type 1), the endpoint is an NVM Express function (class `0x010802`, header type 0), and the bridge forwards
   the endpoint's bus (primary 0, secondary 1, subordinate at least 1).
4. **`NEXT CAPS AFTER 8 S`, eight seconds, then the capability lists**: the PCI Express capability of the port (its type, is the data link layer
   active, is the link training), then, **only after the port's `RP.LINK` line is printed**, the power management capability and the PCI Express
   capability of the endpoint (is it in D0). Each list is walked at most 16 times through pointers masked to dword offsets inside `0x40` to
   `0xff`, so a loop in it ends the walk, and the registers of a capability are read as soon as it is found (a read of the page that does not
   return ends the page: what the walk exists for must not wait behind the headers of the capabilities after it).
5. **The second gate, printed as one `GATE` line:** the link is proven up and not training, memory space is enabled in the endpoint **and in the
   bridge**, the endpoint is in D0, BAR0 is a 4 KiB aligned memory BAR (32 or 64 bit) inside the platform's window and inside the bridge's memory
   window, **no descriptor of usable RAM overlaps it**, and the MMU says its page is a mapped Device page. A refusal is a verdict, not a fault: the
   registers are then not read.
6. **`NEXT NVME_REGS AFTER 8 S`, eight seconds, then `CAP`, `CSTS`, `CC` and `VS`** of the next section, and their decode (`NVME`, `CAP`, `CTRL`),
   **printed before the next block is announced**. The first read that does not return a value stops the block: the registers after it print
   `NOT_ATTEMPTED`, and neither the second block nor anything of RAM is read. A controller that answers with all ones is not decoded
   (`CTRL ODD=ALL_ONES`) and the second block is not read.
7. **`NEXT NVME_AQ AFTER 8 S`, eight seconds, then `CSTS` again, `AQA`, `ASQ` and `ACQ`.** `CSTS` is a register Linux's driver reads and the first
   block has just read through the same page: if it does not return, or reads as all ones, nothing else of the block is read; if its ready, fatal
   or shutdown bits differ from the first reading the state is `TRANSITION`. The three registers after it are the ones only the X2 image has read.
8. **`NEXT ADMIN_QUEUES` (no wait: these are RAM words, not device registers), then the first two slots of each admin queue**, only if the
   controller is enabled, ready and not fatal, the queue sizes are plausible and the two pages are different, the memory map says each page is
   usable RAM and the MMU says it is mapped. The words of a slot are read **data first** (below).
9. **`VERDICT`** and **`DONE`**.

The `NEXT` lines and the waits are `el2mem`'s idiom: the line is drawn, the counter runs for eight seconds, then the reads that may stall the
board; a board that hangs leaves the block's name as the last line on the panel (INFERRED from the earlier boots of the other payloads). If the
counter cannot be used the block is announced, said to be skipped, and **never read**: `SKIPPED=NO_COUNTER` (no counter op),
`SKIPPED=COUNTER_UNUSABLE` (the counter stands still for two million reads, or goes back) or `SKIPPED=SPIN_BOUND` (the counter moves but the wait
did not end within 2^32 - 1 reads of it, which says nothing about the counter being dead). The bound is far above what eight seconds need at any
plausible loop speed: even at 10 ns a read, eight seconds are about 8 x 10^8 reads, a fifth of the bound (INFERRED: the loop speed is not measured
on the unit). Total loads: at most 80 on any page the host test can build (two headers of 7 dwords each, two capability walks of at most 16 steps
and their 5 registers, 11 words of controller registers, 18 words of queue entries); the payload's own cap is 400 and the runner's is 4096.

## The controller registers, in the order they are read

Two blocks, each behind its own `NEXT` line and wait. **The first load of a block is a register Linux's `nvme` driver reads** (`CAP`, then `CSTS`
again in the second block), so that a hang at that load says the page itself is dead and not that one register is odd
(INFERRED from memory of the driver: its source is not a file of this tree). Inside a block the order is by value, since the first abort of a window
ends the window: the state (`CSTS`, `CC`) comes before the version, which is only worth printing. **`AQA`, `ASQ` and `ACQ` come last, behind a second
reading of `CSTS`:** Linux's driver writes them and does not read them (INFERRED), and only the X2 image has read them on this unit (OBSERVED once).

<!-- nvmesnap-registers -->
| # | Block | Register | Offset | Words | What it says here (decoded as the NVMe Base Specification lays it out; INFERRED, the specification is not a file of this tree) |
| --- | --- | --- | --- | --- | --- |
| 1 | `NVME_REGS` | `CAP` | `0x00` | 2 | `MQES` 15:0, `CQR` 16, `TO` 31:24, `DSTRD` 35:32, `NSSRS` 36, `CSS` 44:37, `MPSMIN` 51:48, `MPSMAX` 55:52, `PMRS` 56, `CMBS` 57; read as two words, low first, as the X2 image read it |
| 2 | `NVME_REGS` | `CSTS` | `0x1c` | 1 | `RDY` 0, `CFS` 1 (fatal), `SHST` 3:2 (shutdown status); the state is decided from `CC` and `CSTS` together |
| 3 | `NVME_REGS` | `CC` | `0x14` | 1 | `EN` 0, `CSS` 6:4, `MPS` 10:7, `AMS` 13:11, `SHN` 15:14, `IOSQES` 19:16, `IOCQES` 23:20 |
| 4 | `NVME_REGS` | `VS` | `0x08` | 1 | the version, `MJR` 31:16, `MNR` 15:8, `TER` 7:0, printed as `VER=a.b.c` |
| 5 | `NVME_AQ` | `CSTS2` | `0x1c` | 1 | `CSTS` read a second time, printed as `CSTS2`: a failed or all-ones read stops the block; a change in bits 3:0 makes the state `TRANSITION` |
| 6 | `NVME_AQ` | `AQA` | `0x24` | 1 | `ASQS` 11:0 and `ACQS` 27:16, both zero based: printed as the entry counts `ASQE` and `ACQE`; a set reserved bit (15:12, 31:28) adds `ODD` |
| 7 | `NVME_AQ` | `ASQ` | `0x28` | 2 | the admin submission queue's address; two words, low first |
| 8 | `NVME_AQ` | `ACQ` | `0x30` | 2 | the admin completion queue's address; two words, low first |
<!-- /nvmesnap-registers -->

Nothing at or above offset `0x38` is read, and nothing is written: not `CC`, not a doorbell (they start at `0x1000`), not `CMBLOC`, not the
registers beyond `ACQ` whose existence `CAP` reports. A register is reported as `NAME=0X<value>`, `NAME=FAULT` (the guarded load aborted),
`NAME=REFUSED:<code>` (the op or this payload refused the address; code 127 is the payload's own guard for an address in no window, code 126 its
guard for a page the MMU did not approve, and the budget's code when the payload's load cap was reached) or `NAME=NOT_ATTEMPTED`. The
controller's state is `RUNNING` (`EN` and `RDY`), `DISABLED` (neither), `TRANSITION` (one of them, or the two readings of `CSTS` differ in bits
3:0), `FATAL` (`CFS`), `SHUTDOWN` (`SHST` not 0), `ALL_ONES` (a completed read of `CAP`, `CC` or `CSTS` that is all ones: a device that did not
answer, not a controller that is fatal and shut down) or `UNKNOWN` (`CC` or `CSTS` not read). `ALL_ONES` wins; then a difference in bits 3:0
between the two readings of `CSTS` is `TRANSITION` whatever the first reading said; otherwise fatal and shutdown win over the rest. A **failed read
is never reported as what it gates on:** a register that did not return is `REGISTERS_NOT_READ` (the first block) or
`AQ_REGISTERS_NOT_READ` (the second), and says nothing about the controller being absent or off; all ones is a completed read and is
`REGISTERS_ALL_ONES`.

## What it reads of PCIe configuration space

<!-- nvmesnap-config -->
| Group | Dwords (offsets in the function's 4 KiB page) | Stops when |
| --- | --- | --- |
| header | `0x00` id, `0x04` command and status, `0x08` class, `0x0c` header type, then `0x18` (type 1: bus numbers) and `0x20` (memory window) or `0x10` and `0x14` (type 0: BAR0, BAR1), then `0x34` if status bit 4 says there is a capability list | the id is `0xffffffff` or its vendor is `0xffff` (`ABSENT`); any read does not return |
| capability walk | the dword at each pointer, from the head `0x34` gave, until the PCI Express capability (and, for the endpoint, the power management capability) is found | 16 steps; a pointer outside `0x40` to `0xff`; a read that does not return |
| power management (endpoint only) | `+0x04` of the capability: `PMCSR`, whose bits 1:0 are the power state, read as soon as the capability is found | a read does not return |
| PCI Express capability | the first dword (its bits 23:20 are the device/port type), `+0x0c` link capabilities, `+0x10` link control (low half) and status (high half), read as soon as the capability is found | a read does not return |
<!-- /nvmesnap-config -->

The link is **proven up** only where the port is a root port (type 4) or a downstream port (type 6), its link capabilities (bit 20) say it reports
the data link layer, and its link status says the layer is active (bit 13) and the link is not training (bit 11). A port of another type, or one
that does not report the layer, leaves the link `UNPROVEN`: that the endpoint answers a configuration read is not accepted instead. On an endpoint
those bits are reserved and are not shown. **A decode that does not hold is marked, not dropped:** `RP.LINK` and `EP.LINK` print `TYPE=<n>` and
add `ODD` when the port's type is not 4 or 6, when it reports the data link layer and the layer is not active or the link is training, or when the
endpoint's type is not 0 (endpoint) or 1 (legacy endpoint); the speed and width mean something only where those hold. The bridge's memory space
(command bit 1) must be enabled as well as the endpoint's, since a bridge forwards nothing to its window otherwise: `GATE` prints `RPMEM`.

## The admin queues

Read only if `CC.EN` and `CSTS.RDY` are 1 and neither `CFS` nor `SHST` says otherwise (a controller that is not running holds addresses nobody
promised to keep), `AQA` names at least two and at most 4096 entries in each queue, and `ASQ` and `ACQ` are page aligned, below 2^48 and
different. Each page is asked of the memory map and of the MMU before the first word is read. Slots 0 and 1 are read (the unit's queues have two
entries; a longer queue is shown by its first two). **The words of a slot are read data first**, since a read of RAM that does not return ends every
read of RAM: a submission slot as `CDW0` (opcode, command id), `PRP1` (two words, low first), `NSID`, `CDW10` and `CDW11`; a completion slot as
`DW3` (command id, phase, status code and type), `DW2` (submission queue head and id) and `DW0`. They are printed in the usual order, and a fault
at a word names it and prints the words after it as `NOT_ATTEMPTED`.
**What this shows:** the opcode and the `PRP1` of the commands in the firmware's first two slots show where its DMA landed, and the completions show that the
controller answered (INFERRED: the pages may have been reused since). Nothing is written to either queue.

## Memory rules

The memory map is read in place, as `el2mem` does (`payloads/payload-mmu.h`: a map with a stride below 40 or not a multiple of 8, a size that
is not whole descriptors, a buffer that is unaligned or leaves the 48-bit space, or more than 1024 descriptors is refused and nothing of it
is read, and the gate says `MEMORY_MAP_UNREADABLE`).

* A queue page is read only if the **whole extent lies in a descriptor of type 1 to 7 or 9** (loader, boot services, runtime services,
  conventional and ACPI reclaim memory): not reserved memory, not unusable, not ACPI NVS, not memory-mapped I/O, not anything else.
* **Any descriptor that overlaps the extent and is not one of those types refuses it**, wherever it is in the map and whatever else holds the
  extent: a map that disagrees with itself is never read through. A descriptor that is unaligned, empty or beyond 48 bits is not used.
* **The controller's BAR is never RAM:** a descriptor of usable RAM over its registers refuses the read (`BAR0_IN_RAM`), and a map that cannot
  be read cannot say it is not (`MEMORY_MAP_UNREADABLE`).
* **One extent is open at a time**, exactly the bytes about to be read (128 for the submission queue's two slots, 32 for the completion
  queue's), and `rd()` refuses every other address: the two configuration pages, the 0x38 bytes of the controller's registers the second gate
  opened, and that extent.
* **The MMU is asked first and obeyed**, for the three device pages and for each queue page (RAM may be mapped as anything: only a missing
  mapping refuses it). The answer is EL2's stage 1 as the AT reports it, which is not a proof that a load will not fault.
* A read that does not return stops that function, that block or that queue for good; a fault in a submission queue ends every read of RAM.

## What it prints

<!-- nvmesnap-lines -->
| Line | Entries | When |
| --- | --- | --- |
| `START` | `CURRENTEL`, `FREQ`, `ECAM`, `WINDOW` | always |
| `REFUSED` | `NOT_AT_EL2` or `NO_LOAD_OP` | not at EL2, or no load op |
| `MAP` | `RP`, `EP`: the walk of each page (`DEVICE.NSH`, `WB.IS`, ... or `FAULT=<code>`); a page that is not `DEVICE...` or is a fault is not read | always |
| `RP`, `EP` | `ID`, `CMDSTS`, `CLASSREV`, `HDR`, `BUSES` and `MEMWIN` (port) or `BAR0` and `BAR1` (endpoint), `CAPPTR`; or `ID` and `ABSENT`; or `ID=REFUSED:126` | always (wraps); before the first `NEXT`, the endpoint's right after the port's |
| `NEXT` | `CAPS AFTER 8 S`, `NVME_REGS AFTER 8 S`, `NVME_AQ AFTER 8 S`, `ADMIN_QUEUES`; never dropped | before each block |
| `CAPS`, `NVME_REGS`, `NVME_AQ` | `SKIPPED=NO_COUNTER`, `SKIPPED=COUNTER_UNUSABLE` or `SKIPPED=SPIN_BOUND` | the wait could not be made |
| `RP.LINK`, `EP.LINK` | `LINK`, `ODD`, `TYPE`, `DLLA` and `LT` (only where the capability says the function reports them), `ASPM`, `LNKCAP`, `LNKCTLSTA`; or `PCIE=NONE` or `PCIE=NOT_READ` | after the first `NEXT`; the port's before the endpoint's capability list is read (the endpoint's header is read before that `NEXT`) |
| `EP.PM` | `PMCSR`, `D`; or `PM=NONE` or `PM=NOT_READ` | after the first `NEXT` |
| `GATE` | `LINK`, `RPMEM`, `MEM`, `BME`, `D`, `BAR0`, `MAP`, `WHY` | the first gate let the capabilities be read |
| `NVME` | `CAP`, `CSTS`, `CC`, `VS`, raw | after the second `NEXT` |
| `CAP` | `MQES`, `CQR`, `TO`, `DSTRD`, `NSSRS`, `CSS`, `MPSMIN`, `MPSMAX`, `PMRS`, `CMBS` | `CAP` was read and the controller did not answer all ones |
| `CTRL` | `VER`, `EN`, `RDY`, `CFS`, `SHST`, `CSS`, `MPS`, `AMS`, `SHN`, `IOSQES`, `IOCQES` (wraps); or `ODD=ALL_ONES` | the first block was read |
| `NVME.AQ` | `CSTS2`, `AQA`, `ASQ`, `ACQ`, raw | after the third `NEXT` |
| `AQ` | `ASQE`, `ACQE`, `ODD` (a reserved bit of `AQA` is set) | `AQA` was read |
| `ASQ`, `ACQ` | `AT`, `MEMMAP_TYPE` (or `NOT_IN_MAP`, `MAP_UNUSABLE`), `MAP`; or `NOT_READ` | after the fourth `NEXT` |
| `SQ0`, `SQ1` | `DW0`, `OPC`, `CID`, `NSID`, `PRP1`, `CDW10`, `CDW11` (wraps) | the submission page was read |
| `CQ0`, `CQ1` | `DW0`, `DW3`, `CID`, `P`, `SC`, `SCT`, `SQHD`, `SQID` (or `DW2` when it was not read) | the completion page was read |
| `VERDICT` | `CTRL`, `QUEUES`, `LINK`, `WHY`; never dropped | always |
| `DONE` | `NVME_GROUP_RAN` (the first block was announced, waited for and tried) or `NVME_GROUP_SKIPPED`, `LOADS`, `FAULTS`, `REFUSED`, `NVME_TRIED`, `SUPPRESSED` (only if lines were dropped); never dropped | always |
<!-- /nvmesnap-lines -->

At most 34 lines (the runner draws 40 per payload); the host test measures at most 33 over its worst world and its fuzz, and every line is at most
100 characters. The lines that are not essential are dropped, and counted in `SUPPRESSED`, once they would leave no room for the six that are
(the four `NEXT` lines, the verdict and the last line).

### What the host model prints

The page of the good world of the host test (`tools/test-q1n1-sp11-payload-nvmesnap.c`): a **made-up but self-consistent unit**, with values
chosen to tell fields apart (the endpoint's ids, the controller's `CAP` and the queue contents are NOT read from any unit; the observed unit's
values are in the first section). EXPERIMENTAL (host model only); every value was checked by hand against the scripted words.

<!-- nvmesnap-page -->
```
PAYLOAD NVMESNAP START CURRENTEL=0X8 FREQ=19200000 ECAM=0X70000000 WINDOW=0X70300000
PAYLOAD NVMESNAP MAP RP=DEVICE.NSH EP=DEVICE.NSH
PAYLOAD NVMESNAP RP ID=0X2221111 CMDSTS=0X100007 CLASSREV=0X6040001 HDR=0X10010 BUSES=0X10100
PAYLOAD NVMESNAP RP MEMWIN=0X73F07030 CAPPTR=0X40
PAYLOAD NVMESNAP EP ID=0XFEED1D1D CMDSTS=0X100406 CLASSREV=0X1080201 HDR=0X10 BAR0=0X70300004
PAYLOAD NVMESNAP EP BAR1=0X0 CAPPTR=0X40
PAYLOAD NVMESNAP NEXT CAPS AFTER 8 S
PAYLOAD NVMESNAP RP.LINK LINK=GEN4.X4 TYPE=4 DLLA=1 LT=0 ASPM=3 LNKCAP=0X100C44 LNKCTLSTA=0X20440043
PAYLOAD NVMESNAP EP.PM PMCSR=0X8 D=0
PAYLOAD NVMESNAP EP.LINK LINK=GEN4.X4 TYPE=0 ASPM=1 LNKCAP=0XC44 LNKCTLSTA=0X440041
PAYLOAD NVMESNAP GATE LINK=UP RPMEM=1 MEM=1 BME=1 D=0 BAR0=0X70300000 MAP=DEVICE.NSH WHY=NONE
PAYLOAD NVMESNAP NEXT NVME_REGS AFTER 8 S
PAYLOAD NVMESNAP NVME CAP=0X3100323C0301FF CSTS=0X1 CC=0X460081 VS=0X20100
PAYLOAD NVMESNAP CAP MQES=511 CQR=1 TO=60 DSTRD=2 NSSRS=1 CSS=0X1 MPSMIN=1 MPSMAX=3 PMRS=0 CMBS=0
PAYLOAD NVMESNAP CTRL VER=2.1.0 EN=1 RDY=1 CFS=0 SHST=0 CSS=0 MPS=1 AMS=0 SHN=0 IOSQES=6 IOCQES=4
PAYLOAD NVMESNAP NEXT NVME_AQ AFTER 8 S
PAYLOAD NVMESNAP NVME.AQ CSTS2=0X1 AQA=0X30003 ASQ=0X80100000 ACQ=0X80101000
PAYLOAD NVMESNAP AQ ASQE=4 ACQE=4
PAYLOAD NVMESNAP NEXT ADMIN_QUEUES
PAYLOAD NVMESNAP ASQ AT=0X80100000 MEMMAP_TYPE=7 MAP=WB.IS
PAYLOAD NVMESNAP SQ0 DW0=0X30006 OPC=0X6 CID=0X3 NSID=0X0 PRP1=0X80200000 CDW10=0X1 CDW11=0X0
PAYLOAD NVMESNAP SQ1 DW0=0X40005 OPC=0X5 CID=0X4 NSID=0X0 PRP1=0X80300000 CDW10=0X3F0001 CDW11=0X1
PAYLOAD NVMESNAP ACQ AT=0X80101000 MEMMAP_TYPE=7 MAP=WB.IS
PAYLOAD NVMESNAP CQ0 DW0=0X0 DW3=0X10003 CID=0X3 P=1 SC=0X0 SCT=0 SQHD=0X1 SQID=0X0
PAYLOAD NVMESNAP CQ1 DW0=0X0 DW3=0X10004 CID=0X4 P=1 SC=0X0 SCT=0 SQHD=0X2 SQID=0X0
PAYLOAD NVMESNAP VERDICT CTRL=RUNNING QUEUES=READ LINK=UP WHY=NONE
PAYLOAD NVMESNAP DONE NVME_GROUP_RAN LOADS=55 FAULTS=0 REFUSED=0 NVME_TRIED=8
```
<!-- /nvmesnap-page -->

How to read the page:

* `MEMMAP_TYPE` is the raw EFI memory type of the descriptor that holds the page: 4 boot services data, 7 conventional memory (types 1 to 7 and 9 may be read).
* The `CAP` exponents are not sizes: `MPSMIN` and `MPSMAX` n mean a page of 2^(12 + n) bytes and `DSTRD` n a doorbell stride of 2^(2 + n) bytes; `TO` is in 500 ms units and `MQES` is one less than the entry count.
* `REFUSED:126` means the MMU did not approve a Device page for the read (unmapped, or mapped as something else): nothing was loaded, and the device refused nothing.

### What QEMU shows

Behind the runner under QEMU's EDK2 shell (`tools/test-q1n1-sp11-payload-qemu-nvmesnap.py`: `virt` with 512 MiB of RAM, a real ExitBootServices
and a real EL2), the unit's PCIe addresses are nothing: EL2's stage 1 reports a translation fault for both configuration pages, so the payload
reads neither (the MMU's answer is obeyed), announces no group, reports `RP_NOT_READ`, and the runner counts no load. OBSERVED, QEMU 11.1.3,
EDK2, 6 lines, in a boot of `nvmesnap` alone and again with `smmuprobe` after it (the same page); EXPERIMENTAL, a model of nothing the unit does:

<!-- qemu-lines -->
```
PAYLOAD NVMESNAP START CURRENTEL=0X8 FREQ=<HZ> ECAM=0X70000000 WINDOW=0X70300000
PAYLOAD NVMESNAP MAP RP=FAULT=<FST> EP=FAULT=<FST>
PAYLOAD NVMESNAP RP ID=REFUSED:126 CMDSTS=NOT_ATTEMPTED CLASSREV=NOT_ATTEMPTED HDR=NOT_ATTEMPTED
PAYLOAD NVMESNAP EP ID=REFUSED:126 CMDSTS=NOT_ATTEMPTED CLASSREV=NOT_ATTEMPTED HDR=NOT_ATTEMPTED
PAYLOAD NVMESNAP VERDICT CTRL=UNKNOWN QUEUES=NOT_READ LINK=NA WHY=RP_NOT_READ
PAYLOAD NVMESNAP DONE NVME_GROUP_SKIPPED LOADS=0 FAULTS=0 REFUSED=2 NVME_TRIED=0
```
<!-- /qemu-lines -->

`<HZ>` and `<FST>` stand for the counter frequency and the fault status code the firmware gives, which are not stable across firmware builds.

## What each outcome means

The verdict is about **the SSD's link, endpoint and controller as the firmware left them at the moment of the read**. Each row names what the
takeover of the NVMe window does next. None of the outcomes authorises anything.

<!-- nvmesnap-decisions -->
| Verdict (reasons) | What it says | What it means for the takeover | What comes next |
| --- | --- | --- | --- |
| `CTRL=RUNNING`, `QUEUES=READ`, `LINK=UP` (`WHY=NONE`) | the controller is enabled and ready, the link is proven up, and the first two commands and completions of the admin queues are shown | the state the takeover must quiesce is the one the page shows: a running controller with the firmware's queues (`CC.EN` 1, `ASQ`, `ACQ` as printed); the `PRP1` of the commands says where the firmware's DMA went | compare with the observed unit's registers (first section); the takeover's design is not changed by one more reading |
| `CTRL=DISABLED`, `TRANSITION` (`QUEUES=NOT_ENABLED`) | the firmware left the controller not running, or half way (`EN` and `RDY` disagree), or `CSTS` changed in its ready, fatal or shutdown bits between the first reading and the second | there is no running state to adopt: the takeover must initialise the controller itself, and the stale queue addresses were not read | the owner's call whether the firmware's hand-off state is stable enough to design on |
| `CTRL=FATAL`, `SHUTDOWN` (`QUEUES=NOT_ENABLED`) | the controller reports a fatal status or a shutdown in progress or done | the SSD is not in a state to be taken over without a reset | stop; report; a reset is a write, which this series never makes without its own authorisation |
| `QUEUES=NO_QUEUES`, `BAD_ADDRESS`, `NOT_RAM`, `PAGE_UNMAPPED`, `FAULT` | the controller runs but its queue pages were not shown: sizes of fewer than two entries, an address that is zero, unaligned, beyond 48 bits or the same for both queues, memory that is not usable RAM in the map (`MEMMAP_TYPE` says what it is, or `NOT_IN_MAP`, or `MAP_UNUSABLE` for a map that cannot be read), a page the MMU does not map, or a read that did not return (a word `FAULT`, the words after it in the slot `NOT_ATTEMPTED`, no further slot, no further read of RAM) | the queues are not where the registers say, or are memory this payload may not read | a later payload that reads them only after the operator names the extent |
| `CTRL=UNKNOWN` or `RUNNING`, `QUEUES=NOT_READ` (`REGISTERS_NOT_READ`) | a register of the first block (`CAP`, `CSTS`, `CC`, `VS`) printed `FAULT` (the guarded load aborted) or `REFUSED:<code>`, and the registers after it `NOT_ATTEMPTED`; the state is `UNKNOWN` only if `CSTS` or `CC` was not read, and a `VS` that failed leaves it decoded | only the register that failed is known not to answer: **`CAP`, the first load, failing is the evidence that the controller's page cannot be read at EL2; a later failure after `CAP` read says that register only** (INFERRED: nothing here tells an abort of the register from one of the page) | a design question for the monitor (an unmapped page, a stage-2 abort EL2 cannot take), not a write; the `NVME` line shows which register was the last to answer |
| `CTRL=RUNNING` (or another decoded state), `QUEUES=NOT_READ` (`AQ_REGISTERS_NOT_READ`) | the first block was read and decoded, and `CSTS2` (the second reading), `AQA`, `ASQ` or `ACQ` printed `FAULT` or `REFUSED:<code>`, the ones after it `NOT_ATTEMPTED` | the state stands as the first block showed it; `CSTS2` failing right after the first reading answered says the page stopped answering, `AQA`, `ASQ` or `ACQ` failing says that register (the three Linux's driver never reads) | the `NVME.AQ` line shows which; no queue is read without all three |
| `CTRL=ALL_ONES`, `QUEUES=NOT_READ` (`REGISTERS_ALL_ONES`) | a completed read of `CAP`, `CC` or `CSTS` returned all ones (or `CSTS2`, the second time): `CTRL` says `ODD=ALL_ONES` and nothing is decoded; the second block and the queues are not read | nothing answered: not a controller that is fatal and shut down (INFERRED: all ones is what a root complex returns for a device that is not there or a link that dropped) | read `RP.LINK` and `GATE` again for what changed between the first reading and this one |
| `LINK=DOWN`, `UNPROVEN`, `NA` (`LINK_DOWN`, `LINK_TRAINING`, `LINK_UNPROVEN`, `NO_LINK_CAPABILITY`), `ODD` on `RP.LINK` | the port says the link is not up, is training, does not report whether it is up, is not a root or downstream port (`TYPE` says which), or its link registers were not read (`NA`) | the registers were not read: a read through a link that is not up could hang the bus (INFERRED) | read the `RP.LINK` line; an unproven link is the port's capability, not an SSD fault |
| `NOT_IN_D0`, `MEMORY_SPACE_OFF`, `BRIDGE_MEMORY_OFF` | the endpoint is in a low power state, or memory space is not enabled in it or in the bridge | the registers were not read: the device would not answer them, or the bridge would not forward the read | find out who left the SSD in that state (the firmware's hand-off); `GATE` shows `RPMEM`, `MEM`, `D` |
| `RP_ABSENT`, `RP_NOT_READ`, `RP_NOT_BRIDGE`, `EP_ABSENT`, `EP_NOT_READ`, `EP_NOT_NVME`, `BRIDGE_BUSES`, `CAPS_NOT_RUN`, `CAPS_NOT_READ`; on a header line `ABSENT`, `PCIE=NONE`, `PCIE=NOT_READ`, `PM=NONE`, `PM=NOT_READ` | the first gate or a capability read did not let the payload go on: a function that does not answer (`ABSENT`: all ones) or is not what the descriptor says, a bridge that does not forward bus 1, a configuration read that did not return, a capability list without the capability, or no counter | nothing of the controller was read | the `RP` and `EP` lines say which word; a `NOT_READ` after a `REFUSED:126` is the MMU's answer for the page |
| `BAR0_NOT_MEMORY`, `BAR0_UNALIGNED`, `BAR0_OUTSIDE_PLATFORM_WINDOW`, `BAR0_OUTSIDE_BRIDGE_WINDOW`, `BAR0_IN_RAM`, `MEMORY_MAP_UNREADABLE`, `BAR0_PAGE_UNMAPPED`, `BAR0_PAGE_NOT_DEVICE` | BAR0 is not a place this payload will read: not memory, not 4 KiB aligned, outside the platform's window or the bridge's, in usable RAM, or its page is unmapped or not a Device mapping | nothing of the controller was read | the `GATE` line shows `BAR0` and the walk of its page; the descriptor's window is the one to compare |
| `GROUP_SKIPPED` with `SKIPPED=NO_COUNTER`, `SKIPPED=COUNTER_UNUSABLE` or `SKIPPED=SPIN_BOUND` on the block's line | a wait could not be made: there is no counter op, the counter stood still or went back (`COUNTER_UNUSABLE`), or it moved but not enough in 2^32 - 1 reads (`SPIN_BOUND`: a slow counter, not a dead one) | the block was announced and never read; a skipped first block leaves `NVME_GROUP_SKIPPED`, a skipped second block leaves the first decoded | fix the counter question first (it is the runner's) |
| `SUPPRESSED=<n>` on the last line; a read `REFUSED` with the budget's code | the page budget dropped `<n>` lines that were not essential; or the payload's own load cap was reached and the read that would pass it was refused and not made | the shipped page and cap are never reached on a good page (33 of 34 lines in the worst case the tests build, at most 80 of 400 loads); a smaller page or cap is a test build | read the lines that remain; the `NEXT` lines, the verdict and the last line are never dropped |
| `NAME=NOT_ATTEMPTED`, `NAME=FAULT`, `NAME=REFUSED:126`, `NAME=REFUSED:127` on a line | `NOT_ATTEMPTED`: an earlier read of the same function, block or slot did not return; `FAULT`: the guarded load aborted; `REFUSED:126`: the MMU did not approve the page; `REFUSED:127`: the address is in no window (a bug of this payload, never a state of the unit) | the first `FAULT` or `REFUSED` of a function, block or slot is the only read that failed there | the line says which word; a fault on a later word leaves the words before it printed |
| `REFUSED NOT_AT_EL2`, `REFUSED NO_LOAD_OP` (returns 2, 3) | the payload does not run at EL2 or the runner gave it no load op | nothing was read | a runner question, not the unit's |
| the panel ends at `MAP` or `RP`, with no `NEXT` line after it | the read of the port's header (`MAP` is the last line) or of the endpoint's (`RP` is the last line) did not return or raised something the runner's guard could not take (INFERRED: this has not happened to this payload, which has never run); the header reads have no `NEXT` line and no wait before them, and are reads the X2 image made on the unit (OBSERVED once) but for the endpoint's `0x0c` and `0x34`; a line drawn just before a hang may not have been drawn in time to be seen | the PCIe root did not answer at EL2 a read that it answered in the X2 image's boot (UNKNOWN why); nothing is known of the link, the endpoint or the controller | nothing was written; power-cycle the board and boot the stick again, and report the last line on the panel |
| the panel ends at a `NEXT <block> AFTER 8 S` line (a hang), or on a q1n1 fault page, or the board resets after `DONE` | the read of that block did not return, or raised something the runner's guard could not take (INFERRED: this has not happened to this payload, which has never run); a reset after `DONE` is not this payload's | the last `NEXT` line names the block that was running; every line printed before it stands | **nothing was written, so there is nothing to undo: power-cycle the board and boot the stick again**, and report which `NEXT` line was last |
<!-- /nvmesnap-decisions -->

`LINK` in the verdict is `UP`, `DOWN`, `UNPROVEN` or `NA`. `WHY=NONE` with `QUEUES` other than `READ` means
the controller was read and the queues were not shown, for the reason `QUEUES` names.

## The next payload

If the controller is running and its queues were shown: nothing further is read of it. The monitor's SP11 takeover (UNIMPLEMENTED in Snapintosh
`compat/`: it has no native takeover, no record producer for the two blocks and no DMA proof) is designed from this page and from `smmuprobe`'s,
and only a supervised, separately authorised session may go on to anything that writes. If the controller cannot be read: the runner's `load32`
returns `FAULT` with no syndrome, so a later runner op that returns `ESR_EL2` after a fault (a runner change, not a payload) would say whether it
was a stage-1 translation fault, an external abort or a permission fault.

## Staging (not authorised)

`make -f platform/uefi/Makefile payloads` builds `nvmesnap.elf` and `nvmesnap.bin` with every other payload, and the manifest tool
(`tools/sp11_payload_manifest.py`) lists `NVMESNAP.BIN` like any other: it takes 8.3 names, and `NVMESNAP` has eight letters. `smmuprobe.bin` does
not fit it (`SMMUPROBE.BIN` has nine), so in a chain it is staged as a copy of the same bytes named `SMMUPRB.BIN`. The chain has `nvmesnap`
**before** `smmuprobe`: `smmuprobe`'s reads of the SMMU are the ones the X2 image already saw fault, and a read that hangs takes every earlier
line of the chain with it ([SP11-PAYLOAD.md](SP11-PAYLOAD.md#the-chain-several-payloads-in-one-boot), "Order"). Running it needs the operator's
explicit authorisation; this document, its tests and its build are not that authorisation. A run writes nothing to the internal disk, to a device
register or to the SMMU; what it does write is outside the payload: the stick's Shell script puts its marker file `SP11\DONE<n>.TXT` on the stick,
as every autorun step does, and the runner draws its page on the framebuffer.

**Rules for an authorised run.** Use the unit's own SSD in its socket and the stick booted as for X2 run 7: the endpoint's header is read with no
proof of the link, and an empty socket or another SSD has not been tried (UNKNOWN). Run on AC power or at 50 % battery or more, with one hardware
client. Film the panel continuously from `PAYLOAD CALL 0` until two minutes after `DONE`, or for ten minutes when there is no `DONE`. A silence
after a `NEXT` line is the wait of that block (eight seconds, and a slow counter can stretch it to minutes: INFERRED, 2^32 - 1 reads are about
7 minutes at 100 ns a read); the page is a hang after ten minutes with no new line after a `NEXT` line, or after a minute with none after `MAP`,
`RP` or `EP`, where no wait precedes the reads. **An asynchronous SError is neither caught nor printed:** q1n1 keeps `DAIF.A` masked
(`msr daifset, #15` at its entry points, `platform/uefi/entry.S`) and the runner's guard takes synchronous aborts only (`op_load32` in
`platform/uefi/sp11-payload-run.c`), so one would look like a hang, a q1n1 fault page or a reset after `DONE`.

## Planning a chain's page

The formula is the one of [the runner's planning table](SP11-PAYLOAD.md#the-chain-several-payloads-in-one-boot): `LOADED` for each file and
`READY` (files + 1), `VERIFY`, `CALL` and `DONE` for each payload (3), and the payload's own most lines, here its budget of 34 (the host tests
reach 33 and never pass 34; the runner draws at most 40 per payload).

<!-- nvmesnap-chain-budget -->
| Chain | Lines | Fits the unit's 89 rows | Fits the 60 the layout asks for |
| --- | --- | --- | --- |
| `nvmesnap` alone | (1 + 1) + 3 + 34 = 39 | yes | yes |
| `nvmesnap` and `smmuprobe` | (2 + 1) + 3 x 2 + 34 + 36 = 79 | yes | no |
| `el2mem`, `nvmesnap` and `smmuprobe` | (3 + 1) + 3 x 3 + 26 + 34 + 36 = 109 | no | no |
<!-- /nvmesnap-chain-budget -->

The third chain does not fit the unit's panel: `nvmesnap` is run alone or with `smmuprobe`.

## Tests

| Command | What it holds |
| --- | --- |
| `python3 tools/test-q1n1-sp11-payload-nvmesnap.py` | the host program (`tools/test-q1n1-sp11-payload-nvmesnap.c`, thirteen suites under ASan and UBSan: the good world's exact page and 55 loads in order, every reason the registers are not read, every kind of answer of the MMU for each page, a fault at each load (CSTS read twice: at either reading), every register decoded bit by bit against a table, all-ones and changing controllers, the order of the words of a queue slot, every memory map type and edge, the counter (three waits, one that dies at the second or the third, a slow one), the arguments, the line and load budgets, a fuzz against an oracle written another way), built again with a 14-line and a 10-line page, with load caps of 20 and 10, and with the bound on the reads of a wait lowered to 1000 (a counter that moves too slowly says `SPIN_BOUND`, a dead one `COUNTER_UNUSABLE`); 305 seeded-bug mutants, each rejected for its own reason, and an unmutated control; the source audit; the allow-list and the memory check on `nvmesnap.bin` with 31 seeded bad binaries (writes to a configuration page, to the controller and to a doorbell, unguarded reads of a register value, the controller's window and a queue word, every forbidden instruction) |
| `python3 tools/test-q1n1-sp11-payload-nvmesnap-doc.py` | this document against the source and the host test: the register table, the printed page, the reasons and states, every token the payload can print (the outcome table has a row for each), the evidence labels on the claims about the unit, the link targets, the sizes |
| `python3 tools/test-q1n1-sp11-payload-nvmesnap-refs.py` | the window and the SMMU of the device tree and the register offsets of the X2 image against the pinned copies (a SKIP, never a pass, in a tree without them) |
| `python3 tools/test-q1n1-sp11-payload-qemu-nvmesnap.py` | the binary behind the runner under QEMU's firmware, with a real ExitBootServices and a real EL2 (a SKIP without QEMU, its firmware or the toolchain) |

What the tests cannot show: what the unit does at these addresses, what an EL3 does with a read that hangs, whether a `load32` abort at a
controller register is recoverable, or what a real firmware's queues hold.

## What could not be verified

* **The NVMe field positions** are from the NVMe Base Specification, which is not a file of this tree: the decode is INFERRED, the raw words are
  printed, and the fields agree with the one unit that was read.
* **The PCI Express and power management capability layouts** (the device/port type in bits 23:20 of the first dword, `+0x0c` and `+0x10` of the
  PCI Express capability, link capabilities bit 20, link status bits 13 and 11, `PMCSR` at `+0x04` of the power management capability) are from
  the PCI specifications, not a pinned file (INFERRED).
* **What Linux's `nvme` driver reads and writes** (the reason for the order of the registers) is from memory of its source, which is not a file
  of this tree (INFERRED); it decides the order, not what a read does on this unit.
* **That this root port reports the data link layer** is UNKNOWN: if it does not, the link is `UNPROVEN` and the controller is not read.
* **That a read of the controller's registers does not change the controller** is INFERRED from the specification (they are not read-to-clear
  registers) and from the X2 image having read all seven once; `CSTS` is read twice, which the X2 image did not do.
* **The speed of the loop that waits** is not measured on the unit: the bound of 2^32 - 1 reads is about 5 times what eight seconds need at 10 ns
  a read and about 2.7 times at 5 ns (INFERRED); the stand-still test is two million identical reads.
* **What the PCIe SMMU does with the controller's DMA** is not read here (`smmuprobe`'s question); the queue contents say nothing about it.

## Residual risks

* **A read that hangs, not faults.** The runner's `load32` recovers an abort, not a hang; the `NEXT` lines, the eight seconds, the gates and the
  order (the controller after the configuration space, the queues last, each block starting with a register Linux reads and ending with the ones it
  never reads) are the only mitigation. What is new on this unit is listed in the first section (the endpoint's capability chain and two header
  dwords, the port's link capabilities, `CSTS` read a second time, the queue pages); the controller's other registers and the command words of the
  bridge and the endpoint were read, and the command words used as a gate, by the X2 image (OBSERVED once), so the risk is smaller than that of a
  first read of anything. The endpoint's header is read before any proof of the link (the X2 image did the same), and the headers have no `NEXT`
  line: a hang there leaves `MAP` or `RP` as the last line.
* **An SError is not seen.** The guard takes synchronous aborts only and q1n1 keeps `DAIF.A` masked, so an asynchronous error would show as a hang,
  a q1n1 fault page or a reset (INFERRED: nothing of the kind has been seen).
* **A hang loses what was not printed.** The lines of a block are printed when the block's reads are done; the `NEXT` line names the block, not the
  register, and the first block's decode is printed before the second is announced so that a hang in the second keeps it.
* **The decode is the specification's, not this controller's.** A different `CAP` layout would make the printed fields wrong; the raw words are
  printed so that the page can be re-read by hand.
* **The queues are shown as they are, not as the firmware sent them.** They are boot services memory (INFERRED): the loader may have reused the pages.
* **A refusal can be the whole answer.** If the firmware maps the PCIe windows as Normal memory, the pages are not read and the `MAP` line says so.

## Status

EXPERIMENTAL; hardware NOT RUN. Nothing in this document is VERIFIED for the unit.
