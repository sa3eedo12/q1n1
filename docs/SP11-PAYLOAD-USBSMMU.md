<!-- SPDX-License-Identifier: MIT -->
# SP11 payload `usbsmmu` (S0b): the stick's USB controller, the firmware's xHCI memory and the SMMU context bank

`payloads/usbsmmu.c` is one payload of the stick payload runner described in [SP11-PAYLOAD.md](SP11-PAYLOAD.md): the
manifest and the stick files, [the chain](SP11-PAYLOAD.md#the-chain-several-payloads-in-one-boot), ABI v1 and the
[line catalogue](SP11-PAYLOAD.md#line-catalogue) are defined there and not repeated. It is the read-only follow-up ("S0b") of
the S0 survey boot of the SP11 stick study (`docs/SP11-STICK-LOG.md` section 12 of the Snapintosh tree): it answers, with
**loads only**, whether an EL2 xHCI driver may let the xHC DMA into memory of its own, and where, without one write to the
SMMU. Evidence labels as there: VERIFIED (the architecture or a pinned file says so), OBSERVED (S0 showed it, once),
INFERRED, EXPERIMENTAL, UNIMPLEMENTED, UNKNOWN. **EXPERIMENTAL; hardware NOT RUN:** nothing of this payload is OBSERVED on
the unit; the values printed below are S0's where they are labelled so and a fixture's everywhere else.

## What it answers

S0 (OBSERVED once, 2026-11-14) read these at EL2, after the bounce, with loads only: the stick sits on `usb_1_ss0` (U0, MMIO
`0x0a600000`, size `0xfc100`); `usb_1_ss1` (U1, `0x0a800000`) was idle; both are readable. U0's xHC (xHCI 1.10, `CSZ` 1,
64 slots, 2 ports) is **halted** after ExitBootServices with `USBSTS` `0x1019` (HCH, EINT, PCD and **HCE**), where it read
`0x18` before; the cause of HCE is UNKNOWN. The firmware's xHCI structures are intact in RAM (DCBAA `0xCF412000`, event ring
segment table `0xCF415240`, event dequeue pointer `0xCF414CB8`, three slots behind a hub). `apps_smmu` (`0x15000000`, size
`0x100000`) has `ID0` `0x7C017E9A` and `sCR0` `0x230406`; the streams `0x1420` (U0) and `0x1460` (U1) match stream match
registers 3 and 4, both S2CR TYPE translate into **context bank 3, which nobody has read**. That is the open question
(stop criterion SC2 of the study), and this payload reads what can decide it:

1. what context bank 3 is (type, format, control, tables) and whether the walk of its stage-1 tables is possible;
2. whether it maps arbitrary DRAM identity (OA = IOVA), only the firmware's own xHCI memory, or nothing, by walking the tables
   in software for a handful of probe addresses; an EL2 xHCI driver may place its arena where the walk says it is mapped;
3. what the HCE tail looks like (the whole of `USBSTS`, the DWC3 bus-error address, the last event TRBs, the SMMU's fault
   registers), to look for its cause;
4. the topology of the **direct** connection the operator uses next: the firmware's slot contexts, with the stick plugged in
   without a hub.

## What it reads, and in what order

The groups are ordered by what a reset would cost: first what S0 proved readable, then RAM, then the registers nobody read,
then the walk. A `NEXT` line is printed **before** each group that reads something the unit has not been read for yet, so the
last line on the panel names what hung. A hang or reset in a context bank register is not recovered by anything here.

| Group | `NEXT` line | Reads | Why here |
| --- | --- | --- | --- |
| U0 | `NEXT U0` | the xHC registers of U0 and U1, then DWC3 of U0 | S0 read all of them but `GBUSERRADDR1` and `GDBGLTSSM` |
| SMMU | `NEXT SMMU` | `sCR0`, `ID0`, `ID1`, `ID2`, `sGFSR`, then `sGFAR` and `sGFSYNR0` to `2` only if `sGFSR` is not zero; the stream match registers up to `NUMSMRG`, then the S2CR of the entry each stream matched | S0 read all but `ID1`, `ID2`, `sGFAR`, `sGFSYNR` |
| RINGS | `NEXT RINGS` | `ERSTSZ`, `ERSTBA`, `ERDP`; then RAM only: the first segment table entry, the event TRBs, the DCBAA entries 1 to 8 and the device contexts | S0 read `ERSTBA`, `ERDP`, the DCBAA and the device contexts; new here: `ERSTSZ`, the segment table entry and the event TRBs; every RAM load is preceded by the memory-map check |
| CB | `NEXT CB<n>` | `CBAR`, `CBA2R` (global space 1), then the bank's own page: `SCTLR`, `TCR`, `TCR2`, `TTBR0`, `MAIR0`, `MAIR1`, `TTBR1`, `FSR` (`FAR`, `FSYNR0` only if `FSR` is not zero) | **never read on the unit**: the one real risk |
| WALK | `NEXT WALK` | RAM only: the translation table descriptors, four levels at most | after the bank's registers |

The banks are the ones the two streams' S2CR name (expected: 3, for both), never any other, and never one at or past `NUMCB`.
The walk follows the bank of the controller the stick is on (the first controller that is busy). A second bank, when the two
streams use different ones, is read but not walked. `NEXT WALK` is printed only when the bank is one the walk models: for any
other, nothing in RAM is read after the bank's registers and `WALK UNSUPPORTED` stands in its place.

## Safety rules

| Rule | How it is kept | Seeded bug the host test must reject |
| --- | --- | --- |
| Loads only, 4-byte aligned, at most 3000 (the ABI allows 4096) | every access goes through `load()`; the model fails on a misaligned or a 3001st load; the memory map is the runner's own memory and is read in place with plain C loads (not `load32` calls, so not counted) | (the model) |
| MMIO only inside the three windows, after the identity looked plausible; all ones or zero is "nothing there" and nothing more is read from that block | `rd32()` checks the window; `read_xhc()`, `group_dwc3()` and `read_smmu_global()` stop on an implausible block | window not checked; all ones not recognised; DWC3 ID not checked |
| An abort ends all reads of that window | `rd32()` marks the window dead | an abort that is not sticky |
| Only the bank(s) the streams match, below `NUMCB`; no other bank, no PAR, no RESUME, no register with a read side effect | `pick_banks()`; the allow-list of the model names every register that may be read | off by one at `NUMCB`; bank 2 for bank 3; every bank scanned |
| A RAM address from hardware or memory is loaded only if the UEFI memory map calls it usable RAM (types 1 to 7 and 9), at both ends of the word; Reserved, ACPI NVS, MMIO or unlisted is refused and named | `map_check()` before every RAM load; a map that makes no sense is no map | no check; Reserved or NVS taken for RAM; the last byte not checked; the descriptor count unbounded |
| Everything bounded: 8 slots, 31 endpoints, 256 stream match registers, 4 table levels, 1024 descriptors, 24 lines | constants; the walk descends only through a table descriptor, one level per step | a walk past level 3; slots unbounded |
| A `NEXT` line before the first access of its group | the model fails on an access before the line | each line printed after the read, or never |
| An unsupported format is a printed reason, never a guess | `WALK UNSUPPORTED <why>` with the raw registers; extended stream ids refused | a bank the walk does not model walked anyway |
| CurrentEL first; at any other EL one line and nothing else | `payload_entry()` | the check removed or widened |

## Registers

VERIFIED = the architecture or a pinned file says so: the xHCI 1.2 specification and q1n1's own `platform/uefi/xhci.c`, the
pinned Linux files (`arm-smmu.h`, `core.h`, `hamoa.dtsi` of the Snapintosh tree's `build/sp11-stick-log/refs/`) and the
SMMUv2 architecture. OBSERVED only for what S0 saw. The page of a context bank is `(NUMPAGE + n) * PAGESIZE` from the window
base (`arm-smmu.h`: `ARM_SMMU_CB(s, n) = numpage + n`), `NUMPAGE = 2^(NUMPAGENDXB + 1)`, `PAGESIZE` 4 KiB or, with `ID1.PAGESIZE`,
64 KiB; global space 1 is one `PAGESIZE` up.

<!-- usbsmmu-registers -->
| Register | Offset | Block | Evidence |
| --- | --- | --- | --- |
| `CAP_CAP0` | `0x00` | xHC capability | VERIFIED (xHCI 1.2: CAPLENGTH 7:0, HCIVERSION 31:16); S0 OBSERVED `0x01100020` |
| `CAP_HCSPARAMS1` | `0x04` | xHC capability | VERIFIED (slots 7:0, ports 31:24); S0 OBSERVED 64 slots, 2 ports |
| `CAP_HCCPARAMS1` | `0x10` | xHC capability | VERIFIED (CSZ bit 2); S0 OBSERVED `0x110FFC5`, CSZ 1 |
| `CAP_RTSOFF` | `0x18` | xHC capability | VERIFIED (bits 31:5); S0 OBSERVED `0x1000` |
| `OP_USBCMD` | `0x00` | xHC operational, from CAPLENGTH | VERIFIED (`xhci.c`); S0 OBSERVED 0 at EL2 (1 before ExitBootServices) |
| `OP_USBSTS` | `0x04` | xHC operational | VERIFIED (HCH 0, HSE 2, EINT 3, PCD 4, SSS 8, RSS 9, SRE 10, CNR 11, HCE 12; `xhci.c` has HCH and CNR); S0 OBSERVED `0x1019` after the bounce, `0x18` before |
| `OP_CRCR` | `0x18` | xHC operational, 64-bit | VERIFIED (`xhci.c`); S0 OBSERVED 0 |
| `OP_DCBAAP` | `0x30` | xHC operational, 64-bit | VERIFIED (`xhci.c`); S0 OBSERVED `0xCF412000` |
| `OP_CONFIG` | `0x38` | xHC operational | VERIFIED (MaxSlotsEn 7:0; `xhci.c`); S0 OBSERVED `0x40` on U0 (the firmware's), `0x0` on U1 |
| `OP_PORTSC(n)` | `0x400 + 0x10 * (n - 1)` | xHC port registers, n = 1, 2 | VERIFIED (CCS 0, PED 1, PLS 8:5, speed 13:10; `xhci.c` has CCS and PED); S0 OBSERVED `0xE03` and `0x81203` |
| `RT_ERSTSZ` | `0x28` | from RTSOFF: interrupter 0 + `0x08` | VERIFIED (`xhci.c`: ir0 + `ERSTSZ` 8, interrupter 0 at +`0x20`); never read on the unit |
| `RT_ERSTBA` | `0x30` | from RTSOFF: interrupter 0 + `0x10` | VERIFIED (`xhci.c`); S0 OBSERVED `0xCF415240` |
| `RT_ERDP` | `0x38` | from RTSOFF: interrupter 0 + `0x18` | VERIFIED (`xhci.c`; bits 3:0 are the segment index and EHB); S0 OBSERVED `0xCF414CB8` |
| `DWC3_GCTL` | `0xc110` | DWC3 of U0 | VERIFIED (`core.h:102`); S0 OBSERVED `PRTCAPDIR` 1 (host mode) |
| `DWC3_GSTS` | `0xc118` | DWC3 of U0 | VERIFIED (`core.h:104`); S0 OBSERVED `CURMOD` 1 (host) |
| `DWC3_GSNPSID` | `0xc120` | DWC3 of U0 | VERIFIED (`core.h:106`); S0 OBSERVED `0x33313130` |
| `DWC3_GBUSERRADDR0` | `0xc130` | DWC3 of U0 | VERIFIED (`core.h:110`); S0 OBSERVED no latched bus error |
| `DWC3_GBUSERRADDR1` | `0xc134` | DWC3 of U0 | VERIFIED (`core.h:111`); never read on the unit |
| `DWC3_GDBGLTSSM` | `0xc164` | DWC3 of U0 | VERIFIED (`core.h:123`); never read on the unit |
| `SMMU_SCR0` | `0x00` | apps_smmu global space 0 | VERIFIED (`arm-smmu.h`: USFCFG 10, EXIDENABLE 3, CLIENTPD 0); S0 OBSERVED `0x230406` |
| `SMMU_ID0` | `0x20` | global space 0 | VERIFIED (NUMSMRG 7:0, EXIDS 8, NUMSIDB 12:9); S0 OBSERVED `0x7C017E9A` |
| `SMMU_ID1` | `0x24` | global space 0 | VERIFIED (PAGESIZE 31, NUMPAGENDXB 30:28, NUMS2CB 23:16, NUMCB 7:0); never read on the unit |
| `SMMU_ID2` | `0x28` | global space 0 | VERIFIED; printed raw only; never read on the unit |
| `SMMU_GFAR` | `0x40` | global space 0, 64-bit | VERIFIED by the SMMUv2 architecture (not in the pinned header); only if `sGFSR` is not zero; never read on the unit |
| `SMMU_GFSR` | `0x48` | global space 0 | VERIFIED (`arm-smmu.h`); S0 OBSERVED 0 |
| `SMMU_GFSYNR0` | `0x50` | global space 0 (`+4` and `+8`: `sGFSYNR1` and `2`) | VERIFIED (`arm-smmu.h`); only if `sGFSR` is not zero; never read on the unit |
| `SMMU_SMR(n)` | `0x800 + 4n` | global space 0, n below `NUMSMRG` (at most 256) | VERIFIED (`arm-smmu.h`; valid bit 31, mask 31:16, id 15:0); S0 OBSERVED entries 3 and 4 matching |
| `SMMU_S2CR(n)` | `0xc00 + 4n` | global space 0, for the entries the streams matched | VERIFIED (`arm-smmu.h`; TYPE 17:16, CBNDX 7:0); S0 OBSERVED translate, bank 3 |
| `GR1_CBAR(n)` | `4n` | global space 1 | VERIFIED (`arm-smmu.h`; TYPE 17:16: 0 stage 2, 1 stage 1 with stage 2 bypass, 2 with stage 2 fault, 3 nested); never read on the unit |
| `GR1_CBA2R(n)` | `0x800 + 4n` | global space 1 | VERIFIED (`arm-smmu.h`; VA64 bit 0); never read on the unit |
| `CB_SCTLR` | `0x00` | context bank n | VERIFIED (`arm-smmu.h`; M bit 0); never read on the unit |
| `CB_TCR2` | `0x10` | context bank n | VERIFIED (`arm-smmu.h`); printed raw; never read on the unit |
| `CB_TTBR0` | `0x20` | context bank n, 64-bit | VERIFIED (`arm-smmu.h`; ASID 63:48, base 47:0); never read on the unit |
| `CB_TTBR1` | `0x28` | context bank n, 64-bit | VERIFIED (`arm-smmu.h`); never read on the unit |
| `CB_TCR` | `0x30` | context bank n | VERIFIED (`arm-smmu.h`: T0SZ 5:0, EPD0 7, TG0 15:14, EPD1 23); never read on the unit |
| `CB_MAIR0` | `0x38` | context bank n | VERIFIED (`arm-smmu.h`); never read on the unit |
| `CB_MAIR1` | `0x3c` | context bank n | VERIFIED (`arm-smmu.h`); printed only when not zero; never read on the unit |
| `CB_FSR` | `0x58` | context bank n | VERIFIED (`arm-smmu.h`); never read on the unit |
| `CB_FAR` | `0x60` | context bank n, 64-bit | VERIFIED (`arm-smmu.h`); only if `FSR` is not zero; never read on the unit |
| `CB_FSYNR0` | `0x68` | context bank n | VERIFIED (`arm-smmu.h`); only if `FSR` is not zero; never read on the unit |
<!-- /usbsmmu-registers -->

Not read on purpose: `PAR` (`0x50` of a bank, the result of an address translation operation), `RESUME`, the TLB and ATS
registers, `sCR2` (not needed), any other bank, any other window. The windows are VERIFIED as what the pinned `hamoa.dtsi`
says (`usb_1_ss0` at line 5256, `usb_1_ss1` at 5347, `apps_smmu` at 8438, the streams at 5307 and 5398); that the unit uses
them is INFERRED, and S0 read all three on this image (OBSERVED). The payload cannot see the GCC gate of a block or the
attribute of its own mapping at EL2 (it has no system register but CurrentEL): it relies on S0's OBSERVED reads of the same
windows, with the gate on, on the same image.

## What it prints

Lines are `KEY=0X..` style, upper case, in the page font, at most 100 characters, prefixed `PAYLOAD USBSMMU `. A value below
10 is one digit; a larger one is `0X` and the fewest hex digits; indices (slot, endpoint, bank, match register) are decimal.
At any EL but 2 the payload prints `PAYLOAD USBSMMU SKIPPED_NOT_AT_EL2` and nothing else. Both blocks are the host test's
fixture with S0's values where S0 read them (below). The first has the stick plugged in **directly** (the topology the
operator uses next, a fixture: one slot, route 0); the second has S0's topology with the hub, which costs two probes.

OBSERVED by S0 in them (`docs/SP11-STICK-LOG.md` section 12 of the Snapintosh tree): xHCI 1.10 with 64 slots, 2 ports and
64-byte contexts, `CAPLENGTH` `0x20`; on U0 `USBCMD` 0, `USBSTS` `0x1019`, `CRCR` 0, `DCBAAP`, `CONFIG` `0x40`, `PORTSC1`,
`PORTSC2`, `ERSTBA` and `ERDP`; on U1 `USBSTS` `0x1`, `DCBAAP` 0, `CONFIG` 0 and both ports in RxDetect; the DWC3 ID, host
mode (`PRTCAPDIR` 1, `CURMOD` 1) and no latched bus error; `ID0`, `sCR0`, `sGFSR` (no global fault), `NUMSMRG` and the two
streams; and, in the hub block only, the shape of the three firmware slots (configured, addresses 1 to 3, hub flag 0,
speeds, root ports, route string, the interrupt and bulk endpoint types and packet sizes; the stick's endpoints 2 and 5 are
what its observed bulk addresses `0x01` and `0x82` give). Made up by the host test's fixture: the words of `GCTL` and `GSTS`
(S0 has only the decoded facts), U1's `USBCMD` and port words (S0 has RxDetect), `GBUSERRADDR1`, `LTSSM`, `ID1`, `ID2`,
`ERSTSZ`, the segment table entry, the TRBs, the control endpoints and the interrupt endpoint indexes of the hub slots, every
context bank register, the page tables and so the whole walk.

<!-- direct-lines -->
```
PAYLOAD USBSMMU NEXT U0
PAYLOAD USBSMMU U0 CAPL=0X20 CMD=0X0 STS=0X1019:HCH.EINT.PCD.HCE CRCR=0X0 DCBAAP=0XCF412000 CFG=0X40
PAYLOAD USBSMMU U0 P1=0XE03:CCS.PED.U0.HS P2=0X81203:CCS.PED.U0.SS
PAYLOAD USBSMMU U1 IDLE CAPL=0X20 CMD=0X0 STS=0X1:HCH DCBAAP=0X0 P1=0X2A0:RXDET P2=0X2A0:RXDET
PAYLOAD USBSMMU DWC3 ID=0X33313130 GCTL=0X30C11004 GSTS=0X1 BERR=0X0 LTSSM=0X4009
PAYLOAD USBSMMU NEXT SMMU
PAYLOAD USBSMMU SMMU ID0=0X7C017E9A ID1=0X60800080 ID2=0X7555 SCR0=0X230406 GFSR=0X0
PAYLOAD USBSMMU SMMU SMRG=0X9A NCB=0X80 CBBASE=0X15080000 S1420=SMR3.TRANS.CB3 S1460=SMR4.TRANS.CB3
PAYLOAD USBSMMU NEXT RINGS
PAYLOAD USBSMMU RINGS CSZ=1 ERSTSZ=0X1 ERSTBA=0XCF415240 ERDP=0XCF414CB8 SEG0=0XCF414000/0X100
PAYLOAD USBSMMU TRB M1=PSC.1.0.1 M2=CMD.1.3.1 M3=XFER.1.3.1 AT=0.0.0.0
PAYLOAD USBSMMU U0S1 RT=0 RP=2 SPD=4 HUB=0 ST=3 AD=1 EP1=1.4.0X200 EP2=1.2.0X400 EP5=1.6.0X400
PAYLOAD USBSMMU NEXT CB3
PAYLOAD USBSMMU CB3 CBAR=0X10003 TYPE=S1_S2BYP CBA2R=0X1 VA64=1
PAYLOAD USBSMMU CB3 SCTLR=0X205F7 M=1 TCR=0X803F10 T0SZ=0X10 TG0=4K EPD0=0 TCR2=0X5
PAYLOAD USBSMMU CB3 TTBR0=0X40000A0000000 ASID=0X4 BASE=0XA0000000 MAIR0=0X4FF44 FSR=0X0
PAYLOAD USBSMMU NEXT WALK
PAYLOAD USBSMMU WALK IOVA=0XCF412000 OA=0XCF412000 LVL=2 BLOCK ATTR=0XFF.WB.ISH.RWU DCBAAP
PAYLOAD USBSMMU WALK IOVA=0XCF610000 OA=0XCF610000 LVL=2 BLOCK ATTR=0XFF.WB.ISH.RWU STACK
PAYLOAD USBSMMU WALK IOVA=0X880000000 OA=0X880000000 LVL=2 BLOCK ATTR=0XFF.WB.ISH.RWU CONVLO
PAYLOAD USBSMMU WALK IOVA=0X97FFFF000 OA=0X97FFFF000 LVL=2 BLOCK ATTR=0XFF.WB.ISH.RWU CONVHI
PAYLOAD USBSMMU WALK IOVA=0XCF414CB0 OA=0XCF414CB0 LVL=2 BLOCK ATTR=0XFF.WB.ISH.RWU ERDP
PAYLOAD USBSMMU WALK IOVA=0X80000000 OA=0X80000000 LVL=2 BLOCK ATTR=0XFF.WB.ISH.RWU RAMLO
PAYLOAD USBSMMU WALK SUMMARY PROBES=6 MAPPED=6 IDENTITY=6 FAULT=0 STOP=0
```
<!-- /direct-lines -->

<!-- hub-lines -->
```
PAYLOAD USBSMMU NEXT U0
PAYLOAD USBSMMU U0 CAPL=0X20 CMD=0X0 STS=0X1019:HCH.EINT.PCD.HCE CRCR=0X0 DCBAAP=0XCF412000 CFG=0X40
PAYLOAD USBSMMU U0 P1=0XE03:CCS.PED.U0.HS P2=0X81203:CCS.PED.U0.SS
PAYLOAD USBSMMU U1 IDLE CAPL=0X20 CMD=0X0 STS=0X1:HCH DCBAAP=0X0 P1=0X2A0:RXDET P2=0X2A0:RXDET
PAYLOAD USBSMMU DWC3 ID=0X33313130 GCTL=0X30C11004 GSTS=0X1 BERR=0X0 LTSSM=0X4009
PAYLOAD USBSMMU NEXT SMMU
PAYLOAD USBSMMU SMMU ID0=0X7C017E9A ID1=0X60800080 ID2=0X7555 SCR0=0X230406 GFSR=0X0
PAYLOAD USBSMMU SMMU SMRG=0X9A NCB=0X80 CBBASE=0X15080000 S1420=SMR3.TRANS.CB3 S1460=SMR4.TRANS.CB3
PAYLOAD USBSMMU NEXT RINGS
PAYLOAD USBSMMU RINGS CSZ=1 ERSTSZ=0X1 ERSTBA=0XCF415240 ERDP=0XCF414CB8 SEG0=0XCF414000/0X100
PAYLOAD USBSMMU TRB M1=PSC.1.0.1 M2=CMD.1.3.1 M3=XFER.1.3.1 AT=0.0.0.0
PAYLOAD USBSMMU U0S1 RT=0 RP=1 SPD=3 HUB=0 ST=3 AD=1 EP1=1.4.0X40 EP3=1.7.0X1
PAYLOAD USBSMMU U0S2 RT=0 RP=2 SPD=4 HUB=0 ST=3 AD=2 EP1=1.4.0X200 EP3=1.7.0X2
PAYLOAD USBSMMU U0S3 RT=3 RP=2 SPD=4 HUB=0 ST=3 AD=3 EP1=1.4.0X200 EP2=1.2.0X400 EP5=1.6.0X400
PAYLOAD USBSMMU NEXT CB3
PAYLOAD USBSMMU CB3 CBAR=0X10003 TYPE=S1_S2BYP CBA2R=0X1 VA64=1
PAYLOAD USBSMMU CB3 SCTLR=0X205F7 M=1 TCR=0X803F10 T0SZ=0X10 TG0=4K EPD0=0 TCR2=0X5
PAYLOAD USBSMMU CB3 TTBR0=0X40000A0000000 ASID=0X4 BASE=0XA0000000 MAIR0=0X4FF44 FSR=0X0
PAYLOAD USBSMMU NEXT WALK
PAYLOAD USBSMMU WALK IOVA=0XCF412000 OA=0XCF412000 LVL=2 BLOCK ATTR=0XFF.WB.ISH.RWU DCBAAP
PAYLOAD USBSMMU WALK IOVA=0XCF610000 OA=0XCF610000 LVL=2 BLOCK ATTR=0XFF.WB.ISH.RWU STACK
PAYLOAD USBSMMU WALK IOVA=0X880000000 OA=0X880000000 LVL=2 BLOCK ATTR=0XFF.WB.ISH.RWU CONVLO
PAYLOAD USBSMMU WALK IOVA=0X97FFFF000 OA=0X97FFFF000 LVL=2 BLOCK ATTR=0XFF.WB.ISH.RWU CONVHI
PAYLOAD USBSMMU WALK SUMMARY PROBES=4 MAPPED=4 IDENTITY=4 FAULT=0 STOP=0 CUTS=2
```
<!-- /hub-lines -->

| Line | Fields |
| --- | --- |
| `U0 CAPL= CMD= STS= CRCR= DCBAAP= CFG=` | `CAPLENGTH`, `USBCMD`, `USBSTS` as `0X<raw>:` and every set bit by name (`HCH` 0, `HSE` 2, `EINT` 3, `PCD` 4, `SSS` 8, `RSS` 9, `SRE` 10, `CNR` 11, `HCE` 12; any other `OTHER_0X<bits>`), `CRCR`, `DCBAAP`, `CONFIG`; a controller with no `DCBAAP` and no connection is one `U<i> IDLE` line without `CRCR` and `CFG` |
| `U0 P1= P2=` | `PORTSC` as `0X<raw>:` then `CCS`, `PED`, the link state (`U0` to `U3`, `DIS`, `RXDET`, `INACT`, `POLL`, `RECOV`, `HOTRST`, `COMPL`, `TEST`, `RESUME`) and the speed (`FS`, `LS`, `HS`, `SS`, `SSP`, else `SPD_<n>`) |
| `DWC3 ID= GCTL= GSTS= BERR= LTSSM=` | `GSNPSID`, `GCTL`, `GSTS`, the bus error address (`GBUSERRADDR1:GBUSERRADDR0`), `GDBGLTSSM`; a block whose ID is zero or all ones prints `UNREADABLE ID=` and is read no further |
| `SMMU ID0= ID1= ID2= SCR0= GFSR=` | the raw registers; `SMMU GFAR= GFSYNR0= GFSYNR1= GFSYNR2=` follows only when `GFSR` is not zero |
| `SMMU SMRG= NCB= CBBASE= S1420=...` | `NUMSMRG`, `NUMCB`, the address of bank 0's page, and per stream `S<id>=SMR<n>.<TRANS\|BYPASS\|FAULT\|RSVD>[.CB<n>[.BAD]][.MULTI<k>]`: the lowest stream match register that matches, what its S2CR does (`.S2CR_UNREAD` when that could not be read), the bank (`.BAD` when it is not below `NCB`), how many entries matched; `NOMATCH` when none; `STREAMS=UNSUPPORTED_EXID` with extended stream ids |
| `RINGS CSZ= ERSTSZ= ERSTBA= ERDP= SEG0=` | context size flag, the event ring registers, the first segment table entry as `<base>/<size in TRBs>` (`NO_ERST`, `BAD_SIZE/<n>`; an entry that cannot be read is `REFUSED=... AT=ERST`) |
| `TRB M1= M2= M3= AT=` | the three event TRBs before `ERDP` and the one at it, each `<type>.<completion code>.<slot id>.<cycle>`, the type by name for 32 to 39 (`XFER`, `CMD`, `PSC`, `BWR`, `DB`, `HC`, `DEVNOT`, `MFWRAP`); `SKIPPED=NO_SEG0` or `ERDP_NOT_IN_SEG0` when the first segment does not hold `ERDP` |
| `U0S1 RT= RP= SPD= HUB= ST= AD= EP<dci>=` | per non-zero DCBAA entry (at most 4 lines, `MORE=<n>` for the rest): route string, root port, speed ID, hub flag, slot state, device address, and each endpoint context that is not disabled as `EP<dci>=<state>.<type>.<max packet size>`; contexts are 64 bytes when `CSZ` is 1, else 32; a pointer that is not 64-byte aligned or not usable RAM is `CTX=0X.. REFUSED=...`, an endpoint context that cannot be read ends the line with `AT=EP` after the reason |
| `U0 SLOTS=<why>` | no slot line: `NO_DCBAAP` or `DCBAAP_MISALIGNED` (not 64-byte aligned), `NONE` (the entries 1 to 8, or to `CONFIG`, are all zero), `UNREAD` plus the reason (the DCBAA is not usable RAM) |
| `CB3 CBAR= TYPE= CBA2R= VA64=` | `TYPE` is `S2`, `S1_S2BYP`, `S1_S2FLT` or `NESTED` (a bank whose registers all read zero shows `S2` too: see `ALL_ZERO`) |
| `CB3 SCTLR= M= TCR= T0SZ= TG0= EPD0= TCR2=` | `TG0` is `4K`, `64K`, `16K` or `RSVD` |
| `CB3 TTBR0= ASID= BASE= MAIR0= [MAIR1=] FSR= [FAR= FSYNR0=] [TTBR1=]` | `BASE` (`TTBR0` without the ASID field) only when the ASID is not zero; `MAIR1` only when not zero; `FAR` and `FSYNR0` only when `FSR` is not zero; `TTBR1` only when not zero or enabled (`EPD1` clear); a second line only when the walk keeps its six lines |
| `WALK IOVA= OA= LVL= BLOCK\|PAGE ATTR= <ROLE>` | the mapping of one probe; `ATTR=<MAIR byte>.<WB\|NC\|WT\|DEV\|NRM>.<NSH\|OSH\|ISH>.<RO\|RW>[U][.NOAF]` is AttrIndx through MAIR, `SH`, `AP[2:1]` (`U`: user accessible) and `AF` |
| `WALK IOVA= FAULT LVL= <ROLE>` | a translation fault at that level, or outside the input size |
| `WALK IOVA= STOP=<why> LVL= <ROLE>` | `TABLE_NOT_IN_MAP`, `TABLE_TYPE_0X<t>` (a table in Reserved, ACPI NVS, MMIO ...), `TABLE_NO_MAP`: nothing was loaded from there; `TABLE_FAULT` (an abort), `TABLE_AFTER_FAULT`, `TABLE_BUDGET`, `TABLE_LOAD32` (the other failures of a load); `RESERVED_DESCRIPTOR` (a block where the granule has none, or a reserved level 3 encoding); `DEPTH` (four steps without an answer: unreachable by construction, a guard) |
| `WALK SUMMARY PROBES= MAPPED= IDENTITY= FAULT= STOP= [CUTS=]` | how many probes, how many mapped, how many with OA = IOVA; `CUTS` counts every field or line the budget dropped |
| `WALK UNSUPPORTED <why> CBAR= CBA2R= SCTLR= TCR= TTBR0=` | the reasons, in the order they are checked: `NOT_READ` (a register of the bank could not be read), `ALL_ZERO` (`CBAR`, `CBA2R`, `SCTLR`, `TCR` and `TTBR0` all read zero), `STAGE2_ONLY`, `NESTED`, `M0` (with `TRANSLATES_NOTHING INFERRED=BYPASS_LIKE`), `VA64_0`, `EPD0`, `TG0_RESERVED`, `T0SZ_RANGE` (16 to 39 are walked), `TTBR0_MISALIGNED`; nothing is walked, and the `CB` lines above print the rest of the bank |
| `<group> FAULT AT=<register>` | a guarded load aborted at that register; the window is read no further |
| `<group> REFUSED=<why> [AT=...]` | `NO_MAP` (the map is absent or contradicts itself), `NOT_IN_MAP`, `TYPE_0X<t>` (the descriptor type that is not usable RAM), `MISALIGNED`, `RANGE`, `AFTER_FAULT` (the window already aborted), `BUDGET` (the 3000 loads), `LOAD32` (the op answered an error that is not a fault) |
| `REFUSED_NO_LOAD32` | the runner gave no `load32` op: the payload returns the ABI's bad-arguments value and reads nothing |
| `U0 UNREADABLE WHY=ALL_ONES\|ZERO CAP0=` | the first capability word is all ones (nothing there) or zero: nothing more is read from that controller |
| `U0 NOT_XHCI CAP0= HCS1=` | the block answers, but CAPLENGTH, HCIVERSION, the slot count or the port count is not an xHC's: nothing more is read |
| `SMMU UNREADABLE ID0= SCR0=` | `ID0` is zero or all ones, or `sCR0` is all ones: the SMMU is read no further and no bank is chosen |
| `<group> SKIPPED=<why>` | the group had nothing to read: `U0_NOT_READ` (DWC3), `NO_XHC` (rings), `NO_SEG0` or `ERDP_NOT_IN_SEG0` (the TRB line), `NO_STREAMS` (CB), `NO_BANK` (walk) |

**The probes** are printed one per line with their role: `DCBAAP` (the firmware's DCBAA, which the xHC read by DMA, so it
must be mapped if the firmware set the bank up for it), `STACK` (q1n1's own payload stack), `CONVLO` and `CONVHI` (the first
and last page of the largest conventional region of the memory map), `RAMHI` (the last page of usable RAM, when it is not on
the page of `CONVHI`), `ERDP` (the firmware's event ring) and `RAMLO` (the first page of usable RAM). At most seven, one per
4 KiB page, in that order of priority.

## The line budget

At most **24 lines** whatever the hardware says, over every EL and every answer the host test scripts; the direct fixture
above prints exactly 24. Optional lines are granted in print order, each only if the minimum of the groups after it still
fits (`room()`; the reserves are 17 lines after the U0 group, 14 after the SMMU group, 10 after the rings and 4 after the
first bank): the second line of U1, the SMMU fault registers (only when `sGFSR` is not zero), the wrap of the stream line,
the slot lines after the first, the second line of the third CB block and a second bank. The probes take what is left and are
cut from the bottom of their list: at least four survive (two when a second bank is read). A field that does not fit is
dropped and counted in `CUTS`, never cut in half, and a 25th line is never emitted whatever a group asks for. At most
**3000 loads**: the host test's most is 405 (the ABI allows 4096).

| Group | Lines |
| --- | --- |
| U0: `NEXT U0`, U0 (2), U1 (1; 2 when busy and the budget allows), DWC3 | 5 or 6 |
| SMMU: `NEXT SMMU`, the raw registers, the fault registers (only if `sGFSR` is not zero), the streams (2 when long) | 3 to 5 |
| RINGS: `NEXT RINGS`, the ring registers, the TRBs, one to four slot lines | 4 to 7 |
| CB: `NEXT CB<n>` and three lines (a fourth only if the walk keeps its six lines); a second bank adds four | 4 to 9 |
| WALK: `NEXT WALK`, two to seven probes, the summary (or one or two `UNSUPPORTED` lines) | 4 to 9 |

In a chain, `usbsmmu` costs its 24 lines and the runner's three: [the planning table](SP11-PAYLOAD.md#the-chain-several-payloads-in-one-boot)
carries the maximum as a row and the chain `psci.bin usbsmmu.bin timer.bin` fits the unit's 89 rows.

## What the outcomes mean for the next step

**The bank.** What the CB lines and `WALK UNSUPPORTED` say about context bank 3:

<!-- usbsmmu-outcomes -->
| Printed | Means | Next step |
| --- | --- | --- |
| `TYPE=S1_S2BYP` or `TYPE=S1_S2FLT`, `VA64=1`, `M=1`, `EPD0=0`, the `WALK` lines | a stage-1 AArch64 bank with TTBR0 walks on: the walk below applies | read the probes |
| `WALK UNSUPPORTED ALL_ZERO CBAR=0X0 CBA2R=0X0 SCTLR=0X0 TCR=0X0 TTBR0=0X0` | every raw register of the bank reads zero: INFERRED RAZ/WI (a bank the non-secure world cannot see, or one nobody programmed), or the reads returned zeros for another reason; UNKNOWN who programs it although S2CR says TRANSLATE. This is not a statement that the bank translates nothing (that is `M0`) and not yet SC2 | UNKNOWN: decide with the S1 No-Op or by other means |
| `WALK UNSUPPORTED STAGE2_ONLY` or `NESTED` | stage 2 is involved; its tables are not walked here (INFERRED: they belong to whoever owns stage 2, the hypervisor); the `CB` lines print the raw `CBAR`, `CBA2R`, `SCTLR`, `TCR`, `TCR2`, `TTBR0` and `MAIR0`; UNKNOWN whether the arena is mapped | UNKNOWN: a stage-2 walker payload (VTCR-style `TCR`: T0SZ 5:0, SL0 7:6, TG0 15:14, PASize 18:16; descriptors as stage 1 but MemAttr 5:2, S2AP 7:6) or the S1 No-Op decides; SC2 applies only if a later walk shows the arena unmapped or the tables in memory the map does not call usable RAM |
| `WALK UNSUPPORTED M0 TRANSLATES_NOTHING INFERRED=BYPASS_LIKE` | the bank's stage 1 is off: it translates nothing (INFERRED: DMA passes untranslated; UNKNOWN for `S1_S2FLT`, which may fault everything) | only an attempted DMA tells (the S1 No-Op); a fault there is SC2 |
| `WALK UNSUPPORTED VA64_0`, `EPD0`, `TG0_RESERVED`, `T0SZ_RANGE`, `TTBR0_MISALIGNED` | a format the walk does not model; the raw `CBAR`, `CBA2R`, `SCTLR`, `TCR`, `TTBR0` are printed | decode by hand from them; UNKNOWN until then |
| `WALK UNSUPPORTED NOT_READ`, or `FAULT AT=<register>` in the CB lines | a register of the bank could not be read: the bank is not readable at EL2 (INFERRED: owned by the secure world); what it maps is UNKNOWN | UNKNOWN: read-only evidence ends here; only an attempted DMA (the S1 No-Op, which needs A1) can tell; SC2 applies only if that shows the DMA refused or redirected |
| `CB SKIPPED=NO_TRANSLATING_STREAM_BELOW_NCB` | no stream is a translating one below `NCB`: it is `BYPASS` (INFERRED: no translation in the way, the arena may be anywhere), `FAULT` (**SC2**), unmatched (`NOMATCH`: UNKNOWN, the SMR scan stops at 256), unread (`S2CR_UNREAD`) or names a bank at or past `NCB` (`.BAD`) | as said |
| `STREAMS=UNSUPPORTED_EXID`, `SMMU FAULT AT=...`, `SMMU UNREADABLE` | the SMMU is not read as expected: no bank is chosen | UNKNOWN: stop and read the raw lines |
<!-- /usbsmmu-outcomes -->

**The walk.** For a bank the walk models, what the probe lines say about where an EL2 xHCI driver may put its arena:

<!-- usbsmmu-walk-outcomes -->
| Probes | Means | Where the arena may live |
| --- | --- | --- |
| every probe mapped with `OA` = `IOVA` (`IDENTITY` = `PROBES`), `CONVLO`, `CONVHI`, `RAMLO` and `RAMHI` included | the bank maps the probed DRAM identity; with `LVL=1` or `2` blocks that is INFERRED to be all of DRAM, with `LVL=3` pages only the probed pages are known | **anywhere in DRAM** (SC2 is clear); use the `ATTR` the lines show; no SMMU write is needed |
| `DCBAAP` and `ERDP` mapped identity, the others `FAULT` or `STOP` | the bank maps only the firmware's xHCI memory | **inside the firmware's xHCI memory** (the boot-services data around the DCBAA and the rings), kept out of the allocator; its size is the page range the walk shows |
| mapped with `OA` different from `IOVA` | the firmware used an IOVA allocator: the xHC addresses are IOVAs, not physical addresses | program IOVAs whose `OA` is memory q1n1 owns; only the ranges the lines show are known |
| every probe `FAULT` | the bank maps none of them, `DCBAAP` included, which the xHC read by DMA (INFERRED: the mappings were torn down at ExitBootServices, which may also be what set HCE) | **SC2**: stop, or an SMMU write, which nothing here authorizes |
| `STOP=TABLE_TYPE_0X..` or `TABLE_NOT_IN_MAP` | the tables are in memory the map does not call usable RAM (a protected carve-out): they were not loaded | **SC2**: the mapping cannot be read; stop |
| `STOP=RESERVED_DESCRIPTOR` | a descriptor encoding no stage-1 table has: not the format the walk models, or garbage | UNKNOWN; read the registers by hand |
<!-- /usbsmmu-walk-outcomes -->

**HCE.** `USBSTS` `0x1019` has HCE (bit 12) set and HSE (bit 2) clear. What the other lines add (all INFERRED: HCE's cause is
UNKNOWN until they say):

<!-- usbsmmu-hce -->
| Printed | Reading |
| --- | --- |
| `STS=...HCE` without `HSE` (as S0) | an internal xHC error, not a DMA bus error the xHC itself reports; a DMA fault by the SMMU is not excluded |
| `DWC3 BERR=` not zero | the DWC3 latched a bus error at that address: an IOVA the SMMU or the fabric refused; compare with the `RINGS` addresses and the `WALK` probes |
| `SMMU GFSR=` not zero, with `GFAR` and `GFSYNR` | a global fault (for example an unidentified stream with `USFCFG`): the streams did not match as S0 saw |
| `CB3 FSR=` not zero, with `FAR` and `FSYNR0` | a translation fault in bank 3: the xHC DMA'd to an IOVA the bank does not map; `FAR` names it, and an address in the firmware's rings means the mapping was torn down under the xHC |
| `TRB` tail with an `HC` event (type 37) or a completion code that is not 1 | the xHC's own report of an error before it stopped; the codes are xHCI 1.2 section 6.4.5 |
| none of them | UNKNOWN: nothing this payload reads explains HCE; the controller may only need a reset, which this payload does not do |
<!-- /usbsmmu-hce -->

## In a chain

It goes after `psci` and before `timer`: `psci.bin usbsmmu.bin timer.bin`. It may hang or reset the board at `NEXT CB<n>`
(UNKNOWN, hardware NOT RUN), so `timer`, which may stall the board too, goes **last**. The planning table counts `psci` 30,
this payload 24, `timer` 16, the runner's three lines per payload and one per file:
(3 + 1) + 3 x 3 + 30 + 24 + 16 = 83 lines, six under the unit's 89 rows. `state` is left out of the unit's chain because
all four need (4 + 1) + 3 x 4 + 22 + 30 + 24 + 16 = 109 lines: past the 89 rows (QEMU's page has no such limit, and the
QEMU test runs all four).

## What QEMU shows

QEMU's `virt` machine has none of the three windows: the two USB windows lie in a hole of its memory map (the first guarded
load of each aborts), and the SMMU window lies inside its PCIe MMIO window, where unmapped loads answer all ones. Run at EL2
behind the runner (OBSERVED, QEMU 11.1.3, EDK2, 10 lines, `LOADS=4 FAULTS=2 REFUSED=0`), the payload prints:

<!-- qemu-lines -->
```
PAYLOAD USBSMMU NEXT U0
PAYLOAD USBSMMU U0 FAULT AT=CAP0
PAYLOAD USBSMMU U1 FAULT AT=CAP0
PAYLOAD USBSMMU DWC3 SKIPPED=U0_NOT_READ
PAYLOAD USBSMMU NEXT SMMU
PAYLOAD USBSMMU SMMU UNREADABLE ID0=0XFFFFFFFF SCR0=0XFFFFFFFF
PAYLOAD USBSMMU NEXT RINGS
PAYLOAD USBSMMU RINGS SKIPPED=NO_XHC
PAYLOAD USBSMMU CB SKIPPED=NO_STREAMS
PAYLOAD USBSMMU WALK SKIPPED=NO_BANK
```
<!-- /qemu-lines -->

and finishes with a normal `PAYLOAD DONE`: every load aborted or answered all ones and was reported as such, the runner
accepted every destination (no `REFUSED=LOAD32`), and `timer` after it ran to its end. That proves the binary runs at EL2
behind the runner, uses only its ops and fails closed on both kinds of nothing; it proves nothing about the unit's windows,
the memory-map checks on real descriptors or the walk, which only the host test exercises.

## Tests

* `tools/test-q1n1-sp11-payload-usbsmmu.c`, run by `tools/test-q1n1-sp11-payload-usbsmmu.py` under ASan and UBSan: a model
  of the three windows, RAM and the memory map that fails the run on any misaligned load, a 3001st load, a register outside
  its allow-list, a load in a window after an abort in it, a bank no stream selects, a RAM load the map does not call
  usable, or a load before its group's `NEXT` line; the exact lines of the two fixtures above; the walk against page tables
  built independently (4 KiB with four and three levels, 16 KiB, 64 KiB, blocks at levels 1 and 2, pages, holes, invalid and
  reserved descriptors, a table that points at itself, tables in Reserved, ACPI NVS, MMIO or outside the map, attributes);
  an abort at every load; thousands of units with hostile words; the memory map's own plausibility; the arguments and
  the exception levels.
* the same Python file seeds bugs in `usbsmmu.c`, each of which that program must reject, with an unmutated control; applies the
  allow-list of `tools/sp11_payload_testlib.py` to `usbsmmu.bin` (`MRS` of CurrentEL, no barrier, no SMC, at most 20480 bytes)
  and to the other three policies, with seeded bad binaries; audits the source for what it may touch (only the load op, the
  one MRS); and runs the manifest tool and the runner's validator on `psci usbsmmu timer`.
* `tools/test-q1n1-sp11-payload-usbsmmu-doc.py`: this document and its pointers in `SP11-PAYLOAD.md` against the source, the
  host test's own dump of the two fixtures above and each other, with seeded mistakes in the documents.
* `tools/test-q1n1-sp11-payload-qemu-usbsmmu.py`: the chains above under QEMU, with the lines of "What QEMU shows".

## Limits

The probes show where the bank maps a handful of addresses, not every address: a bank of 4 KiB pages can map the probes and
nothing else (INFERRED only for blocks). Only the first segment of the event ring is read. A second bank is read and not
walked; stage-2 and nested banks are not walked either (what they map is UNKNOWN, not SC2), nor is a bank that reads all zero.
The extended stream id format and the 32-bit formats are refused. The gate of the windows and the attribute of their
own mapping are not checked at EL2. Reading a context bank may hang or reset the board: nothing recovers it, and AC power or
50% battery, the thermal guard and one hardware client at a time apply as for every payload.
