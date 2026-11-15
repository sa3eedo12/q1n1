<!-- SPDX-License-Identifier: MIT -->
# SP11 payload `hashbig`: hash the biggest loaded file at EL2, and ask the MMU how its memory is mapped

`payloads/hashbig.c` is one payload of the stick payload runner described in [SP11-PAYLOAD.md](SP11-PAYLOAD.md): the manifest
and the stick files, [the chain](SP11-PAYLOAD.md#the-chain-several-payloads-in-one-boot), ABI v1 and the
[line catalogue](SP11-PAYLOAD.md#line-catalogue) are defined there and not repeated. Its companion is
[`el2mem`](SP11-PAYLOAD-EL2MEM.md), with which it shares the code that asks the MMU and reads the memory map
(`payloads/payload-mmu.h`) and which explains `AT S1E2R`, the decoding of `PAR_EL1` and the memory discipline of the binary check
once for both. Evidence labels as there: VERIFIED, OBSERVED, INFERRED, EXPERIMENTAL, UNIMPLEMENTED, UNKNOWN.
**EXPERIMENTAL; hardware NOT RUN.**

`hashbig` is **read only** and answers one question of the monitor port (the monitor-port document of the Snapintosh repository,
unknown U6): **the monitor's wrapper must verify its 115 to 144 MiB bundle itself, so how fast can a payload at EL2 hash a file
the runner loaded, is that file's memory mapped cacheable, and where did the firmware put it?** The runner hashes data files
before the bounce and only the payloads, the files named `.BIN`, again at EL2, because a data file can be hundreds of megabytes
([SP11-PAYLOAD.md](SP11-PAYLOAD.md), "What the next payloads need from this ABI"); nothing has measured what a plain-C
SHA-256 at EL2 costs there. **No value of this payload has been OBSERVED on the unit.** What the design rests on, OBSERVED on
earlier runs ([the results](SP11-PAYLOAD-RESULTS.md)): both payloads of boot 5, loaded at `0xCEC90000` and `0xCEA89000`, hashed
correctly at EL2 where the firmware put them, so memory the runner allocated below 4 GiB is readable after the bounce; whether
the same holds for a 144 MiB file, or above 4 GiB, is UNKNOWN.

## What it does, in order

1. **Where it runs.** `CurrentEL` and `CNTFRQ_EL0` (19.2 MHz is used if the frequency is outside 1 MHz to 1 GHz). Not at EL2 it
   prints `REFUSED NOT_AT_EL2` and returns 2 (`AT S1E2R` is UNDEFINED below EL2). The final memory map must pass the checks
   `el2mem` makes (`MAP_REFUSED <reason>`, return 3), and the arguments must carry the counter op.
2. **Which file.** The preload table (`a->preload_table`, `struct q1n1_preload_cache`) is checked: present, 8-byte aligned,
   inside the 48-bit space, its magic, version 1, entry size 312, a count of at most 16 and a size that holds the count
   (`TABLE_REFUSED NO_TABLE`, `BAD_HEADER` or `TABLE_OVERRUNS_ITS_SIZE`, return 4). Its **largest entry that is not a payload** is
   chosen; the first of equal sizes wins. An entry is skipped if its size is 0, if its base is this payload's own base, or if its
   path has no terminator within 256 bytes or ends in `.BIN` in any case after at least one character of name. No entry is left:
   `TABLE_REFUSED NO_DATA_FILE`, return 4. The line `FILE` says which: the table index, the base address the firmware put it at (U6),
   its size in bytes and in whole MiB.
3. **The extent.** The base is page aligned, the size is at least 1 byte and at most 256 MiB (the runner's own cap), the extent
   does not leave the 48-bit space, and **all of `[base, base + size)` lies inside descriptors of type 1 or 2** of the final map
   (`EfiLoaderCode` and `EfiLoaderData`: the memory the runner allocated; adjacent descriptors are followed). Otherwise
   `EXTENT REFUSED=<reason>` (return 5) and **nothing of the file is read**. `EXTENT ALLOCATED DESCRIPTORS=<n>` says how many
   descriptors the walk crossed.
4. **The attributes.** `AT S1E2R` at the first, the middle and the last page of the file, in one `ATTR` line (`WB.IS` is write-back
   inner-shareable, the cacheable case). A page that is not mapped refuses the hash (`REFUSED A_PAGE_OF_THE_FILE_IS_NOT_MAPPED`,
   return 7): the load would abort. **Device and non-cacheable mappings are reported and still hashed**: slow is the answer.
5. **The hash.** `NEXT SHA256 BOX=25 S`, then SHA-256 over the file in 64 KiB steps with plain loads, timed with the runner's
   counter. After every step the payload looks at the counter: **25 seconds** of counter time since the start end the loop
   (`TIMEBOX`), a counter that is behind its start ends it, and **256 looks in a row with the same value** (no tick in 16 MiB) end it
   as `COUNTER_STUCK`; a file is at most 256 MiB, so the loop ends by its own bound as well. A partial rate is still the answer.
6. **The verdict.** All 32 bytes of the digest are compared with the SHA-256 the runner computed before the bounce:
   `DIGEST <first 16 hex digits> MATCH`, or `DIFFER` with `WANT=<the runner's first 16>` (return 6). The last line is `DONE MATCH`,
   `DONE DIFFER`, `DONE TIMEBOX` or `DONE COUNTER_STUCK`; `TIMEBOX` and `COUNTER_STUCK` return 0 and print the bytes hashed so far.

Return values, which the runner shows in its `DONE` line:

<!-- hashbig-returns -->
| Return | Meaning |
| --- | --- |
| 0 | the digest matched, or the time box or a stuck counter ended the hash (a partial rate) |
| 1 | the argument block is bad (the ABI check every payload makes) |
| 2 | not at EL2 |
| 3 | the final memory map was refused |
| 4 | no usable preload table, or no data file in it |
| 5 | the extent of the file is not page aligned, not 1 byte to 256 MiB, beyond 48 bits, or not inside allocated descriptors |
| 6 | the digest differs from the runner's |
| 7 | a page of the file (first, middle or last) is not mapped at EL2 |
<!-- /hashbig-returns -->

**The SHA-256 is plain C written in the payload** (`payloads/payload-sha256.h`): no libc, no vector or crypto instruction (a payload is
built `-mgeneral-regs-only`), 64 round constants in a read-only table addressed relative to the code, and the eight initial words as
literals. The compression function is out of line, so the one place that reads the file in place is one function plus the byte copy of
the last partial block. The hardware SHA-256 instructions (`ID_AA64ISAR0_EL1` `0x1221111110212120`, OBSERVED on the unit, has `SHA2` 2 in
bits 15:12: INFERRED field position) are not used: this is the floor the monitor's wrapper can count on, and a faster path is a separate
decision (UNKNOWN whether the vector registers may be used from a payload).

It is checked against FIPS 180-4 vectors, against the runner's own `sha256.c` at every length around a block boundary, and against
Python's `hashlib` on random sizes and contents, and at the staged size of 144 MiB (150,994,944 bytes); the host test links the
payload's own code.

## What it may issue

The binary is checked by `tools/sp11_payload_testlib.py`, by the disassembly and by the encoding of every aligned word of its code,
with the memory discipline of `tools/sp11_payload_memcheck.py` ([`el2mem`](SP11-PAYLOAD-EL2MEM.md#memory-rules)). Its policy has
`read_only` and, as the only payload so far, **`bulk_reads`**: loads may use any base register, because it reads memory it was told
about (a loaded file) in place, and nothing may store through anything but the stack. The check proves that the loads through an
arbitrary base are in **exactly two functions**: the compression function and the copy of the tail. With `bulk_reads` removed from the
policy the binary is refused in exactly those two.

<!-- hashbig-instructions -->
| Kind | Operands allowed | Where | Why |
| --- | --- | --- | --- |
| `MRS` | `CurrentEL`, `CNTFRQ_EL0`, once each | `payload_entry` | where it runs; the counter frequency |
| `MRS` | `PAR_EL1`, once | `pl_at_s1e2r` | the answer of the `AT` |
| `AT` | `S1E2R`, one site, **no other form** | `pl_at_s1e2r` | asks the MMU, makes no access |
| `ISB` | one site | `pl_at_s1e2r` | `PAR_EL1` must not be read before the `AT` is done |
| loads | the stack, the image, the arguments and the pointers they hold (the map and the table) | everywhere | the discipline |
| loads | **any base** | the compression function and the tail copy only | the file, inside the extent that step 3 verified |
| stores | the payload's own stack only | everywhere | the discipline |
| `BL`, `BLR`, `B`, `RET` | `BLR` is the runner's ops (`puts`, `hex`, `counter`) | everywhere | the ABI |
<!-- /hashbig-instructions -->

Nothing else: no `MSR`, `DC`, `IC`, `TLBI`, `SYS`, no other `AT`, no `SMC`, `HVC`, `SVC`, `ERET`, `WFI`, `WFE`, `SEV`, no `DSB` or `DMB`,
no exclusive or atomic, and no `load32`. The binary is **9,412 bytes**, 2,127 instructions. The bytes of the file are read only inside the
verified extent: the tail of the last block is never read beyond the file's last byte.

## What it prints

At most **12 lines**, each at most 100 characters in the page font, every one beginning `PAYLOAD HASHBIG `. Values are printed as the
runner's hex op prints them (`0X` and capitals); `<walk>` is one AT answer as in [`el2mem`](SP11-PAYLOAD-EL2MEM.md#what-it-prints).
The last two lines the payload may print are reserved for the `NEXT` line and the last line, so a long report can never push them
out: another line that would leave less room is dropped and counted in `SUPPRESSED=` on the last line.

<!-- hashbig-lines -->
| Line | Meaning |
| --- | --- |
| `START CURRENTEL=0X.. FREQ=<n>` | the exception level and the counter frequency |
| `REFUSED NOT_AT_EL2` | CurrentEL is not EL2: nothing else was done (return 2) |
| `MAP_REFUSED STRIDE_BELOW_40` / `STRIDE_NOT_A_MULTIPLE_OF_8` / `SIZE_NOT_WHOLE_DESCRIPTORS` / `BUFFER_OUT_OF_RANGE` / `TOO_MANY_DESCRIPTORS` | the final map was not read, and why (return 3) |
| `TABLE_REFUSED NO_TABLE` / `BAD_HEADER` / `TABLE_OVERRUNS_ITS_SIZE` / `NO_DATA_FILE` | the preload table cannot be used, or holds no data file (return 4) |
| `FILE INDEX=<n> BASE=0X.. BYTES=<n> MIB=<n>` | the file chosen: its index in the table, where the firmware put it, its size |
| `EXTENT REFUSED=BASE_NOT_PAGE_ALIGNED` / `SIZE_ZERO_OR_OVER_256_MIB` / `BEYOND_THE_48_BIT_SPACE` / `NOT_IN_ALLOCATED_DESCRIPTORS` + ` AT=0X..` | the extent was refused (return 5); for the last reason, the first address that is in no allocated descriptor |
| `EXTENT ALLOCATED DESCRIPTORS=<n>` | the whole file is inside allocated descriptors, crossing this many |
| `ATTR FIRST=<walk> MID=<walk> LAST=<walk>` | the AT answer for the first, the middle and the last page of the file |
| `REFUSED A_PAGE_OF_THE_FILE_IS_NOT_MAPPED` | one of those pages is not mapped at EL2 (return 7) |
| `NEXT SHA256 BOX=25 S` | the hash starts now and ends by 25 seconds of counter time |
| `HASH BYTES=<n> TICKS=<n> MS=<n> MIBS=<n>` | the bytes hashed, the counter ticks, whole milliseconds, whole MiB per second (`RATE=UNKNOWN_COUNTER` in place of the last two if no tick passed or the count is beyond 2^43) |
| `DIGEST <16 hex digits> MATCH` / `DIFFER` + ` WANT=<16 hex digits>` | the first eight bytes of the digest, and the verdict over all thirty-two |
| `TIMEBOX HASHED=<n> OF <n> TICKS=<n>` / `COUNTER_STUCK HASHED=<n> OF <n> TICKS=<n>` | the hash did not finish: how much was hashed, of how much, in how many ticks |
| `DONE MATCH` / `DIFFER` / `TIMEBOX` / `COUNTER_STUCK` + ` SUPPRESSED=<n>` | the last line, and the lines dropped |
<!-- /hashbig-lines -->

**A normal run**, as the host model prints it (8 lines; the values are the model's, **not** a unit's: a 4 MiB file at an address made up
for the example, mapped write-back inner-shareable, hashed by a model clock of 65,000,000 ticks; EXPERIMENTAL):

<!-- hashbig-page -->
```
PAYLOAD HASHBIG START CURRENTEL=0X8 FREQ=19200000
PAYLOAD HASHBIG FILE INDEX=2 BASE=0XCF000000 BYTES=4194304 MIB=4
PAYLOAD HASHBIG EXTENT ALLOCATED DESCRIPTORS=1
PAYLOAD HASHBIG ATTR FIRST=WB.IS MID=WB.IS LAST=WB.IS
PAYLOAD HASHBIG NEXT SHA256 BOX=25 S
PAYLOAD HASHBIG HASH BYTES=4194304 TICKS=65000000 MS=3385 MIBS=1
PAYLOAD HASHBIG DIGEST D91313D6FDEC24D7 MATCH
PAYLOAD HASHBIG DONE MATCH
```
<!-- /hashbig-page -->

The most lines the host tests measure over every world they script is 8; the budget is 12 so that a wrapped `ATTR` line or a `DIFFER`
cannot push the last line out.

## What each outcome means for the monitor

INFERRED throughout: nothing below has been observed on the unit. The "next step" is a proposal for a separate, authorized change,
never something this payload does.

<!-- hashbig-decisions -->
| Outcome on the page | What it means | Next step |
| --- | --- | --- |
| `HASH BYTES=150994944 ... MIBS=<n>` and `DIGEST ... MATCH` | a plain-C SHA-256 at EL2 hashes the 144 MiB at `MIBS` MiB/s: 144 / `MIBS` seconds; at 6 or more that is within the 25-second box and a boot-time check of the bundle is affordable | the wrapper may verify its bundle itself with this code; the number sizes the boot delay |
| `TIMEBOX HASHED=<n> OF <n>` with a `HASH` line | the box ended before the file did; the `HASH` line gives the rate over the part hashed (still the answer): the whole file would take about 144 / `MIBS` seconds | decide whether that delay is acceptable; if not, the hardware SHA-256 instructions or a smaller bundle are the options (separate decisions); no result is lost |
| `ATTR FIRST=WB.IS MID=WB.IS LAST=WB.IS` | the loaded file is Normal write-back inner-shareable: cacheable, the fast case | none |
| `ATTR ... NC ...` or `DEVICE` | the file's memory is non-cacheable or Device at EL2: reads are uncached (INFERRED: several times slower) | the wrapper must copy the bundle to cacheable memory before it works on it, or accept the rate shown |
| `ATTR` entries that differ (`FIRST` against `LAST`) | the file spans mappings with different attributes | the monitor must not assume one attribute for a bundle |
| `ATTR ... NONIDENT` or `.NS1` | the output page is not the input page (the map is not an identity map there), or the NS bit is set (its meaning is UNKNOWN; QEMU shows it set) | the wrapper's address arithmetic must not assume identity |
| `FILE ... BASE=0X..` below `0X100000000` / in `0X880000000` and above | where the firmware put a 144 MiB file: in the low extents or in the bank (U6) | decides where the loader may expect a big block, and how much of the bank the runner already uses |
| `EXTENT REFUSED=NOT_IN_ALLOCATED_DESCRIPTORS AT=0X..` | part of the file is in memory the map does not call allocated (a hole, or another type): the runner's placement or the map does not agree | the wrapper cannot trust the runner's placement; compare the descriptor at `AT` with the earlier boots' maps |
| `EXTENT REFUSED=BASE_NOT_PAGE_ALIGNED`, `SIZE_ZERO_OR_OVER_256_MIB` or `BEYOND_THE_48_BIT_SPACE` | the table's entry is not one the runner could have built: it allocates whole pages, at most 256 MiB, inside the address space | a runner bug or a changed ABI: stop; nothing of the file was read |
| `REFUSED A_PAGE_OF_THE_FILE_IS_NOT_MAPPED` | EL2's stage-1 lacks a page of the loaded file after the bounce | the monitor cannot read its bundle in place at EL2 without a map of its own: the central finding of U6 |
| `DIGEST ... DIFFER WANT=...` | the file changed between the runner's hash before the bounce and now (the bounce, a copy, memory that was not preserved), or the hash code is wrong (the host tests say it is not) | the bundle cannot be verified at EL2 as the runner leaves it; which bytes differ is not shown (a separate payload could bisect) |
| `TABLE_REFUSED NO_DATA_FILE` | the manifest lists no data file | stage the file and run again; nothing was read |
| `TABLE_REFUSED BAD_HEADER` / `TABLE_OVERRUNS_ITS_SIZE` / `NO_TABLE` | the preload table is not what the runner builds | a runner bug or a changed ABI: stop |
| `MAP_REFUSED <reason>` | the final map the runner passed is not one the payload reads | the map itself is the finding (return 3) |
| `COUNTER_STUCK` | 256 looks, 16 MiB, without a tick: the counter does not run | no rate can be had from this payload; the result of the hash up to there stands |
| `RATE=UNKNOWN_COUNTER` | no tick passed, or the count is beyond 2^43: no rate | as above |
| the page ends at `NEXT SHA256 BOX=25 S` | a hang or a reset inside the hash: a read of the file that neither answered nor aborted (INFERRED: a hole the three-page AT check did not see aborts into q1n1's fault page instead) | photograph the page, power-cycle; the file's `BASE` and `BYTES` are on the page |
| a q1n1 fault page after `NEXT SHA256 BOX=25 S` | a page between the three the payload asked about is not mapped, and the load aborted; `FAR` says which | stop; this is a finding about the map, not about the hash |
| `SUPPRESSED=<n>` on the last line | the page budget dropped `<n>` lines | read what is there; the `NEXT` line and the last line are never dropped |
<!-- /hashbig-decisions -->

## What QEMU shows

OBSERVED, QEMU 11.1.3 (`virt,virtualization=on`, `-cpu max`, `-smp 1`, TCG, EDK2 AArch64), once per run of
`tools/test-q1n1-sp11-payload-qemu-el2mem.py`: the payload runs at EL2 behind the runner after a real `ExitBootServices`, alone and
in the chain, finds the data file the runner loaded (1 MiB and 4,093 bytes of fixed pseudo-random bytes, not 144 MiB: QEMU reads a FAT
directory slowly, and what 144 MiB takes on the unit is the question the unit has to answer), checks its extent against the final map,
asks the MMU about its pages and says `MATCH` with **the digest Python's `hashlib` computes for the same bytes** and the runner computed
before the bounce. The address and the rate vary from run to run: the test asserts the shape and the cross-checks.

<!-- hashbig-qemu -->
```
PAYLOAD HASHBIG START CURRENTEL=0X8 FREQ=1000000000
PAYLOAD HASHBIG FILE INDEX=1 BASE=0X5C048000 BYTES=1052669 MIB=1
PAYLOAD HASHBIG EXTENT ALLOCATED DESCRIPTORS=1
PAYLOAD HASHBIG ATTR FIRST=WB.IS.NS1 MID=WB.IS.NS1 LAST=WB.IS.NS1
PAYLOAD HASHBIG NEXT SHA256 BOX=25 S
PAYLOAD HASHBIG HASH BYTES=1052669 TICKS=17419000 MS=17 MIBS=57
PAYLOAD HASHBIG DIGEST 2E86FE97C8CD65D7 MATCH
PAYLOAD HASHBIG DONE MATCH
```
<!-- /hashbig-qemu -->

A stick with `HASHBIG.BIN` and no data file ends, as asserted, after `PAYLOAD HASHBIG START ...` with
`PAYLOAD HASHBIG TABLE_REFUSED NO_DATA_FILE`, and the runner's `DONE` line shows `RETURN=0X4`. What the test checks beyond the shape:
the file's base and size are the ones the runner reported on its `LOADED` line; the digest is the runner's and `hashlib`'s; `MS` and
`MIBS` are the arithmetic of `TICKS` and the counter frequency the runner printed; the three pages of the file are mapped; the runner
counted the lines and dropped none; no file on the stick changed.

**What QEMU cannot show**, UNKNOWN on the unit: how fast the unit hashes (TCG speed says nothing: 57 MiB/s here), the attributes of a
144 MiB file, where the firmware puts it, whether a page in the middle of it is mapped, and what `NS` means.

## The proposed staging plan (not run)

The plan is the coordinator's and is the same as in [`el2mem`](SP11-PAYLOAD-EL2MEM.md#the-proposed-staging-plan-not-run): one boot, three
files, the manifest listing `EL2MEM.BIN`, `HASHBIG.BIN` and `BIG.DAT` of 144 MiB (150,994,944 bytes), run through `Q1N1-PAYLOAD.EFI --el2`
under `SLBOUNCE-DEVHE-MARK.EFI`. `hashbig` hashes `BIG.DAT` because it is the largest file that is not a payload.

<!-- hashbig-staging -->
```sh
dd if=/dev/urandom of=BIG.DAT bs=1048576 count=144
python3 tools/sp11_payload_manifest.py --out-dir build/stick build/uefi/payloads/el2mem.bin build/uefi/payloads/hashbig.bin BIG.DAT
load SP11\SLBOUNCE-DEVHE-MARK.EFI
SP11\Q1N1-PAYLOAD.EFI --el2
```
<!-- /hashbig-staging -->

The runner's own limits allow it (at most 5 files, each at most 256 MiB); slbounce splits a declared range into chunks of the 1 MiB
cap q1n1 declares, at most 256 of them for a range, so a 144 MiB file takes 144. Whether the whole sweep, the image, the map, the table and
the three payload ranges fit slbounce's budget with that file is INFERRED from the runner's document and was not tried; a refusal before
the bounce leaves the stick as it was.

**Proposed stop rule.** One boot. `hashbig` is read only and bounded (25 seconds of counter time, 256 MiB at the most), so a page that
ends after `NEXT SHA256 BOX=25 S`, or a board that resets during it, is a finding to photograph and not to retry as it is. `TIMEBOX`,
`DIFFER`, every `REFUSED` and every `TABLE_REFUSED` are results, not stops.

OBSERVED (a restart control of 2026-11-16, reported to this work; no page of it is in this tree): the runner flow with a read-only PSCI
payload alive at `UPTIME` 224 S and 268 S in two boots. A long-running read-only payload, which this one may be for up to its 25 second
box, is not expected to restart the board by itself.

## Tests

Hardware: NOT RUN. Every command writes only under `build/`.

| Command | What it runs |
| --- | --- |
| `python3 tools/test-q1n1-sp11-payload-hashbig.py` | the host program `tools/test-q1n1-sp11-payload-hashbig.c` (twelve suites over a modelled machine: the FIPS vectors, every block-boundary size against the runner's `sha256.c`, which file is chosen, every refusal of the table, the extent, the map and the arguments with the file's memory made `PROT_NONE` where nothing may be read, Device and non-cacheable and unmapped pages, a corrupted file, the 25-second box, a counter that stands still or goes back, random worlds) under ASan and UBSan; the payload's SHA-256 against `hashlib` on random sizes and at 144 MiB; 46 seeded-bug mutants in `hashbig.c` and `payload-sha256.h`, each of which it must reject; the allow-list on the binary with 13 seeded bad binaries, and the loads through any base confined to two functions; the source audits |
| `python3 tools/test-q1n1-sp11-payload-memcheck.py` | the policy engine and its memory checker, as for `el2mem` |
| `python3 tools/test-q1n1-sp11-payload-qemu-el2mem.py` | the QEMU boots above, and `el2mem`'s |
| `python3 tools/test-q1n1-sp11-payload-mmu-doc.py` | this document and the `el2mem` one against the sources, the host models, the binaries and the chain arithmetic, with seeded mistakes in each document |
| `python3 tools/test-q1n1-sp11-payload-build.py` | `make payloads` builds `hashbig.bin`, the ELF check, the allow-list of every payload, two builds byte-identical |
| `python3 tools/test-q1n1-sp11-payload-hashbig.py facts` | the size, digest and instruction inventory of the built binary |

## Planning a chain's page

The formula is the one of [the runner's planning table](SP11-PAYLOAD.md#the-chain-several-payloads-in-one-boot): `LOADED` for each file
and `READY` (files + 1), `VERIFY`, `CALL` and `DONE` for each payload (3), and the payload's own most lines, here its budget of 12 (the
host tests measure 8).

<!-- hashbig-chain-budget -->
| Chain | Lines | Fits the unit's 89 rows | Fits the 60 the layout asks for |
| --- | --- | --- | --- |
| `hashbig` and a data file | (2 + 1) + 3 + 12 = 18 | yes | yes |
| `el2mem`, `hashbig` and `BIG.DAT`: the staging plan | (3 + 1) + 3 x 2 + 26 + 12 = 48 | yes | yes |
| `psci`, `hashbig` and `BIG.DAT` | (3 + 1) + 3 x 2 + 30 + 12 = 52 | yes | yes |
<!-- /hashbig-chain-budget -->

## Residual risks

* **Three pages of a 144 MiB file are asked about, not all of them.** A hole between them would abort the load into q1n1's fault
  page (INFERRED), not hang; the extent check against the allocated descriptors is what bounds the rest.
* **The rate depends on the attributes**: the `ATTR` line is printed before the hash so that a slow run can be read against it.
* **A 25-second box is a choice**, not a finding: a file of 144 MiB at less than 5.76 MiB/s ends in `TIMEBOX` with the rate of the
  part hashed, which is the answer the monitor needs.
* **`MIBS` is an integer**, so it truncates: the `TICKS` and `BYTES` on the same line are the exact figures.
* **Only the first eight bytes of each digest are printed**; the verdict is over all thirty-two (tested with a difference in the last
  byte).
* **QEMU shows the shape only** (TCG speed, a small file): the unit's first run is the first observation of any value.

## Status

EXPERIMENTAL. Hardware NOT RUN. OBSERVED on the unit by other payloads: payloads of boot 5 hashed correctly at EL2 where the firmware put
them. OBSERVED under QEMU only: the page above and the behaviours listed under it. UNKNOWN: everything else this payload would print on
the unit.
