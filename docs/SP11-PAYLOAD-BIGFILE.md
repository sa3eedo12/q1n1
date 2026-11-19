<!-- SPDX-License-Identifier: MIT -->
# The runner's big files: data files of up to 2 GiB

`platform/uefi/sp11-payload.h`, `sp11-payload-load.c`, `sp11-payload-plan.c` and the runner's glue in `platform/uefi/main.c` carry an opt-in form of the stick payload runner
described in [SP11-PAYLOAD.md](SP11-PAYLOAD.md): the manifest, the stick files, [the chain](SP11-PAYLOAD.md#the-chain-several-payloads-in-one-boot), ABI v1 and the
[line catalogue](SP11-PAYLOAD.md#line-catalogue) are defined there and not repeated. With it, a data file on the stick may be up to **2 GiB** instead of 256 MiB, because the
runner declares its ranges to slbounce with a larger chunk cap and allocates data files with `AllocateMaxAddress`, at or below the top of RAM. It exists for one use: carrying a root image of 1,862,270,976 bytes
(1,776 MiB) from the stick into RAM before the bounce. Evidence labels as there: VERIFIED (read in the sources or run on the host), OBSERVED, INFERRED, EXPERIMENTAL,
UNIMPLEMENTED, UNKNOWN. **EXPERIMENTAL; hardware NOT RUN: nothing of this has run on the unit, and this document authorises no run.**

The gate is `Q1N1_SP11_BIGFILE` (default 0), built with `BIGFILE=1` on top of `PAYLOAD=1`. With it at 0 every changed line is under an `#if` whose other branch is the old text, and the
runner is the pinned runner byte for byte ([Building it](#building-it), [Tests and proofs](#tests-and-proofs)).

## Why

The runner takes at most 5 files, each at most 256 ops of the chunk cap q1n1 declares, and the cap was 1 MiB: 5 x 256 MiB is 1,280 MiB, less than the root image, and the file buffers came
from `AllocatePages(AnyPages)`. On the unit every file so far landed under 4 GiB at the top of the largest low extent (0xC3E65000 for 144 MiB, OBSERVED, boots 8 and 9 in
[SP11-PAYLOAD-RESULTS.md](SP11-PAYLOAD-RESULTS.md)), and all the low RAM is 1,361 MiB in seven extents, the largest 590 MiB: a 1.8 GiB request cannot succeed there (VERIFIED arithmetic
from that map). The RAM that can hold it is the 30,720 MiB bank that ends at 2^36. Whether `AnyPages` ever falls back to the bank is UNKNOWN, so the gate asks for the range under the top of RAM by name and
says so when it cannot have it.

## The gate and its numbers

| What | Gate off (the pinned runner) | Gate on (`BIGFILE=1`) | Label |
| --- | --- | --- | --- |
| Chunk cap q1n1 declares (`chunk_cap` of the declared table, the unit of one flush op of slbounce's sweep) | 1 MiB, `t.chunk_cap = 1u << 20` | `BIGFILE_CHUNK_KIB` KiB, 8192 KiB = 8 MiB by default: a power of two from 64 KiB to 8192 KiB, a build constant | VERIFIED in the source; an 8 MiB flush op is UNKNOWN until a run |
| Ops slbounce splits a range into | at most 256 (`SP11_SWEEP_MAX_OPS`) | the same: **256 chunks** | VERIFIED, slbounce fork `src/bounce_main.c:111,157-162` |
| Largest file | 256 MiB (256 x 1 MiB) | 256 x the cap, at most 2 GiB: **2 GiB** (2,147,483,648 B) at 8 MiB; 16 MiB at 64 KiB | derived in `sp11-payload.h`, two `_Static_assert`s |
| Files together | 4 GiB, the A16 manifest's total (`preload.c`, shared, unchanged) | the same | VERIFIED |
| Allocation of a data file | `AllocatePages(AnyPages, LoaderData)` | `AllocateMaxAddress` with the last byte at or below `0xFFFFFFFFF` (2^36 - 1), no second try | where the firmware places it is UNKNOWN |
| Allocation of a payload, the preload table, the stack | `AnyPages` | `AnyPages`, unchanged | VERIFIED |
| Read request to the file system | 1 MiB | 1 MiB, unchanged (a larger request is a possible speed-up and UNKNOWN) | OBSERVED working at 144 MiB in all |
| SHA-256 of a file | one call over the whole buffer | the same digest in slices of 64 MiB, one line after each full slice | VERIFIED on the host |
| Lines | the per-file `PAYLOAD LOADED` notes, `PAYLOAD READY`, `SP11 EBS` | those, unchanged, plus `PAYLOAD READ`, `PAYLOAD HASH` (firmware console only) and one `PAYLOAD BIGFILE` note | see [Lines](#lines) |
| New refusal | none | `FILE_NO_MEMORY`, after `DECLARE` in the enum: the value of no old refusal moves | VERIFIED |

`BIGFILE_CHUNK_KIB` is the knob: **the unit of work is a parameter, not a constant**. A smaller cap only lowers the limit (256 chunks of it); it cannot raise it. The only way to carry a
1.8 GiB file with 1 MiB units is to raise slbounce's `SP11_SWEEP_MAX_OPS` from 256 to 2048, a new slbounce binary, which this change does not make and slbounce does not need for it
(below).

### Why a build constant and not a manifest field

The cap is the contract between the runner and slbounce (the `chunk_cap` of the declared table), not a property of a stick's content. The manifest (`Q1N1PLD1`, `preload.h`) is the A16
loader's layout and `q1n1_preload_manifest_valid` in `preload.c`, compiled into every image, pins its size to 32 + count x 296 bytes: a new field would change a shared format and every
image's validator. And a stick must not be able to change the flush unit that a reviewed runner stands for: as a build constant the unit is part of the runner's digest, printed in
`SP11 EBS: ... chunk=0x800000` and in the `PAYLOAD BIGFILE` line, and the stick can only fall under it. So the manifest has **no new field**; the field widths it has are in [the table below](#the-manifest-and-its-tool).

### What the unit is, and what it is not

slbounce (VERIFIED, read in the fork: `src/sp11_scoped_sweep.c:43-75`, `src/bounce_main.c:157-165`, `src/arch.c:18-33`) checks `chunk_cap` only for zero, walks each declared range in ops of at
most `chunk_cap` bytes into a stack array of 256, and for each op runs `clear_dcache_range`: a `dc civac` per cache line, then one `dsb ish; isb`. The total number of `dc civac`
instructions is the same at any cap; the cap spaces the barriers and bounds the longest stretch between two of them. The 1 MiB it had is "an unmeasured but bounded unit of work" borrowed
from the project's GPU submission rule (`main.c`, `sp11_declare_ranges`): it was never a measurement of a hang's cause, so **an 8 MiB stretch is UNKNOWN**, not known safe. What bounds it
here: the cap is printed (`chunk=` on the console and on the page, and `CHUNK=` in the new note), the number of ops of the biggest range is printed (`MAXOPS=`), and slbounce prints
nothing per op, so the film is what measures it: the time from `PAYLOAD READY` to the first line of the page bounds the whole `ExitBootServices` (the sweep and the bounce together), not an op.
The runner has no timer across the bounce (the counter's offset after the bounce is a separate unknown), and adds none.

## What the gate changes

### Allocation under the top of RAM

For each data file (a name that is not `<stem>.BIN`) the loader calls `AllocatePages(AllocateMaxAddress, LoaderData, pages, &address)` with `address` set to `0xFFFFFFFFF`, the
last byte the range may end at (the unit's RAM ends exactly at 2^36, OBSERVED, boot 6 memory map). The answer is checked, not trusted (`q1n1_payload_top_ok`): an address of zero, off a
page boundary, above the bound, or whose last byte is above it, is given back and refused like a failure. There is **no fallback to `AnyPages`**, because on the unit that would put a file
where the low extents cannot hold the next one. A failure is `PAYLOAD REFUSED=FILE_NO_MEMORY INDEX=<n> EFI=<status> GOT=0 WANT=<bytes>`: the file, the firmware's status and the size (a whole number of pages) that
could not be had; everything allocated so far is freed, nothing was declared or bounced, and the Shell gets `EFI_ABORTED` as for every refusal. (The old `NO_MEMORY` stays for the preload table, the
stack and a payload.) Where this firmware places such an allocation is UNKNOWN: the bound is an upper limit, not an address. EDK2's `AllocateMaxAddress` is understood to take the highest free range that fits at or below it,
which on the unit would be the top of the bank (INFERRED from EDK2's design, not read from this firmware), and on QEMU's EDK2 a 300 MiB data file in a guest of 1 GiB came back at `0x69548000`, below the runner's
own image and payload (`0x7C148000`, `0x7CB57000`) and the firmware's allocations above them (OBSERVED on QEMU, a model: its map is not the unit's). Whether a 1.8 GiB `LoaderData` range is **one descriptor** of the memory map, as slbounce requires of every range, depends on whether the
firmware keeps adjacent allocations of one type apart or merges them (UNKNOWN). If it lists two, the runner's own check before the point of no return refuses the table by name
(`PAYLOAD REFUSED=RANGES REASON=NOT_IN_ONE_DESCRIPTOR RANGE=<n>`), instead of slbounce's bare `EFI_ABORTED`.

### Sizes are 64-bit

Every size in the loader is a `uint64_t`: the manifest's size, the file's size from `GetInfo`, `bytes` and `alloc` of a loaded file, the count of pages, the range of the declared table
(`struct sp11_ebs_range`), the cache entry, the diagnostic fields and the decimal printer. `size_t` is 64 bits on the aarch64 COFF target (the target is LLP64: `long` is 32 bits, and no `long`
is used in a size), and the header refuses a target where it is narrower. The one 32-bit width is `chunk_cap` (`uint32_t` in the declared table, a layout shared with slbounce), good to 4 GiB less one.
`chunks_for(size, chunk_cap)` takes a 64-bit size, so a range of 2^32 + 8 MiB is not mistaken for one of 8 MiB. The shared manifest validator already refuses a size that would overflow its running
total, so a size of 2^32 + 1 or more never reaches the runner's own rule; sizes of 2^32 - 1 and 2^32, which the validator accepts when they stand alone, are refused by the runner by name.

| A manifest entry of ... | Result | Where |
| --- | --- | --- |
| exactly 256 x cap bytes (2 GiB at 8 MiB) | accepted by size; 256 ops; refused only if the firmware has no room | `FILE_TOO_BIG` rule, plan check |
| 256 x cap + 1 byte, or 2 GiB + 1 at the default cap | `FILE_TOO_BIG INDEX= GOT= WANT=` before the file is opened | the runner |
| 2^32 - 1 or 2^32 bytes (alone in the manifest) | `FILE_TOO_BIG`, before the file is opened | the runner |
| 2^32 + 1 bytes or more, or 0 | `MANIFEST_BAD` | the shared validator in `preload.c` |
| files whose sizes add up to more than 4 GiB | `MANIFEST_BAD` | the shared validator; the tool refuses it before hashing |
| a range of a table that needs 257 ops, or 2^32 + 8 MiB | `RANGES REASON=RANGE_TOO_LARGE` | `q1n1_payload_table_check`, `q1n1_payload_map_check` |

### The firmware watchdog

With the gate on, `sp11_payload_prepare` calls `set_watchdog(0, 0, 0, NULL)` before the first read, the call `leave_firmware` makes unconditionally after the load. With the gate off the only call is the one in `leave_firmware`, as before. Whether the Shell
left the 5-minute watchdog armed is UNKNOWN; the call is there so that a slow read of 1.8 GiB cannot be what trips it (below, [What is UNKNOWN](#what-is-unknown)).

### Lines

The per-file notes (`PAYLOAD LOADED INDEX= BASE= BYTES= SHA= TYPE=`), `PAYLOAD READY FILES= RANGES= CODE=` and the `SP11 EBS:` lines keep their shape. What is added, all before the bounce
unless said:

| Line | Where | Meaning |
| --- | --- | --- |
| `PAYLOAD READ INDEX=<n> MIB=<m> OF=<total MiB>` | firmware console | after each 64 MiB of file `n` has been read (not per request: the request stays 1 MiB) |
| `PAYLOAD HASH INDEX=<n> MIB=<m>` | firmware console | after each 64 MiB of it has been hashed; none for a file under 64 MiB |
| `PAYLOAD BIGFILE CHUNK=<bytes> MAXOPS=<n> MAXFILE=<bytes> TOP=<address>` | firmware console, kept as a note and replayed on the page | the unit the sweep will use, the most ops any declared range needs (the film is read against it), the file limit and the allocation bound; one more note, 7 of the page's 8 |

At most 128 progress lines in all (4 GiB in all, at 64 MiB each, read and hashed): never one per op or per request. A film of the console reads the rate of the stick between two `PAYLOAD READ`
lines; it is UNKNOWN until a run (the stick's **read rate** on the unit at this size: the 144 MiB of boots 8 and 9 read and hashed in under about 6 s, INFERRED by subtraction, so at least
24 MiB/s there, which would make 1.8 GiB about 75 s).

### The manifest and its tool

There is no new manifest field. The fields it has, and how wide:

| Field | Width | Limit |
| --- | --- | --- |
| `magic`, `version`, `count`, `entry_size` | 64-bit each | 1 to 16 files in the shared format, at most 5 for the runner |
| per file `size` | 64-bit | 1 to 4 GiB in the shared format; at most 256 x cap, 2 GiB, for the runner |
| per file `sha256`, `path` | 32 B, 256 B | unchanged |

`tools/sp11_payload_manifest.py` gains `--chunk-cap-kib N` (default 1024, the pinned runner; a runner built with `BIGFILE_CHUNK_KIB=N` takes files of up to 256 x N KiB). N is a power of two from 64 to 8192
(`file_limit()`); the limit is at most 2 GiB. The tool checks every size rule, the total of 4 GiB included, before it reads a byte, then hashes in blocks of 8 MiB (it used to read each file whole)
and refuses a file whose length changed while it was being read. A faulty input is refused with exit status 1 and no `--out-dir` written: a cap that is not a power of two or is outside 64 to 8192, a
file one byte over the limit, a size whose low 32 bits are small (2^32 + 8192), a total over 4 GiB. When N is not 1024 the printed instructions say to build with `BIGFILE=1 BIGFILE_CHUNK_KIB=N` and that the runner of
the pinned digest takes no file over 256 MiB.

## Placement and what a stick needs

A runner with the gate on asks for data files at or below `2^36 - 1` and takes what the firmware gives; on the unit that is INFERRED to be the top of the 30,720 MiB bank (UNKNOWN until a run, above). The total of the files is at most 4 GiB. Anything else that wants
that RAM (a guest placement, a work area) has to stay outside the files: the runner declares each file as a range, and a table in which two ranges overlap is refused (`RANGES_OVERLAP`), but what the
runner cannot know is where a payload or a later stage wants to put things; that is the placement rule of whatever carries the files on (the Snapintosh stick bundle puts its file buffers outside its
placement, and its own limits, `SP11SB_FILE_MAX` and the tool's file caps, are the 256 MiB this gate lifts: they change in that repository, not here).

## What is UNKNOWN

* **An 8 MiB flush op.** slbounce's loop is `dc civac` over the range then one barrier; the unit only spaces the barriers. No run has made an op of this size; the 1 MiB had no measurement behind it either.
  If a run hangs in the sweep, build with `BIGFILE_CHUNK_KIB=` smaller (a limit of 256 x that), and say which cap hung.
* **Where this firmware places an `AllocateMaxAddress` allocation**, whether the 1.8 GiB `LoaderData` range is **one descriptor** (slbounce wants exactly one), and whether the firmware's allocator
  agrees with the bound: the runner refuses by name in each case it can see, but none has run on the unit.
* **A read into a buffer above 4 GiB.** Every file read so far went to a buffer below 4 GiB (`0xC3E65000`, OBSERVED); the top-of-RAM bound may put this one in the 30,720 MiB bank (INFERRED). Whether the firmware's USB path
  bounces or addresses 64 bits there is UNKNOWN; a failure is `FILE_READ` or `HASH` before the bounce, a truncated DMA address could damage low memory. Run the gate-on runner once with a data file of about 64 MiB first: it shows the
  `BASE` it gets and that the read verifies.
* **The firmware watchdog.** The gate-on runner calls `set_watchdog(0, 0, 0, NULL)` before the load, but whether the Shell left the 5-minute watchdog armed, and whether that call disarms it on this firmware, is UNKNOWN; 1.8 GiB at 6 MiB/s or less
  would pass 5 minutes, and a reset between `PAYLOAD READ` lines is that.
* **The stick's read rate** at 1 MiB requests for 1.8 GiB, and the firmware console's cost of 128 lines.
* That a stick of FAT32 (a file over 4 GiB is impossible there, one of 2 GiB is not) is what the firmware's driver reads in 1 MiB requests all the way to the end of such a file (the 144 MiB file is the only size seen).
* What a payload or a stage makes of RAM the runner allocated at the top of the bank (the runner's part ends at the bounce).

## Tests and proofs

All of it on a host. QEMU's EDK2 is a model: its memory map, its allocator and its FAT driver are not the unit's, and slbounce is absent there, so the sweep is not exercised. Hardware: NOT RUN.

| Suite | What it holds the gate to |
| --- | --- |
| `tools/test-q1n1-sp11-payload.py` (`Native`, `Mutants`) | the loader and plan programs (`-load.c` with `-load-big.h`, `-plan.c` with `-plan-big.h`) built with the gate on at 8 MiB (limit 2 GiB: a 300 MiB file is loaded, hashed and printed, 64 MiB at its edges, the limit's own edge reached through an allocation that fails, 2 GiB + 1, 2^32 - 1, 2^32 and a total over 4 GiB refused by name) and at 64 KiB (limit 16 MiB: a file of exactly the limit is loaded and one byte more refused), data asked of the top and nothing else, the allocation that fails or lies, `q1n1_payload_top_ok` at its edges, the plan's budget at 256 ops in 64-bit arithmetic and, with the slbounce fork, its own verdicts on the same ranges; 25 seeded bugs in `tools/sp11_payload_bigfile_mutants.py` |
| `tools/test-q1n1-sp11-payload-build.py` (`ManifestTool`, `ToolMutants`) | the tool's limits and cap, the faulty inputs above, 6 new seeded bugs in the tool |
| `tools/test-q1n1-sp11-payload-qemu.py` (`PayloadQemuBig`) | one QEMU at a time: a guest of 1 GiB loads a 300 MiB file made in blocks on disk, with the host's digest on the console and the progress lines; the same stick under the gate-off runner is `FILE_TOO_BIG`; a guest of 256 MiB gets `FILE_NO_MEMORY` and no fallback |
| `tools/test-q1n1-sp11-payload-bigfile.py` | with the gate at 0 every runner file preprocesses and compiles to the base commit's text and bytes, the Makefile's command lines are its lines, the gate without the runner and a bad cap are errors, the gate's constants, its glue, and this document |

Mutants (the loader and plan programs must each reject them): the limit not derived from the cap, 512 ops, a cap of 16 MiB, a ceiling that lets 4 GiB through, a size truncated to 32 bits in the loader and in the
plan, the limit exclusive, data asked of `AnyPages`, a fallback to `AnyPages`, an allocation failure not refused, a refusal that does not name the file, the payload asked of the top, the firmware's
answer trusted, the bound exclusive or without its end, a hash that skips the last slice or re-reads the first, a hash over a narrowed length, a read request of 8 MiB, progress per request, no
hash progress, a changed line shape, the op count rounded down. The harness counts a seed whose text is not in the source once as stale, not as caught.

### Building it

```
make -f platform/uefi/Makefile SP11=1 PAYLOAD=1 BIGFILE=1 [BIGFILE_CHUNK_KIB=8192] SP11_USB_TABLE_C=... SP11_STAGE_TABLE_C=... payload-runner
python3 tools/sp11_payload_manifest.py --out-dir <dir> --chunk-cap-kib 8192 STATE.BIN ... ROOT.DAT
```

`BIGFILE=1` without `PAYLOAD=1` is refused by the Makefile and by the header. The objects do not depend on the gate or the cap, so build each setting into its own `OUT=` or a fresh worktree;
`strings -a q1n1-payload.efi | grep 'PAYLOAD BIGFILE'` finds the note only in a gate-on image. With `BIGFILE=0` (the default) no recipe, prerequisite or object changes. Both runners were built from this tree with `/Brepro`, twice each:

<!-- bigfile-digests -->
| Size | SHA-256 |
| --- | --- |
| 776,192 B | `c20579093ec7b1506faca3c0d33520561716510d7932ac1c9d340f432c88bf6e` |
| 779,264 B | `af76e0bf726be99ec22aaaf6bb1079dcf8ec6579fe64cf2141cc0cad09181e9f` |
<!-- /bigfile-digests -->

The first row is the gate off with the stamp `A9F00F9CCBB5`, equal to the pinned runner; the second the gate on at 8 MiB with the stamp `E448F9A-W4BIG`. The mapping step's runner (`SMMUMAP=1`) is also unchanged with
the gate at 0: with the stamp `E448F9A315F2` it is the S1b runner of the base commit.
