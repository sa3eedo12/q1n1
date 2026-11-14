<!-- SPDX-License-Identifier: MIT -->
# SP11 stick payload runner: reviewed EL2 test code from the boot stick

A second q1n1 image, `Q1N1-PAYLOAD.EFI`, that loads *payloads* (flat, position-independent binaries) from the
volume it was started from, checks them, hands their pages to slbounce's scoped sweep, and after the Secure-Launch
bounce calls them at EL2, one after the other, through a small ABI. The point is to run reviewed EL2 test code on
the Surface Pro 11 **without rebuilding q1n1 and without a host link**: the unit has no UART, no USB link and no
persistent log, so a payload prints through q1n1's own page and the operator reads it with a phone camera. Every
boot costs a power cycle and a photograph, so one boot can run a **chain** of up to five files (see "The chain"),
for example `state` (the registers) and then `psci` (what the firmware's PSCI supports). It is the foundation for
the next measurements (secondary CPUs through PSCI, an EL2 monitor, guest images; see the last section).

Evidence labels follow the Snapintosh `AGENTS.md`: VERIFIED, OBSERVED, INFERRED, EXPERIMENTAL, UNIMPLEMENTED,
UNKNOWN. Everything below is **EXPERIMENTAL**: built and tested on a host and on QEMU's EDK2 (which gives the
runner a real EL2); **hardware NOT RUN**. Facts about the unit are labelled where they are used.

## Build

```sh
# the runner (a PE image) and the payloads (flat binaries)
make -f platform/uefi/Makefile SP11=1 PAYLOAD=1 \
    SP11_USB_TABLE_C=<file from sp11_usb_ports.py emit-c> \
    SP11_STAGE_TABLE_C=<file defining q1n1_sp11_stage_table_get()> \
    payload-runner payloads          # -> $(OUT)/q1n1-payload.efi and $(OUT)/payloads/{state,psci,usbsmmu,timer}.bin
```

* `Q1N1_SP11_PAYLOAD` (default 0) needs `SNAP_PLATFORM_SP11=1` and is an `#error` without it, in `main.c` and in
  every `platform/uefi/sp11-payload-*` file, and an `#error` when combined with `Q1N1_SP11_STK_SURVEY`: the survey
  and the runner are separate images. The Makefile refuses `PAYLOAD=1` without `SP11=1` and with `STK_SURVEY=1`.
* Only `main-payload.obj` and the `sp11-payload-*.obj` objects are compiled with the gate. `q1n1.efi`, the stages,
  the survey image and every object they use are what a build without `PAYLOAD` makes, byte for byte (see
  "Tests"). `make ... PAYLOAD=1 all` also builds the normal artefacts beside both outputs.
* `make payloads` needs no `SP11` and no `PAYLOAD`: it builds every `payloads/*.c` with the start stub and the
  linker script, **fails if the ELF holds any relocation that depends on the load address** or any dynamic, GOT,
  PLT or TLS part (`tools/sp11_payload_elfcheck.py`, run after every link on the relocations `--emit-relocs`
  keeps), and flattens it. Freestanding, no libc, general-regs-only, like the rest of q1n1. A second check, in
  the tests, disassembles each binary against a per-payload allow-list: `state` may hold `MRS` of its registers
  and nothing else; `psci` may hold `MRS` of CurrentEL and MPIDR_EL1 and exactly **one** `smc #0`; `timer` `MRS` of its
  twelve timer and counter registers and no barrier; `usbsmmu` `MRS` of CurrentEL, no barrier and no `smc`.

## On the stick, and the one command

```sh
python3 tools/sp11_payload_manifest.py --out-dir build/stick build/uefi/payloads/state.bin build/uefi/payloads/psci.bin build/uefi/payloads/timer.bin [data.dat ...]
```

writes `build/stick/SP11/PAYLOAD.MAN` and a capitalised 8.3 copy of every file below `build/stick/SP11/`, and
prints what to copy and what to run, one line per file saying whether it is a payload (called, in manifest order)
or data (never called). The positional files keep the order given. A file whose name ends in `.BIN` (any case) is a
payload; any other is data; the **first** must be a `.BIN`. `state.bin` alone gives exactly the manifest it always
gave. Copy these to the stick, keeping the `SP11` directory; for a `state`, `psci`, `timer` boot the stick holds
exactly:

| File on the stick | From |
| --- | --- |
| `SP11\Q1N1-PAYLOAD.EFI` | `$(OUT)/q1n1-payload.efi` (not written by the tool) |
| `SP11\PAYLOAD.MAN` | the tool |
| `SP11\STATE.BIN` | the tool (a copy of `state.bin`; manifest index 0) |
| `SP11\PSCI.BIN` | the tool (a copy of `psci.bin`; manifest index 1) |
| `SP11\TIMER.BIN` | the tool (a copy of `timer.bin`; manifest index 2, **last**: it may stall the board) |
| `SP11\USBSMMU.BIN` | only in a chain that has `usbsmmu`: the tool (a copy of `usbsmmu.bin`, between `psci` and `timer`) |

The S0b chain is `psci.bin usbsmmu.bin timer.bin` (manifest indexes 0, 1, 2; the stick holds `SP11\PSCI.BIN`,
`SP11\USBSMMU.BIN`, `SP11\TIMER.BIN`, `SP11\PAYLOAD.MAN` and the runner, and no `SP11\STATE.BIN`): see "Payload `usbsmmu`".

Then, from the UEFI Shell, with slbounce loaded exactly as for q1n1 (`load SP11\SLBOUNCE-DEVHE-MARK.EFI`):

```
SP11\Q1N1-PAYLOAD.EFI --el2
```

There is no new option. The argument parser is unchanged: `--boot`, `--uart-proxy` and the no-argument preflight
never run the runner (QEMU test: the no-argument run prints no `PAYLOAD` line). The Snapintosh autorun allow-list
and staging are not touched here.

## The manifest

`\SP11\PAYLOAD.MAN`, on the volume the image was loaded from and nowhere else, in the A16 preload's `Q1N1PLD1`
format (`platform/uefi/preload.h`, `tools/preload.py`): a header, then per file its size, SHA-256 and path. A file
named `<stem>.BIN` (any case) is a payload and is called; any other file is data a payload finds through the
preload table (see "The chain"). The runner adds rules to the shared validator: at most **5** files, every path
below `\SP11\` (compared without regard to case), none of them the manifest itself, each at most **256 MiB**, and
file 0 must be a payload. The tool enforces the same limits plus 8.3 names, which keeps FAT long-name aliases out
of the question, and writes nothing outside `--out-dir`. It holds no host path and no machine identifier, and its
output is deterministic.

Why 5 and 256 MiB: slbounce takes at most 8 declared ranges (`SP11_EBS_MAX_RANGES`) and the image, the memory-map
buffer and the preload table use 3; and it splits a range into at most 256 chunks (`SP11_SWEEP_MAX_OPS`) of the
1 MiB chunk cap q1n1 declares.

## What happens

**Before ExitBootServices** (every failure here returns to the Shell, nothing is bounced):

1. `sp11_payload_prepare`: EFI_LOADED_IMAGE.DeviceHandle -> SimpleFileSystem -> OpenVolume. No ConnectController,
   no enumeration of block devices or volumes, the internal disk is not looked at, nothing is written (files are
   opened for reading, mode 1). Reads and validates the manifest, then for each file: GetInfo size equals the
   manifest's, reads exactly that many bytes and probes for one more, AllocatePages (`EfiLoaderCode` for a payload,
   `EfiLoaderData` for data), zeroes the rest of the last page, SHA-256 equals the manifest's. Then the preload
   table and the payload stack (below).
2. `leave_firmware`: allocates the memory-map buffer, then `sp11_declare_ranges` writes the declared table the
   sweep reads (`Q1N1Sp11EbsRanges`): **image, map buffer, preload table, then each file** (labels `image`, `map`,
   `preload`, `payload`, `file1`...). The framebuffer is never declared: it is RESERVED memory on the unit, which
   the sweep refuses by design, and nothing reads it after the bounce. `sp11_payload_precheck` then reads the map
   into the retry loop's buffer and applies slbounce's rules to each range, in its order (one descriptor, type
   1-6 or 9, write-back, at most 256 chunks). A refusal prints one `PAYLOAD REFUSED=...` line, **deletes the
   declared variable**, frees the map buffer and returns `EFI_ABORTED`; otherwise
   `PAYLOAD READY FILES=n RANGES=n CODE=k` (n files, k of them payloads).
3. The retry loop (GetMemoryMap, ExitBootServices) is unchanged and nothing of the runner is in it: no allocation
   happens between the last GetMemoryMap and ExitBootServices (a source audit checks it).

**After the bounce, at EL2 only**, once q1n1's own page is drawn:

1. The notes from step 1 are replayed on the page.
2. For each payload, in manifest order (see "The chain"): `PAYLOAD VERIFY=OK` follows a check that the preload
   table still describes what the runner loaded (count, and for each entry base, size, allocation and digest
   against the runner's own record) and that this payload, where it now is, still hashes to the manifest's digest.
   Every payload is hashed twice, before and after the bounce, the second time right before its call; one that
   does not verify is **not called** and ends the chain (`PAYLOAD REFUSED=HASH_AT_EL2 INDEX=n WANT= HAVE=`).
   Data and instruction caches are synchronised over that payload's pages (DC CVAU, IC IVAU, with the line sizes
   from CTR_EL0), the guard words are written at the low end of the payload stack, and
   `PAYLOAD CALL <index> <first 8 bytes of the hash>` is printed **before** the call, so a hang is named by the
   last line.
3. `q1n1_payload_call` keeps q1n1's callee-saved registers and its SP (in memory, not in a register) safe, puts SP
   at the top of the payload stack and calls the entry; a payload that breaks AAPCS64 still gives control back.
   Afterwards the runner prints one line, `PAYLOAD DONE INDEX=n RETURN=<value> STACK=OK|OVERFLOW LOADS= FAULTS=
   REFUSED= LINES= DROPPED=`. A payload that faults lands in q1n1's existing fault page (QEMU test: its red bar).
4. Not at EL2 (QEMU with `virtualization=off`): `PAYLOAD SKIPPED=NOT_AT_EL2`, nothing is called, the survey-style
   page carries on.

The payloads run with D, A, I and F masked as q1n1 left them (`DAIF` 0x3C0, OBSERVED on the unit's page), so
q1n1's heartbeat and timer do not run while they do.

## The chain: several payloads in one boot

The convention is the file name and nothing else:

* A manifest entry whose file name ends in `.BIN` (compared without regard to case, with a non-empty name before
  the dot) is a **payload**: loaded as `EfiLoaderCode` and called. Any other entry is **data**: loaded as
  `EfiLoaderData`, hash-checked before the bounce, declared to the sweep, found through the preload table, and
  **never called**, even if its bytes are a working payload (a test puts one there).
* File 0 must be a payload (`PAYLOAD REFUSED=FILE0_NOT_BIN` otherwise). At most 5 files in all, as before.
* After the bounce the payloads are called in **manifest order**, each once. The `INDEX` in the lines below is the
  file's manifest index, so a data file at index 1 makes the second call `PAYLOAD CALL 2`.

Each payload is verified, given arguments built from nothing (`payload_base` and `payload_size` describe **that**
payload; nothing in the ABI changed), given its own budgets and guard words and its own cache maintenance, named
by `PAYLOAD CALL`, called, and reported by `PAYLOAD DONE`, as in "What happens".

The chain **stops** (one line, `PAYLOAD CHAIN STOPPED INDEX=<n> REASON=<reason>`; later payloads are not called) in
exactly two cases:

| `REASON` | When | Also printed |
| --- | --- | --- |
| `HASH_AT_EL2` | payload n, or the preload table, differs from the runner's record when the runner re-checks it right before the call | `PAYLOAD REFUSED=HASH_AT_EL2 INDEX=n WANT=<hash16> HAVE=<hash16>` |
| `STACK_OVERFLOW` | payload n overwrote the guard words at the low end of its stack: nothing says what else it overwrote | its `PAYLOAD DONE` line, `STACK=OVERFLOW` |

What a payload **returns** never stops the chain. A payload that hangs or faults ends the boot as a single payload
did: a hang is named by the last line (`PAYLOAD CALL <n> ...`, with the earlier payloads' lines above it), a fault
lands in q1n1's fault page. A manifest the loader refuses (a wrong hash, a sixth file, file 0 not a `.BIN`) is
refused as a whole before the bounce, and then **no** payload runs.

The page: the runner's own lines are three per payload (`VERIFY`, `CALL`, `DONE`) plus the replayed notes, so a
chain of `state` and `psci` is 3 + 3 + 21 + 3 + 22 = 52 lines. The region on the panel holds about 89 lines on
the unit's panel size (2880 x 1920, computed by the layout function) and the layout asks for at least 60; lines
past the last row are mirrored to the UART but not drawn. Each `DONE` line stays within 100 characters.

**Planning a chain's page.** A chain fits when the lines below add up to at most the panel's rows:

<!-- chain-budget -->
| Item | Lines |
| --- | --- |
| runner, once per boot: `LOADED` for each file (payload or data), `READY` | files + 1 |
| runner, for each payload: `VERIFY`, `CALL`, `DONE` | 3 |
| `state`, at most | 22 |
| `psci`, at most | 30 |
| `usbsmmu`, at most | 24 |
| `timer`, at most | 16 |
| panel region, the unit's 2880 x 1920 panel | 89 |
| panel region, the stock layout: the least it asks for | 60 |
<!-- /chain-budget -->

The maxima are what the host tests measure, over every EL and every answer they script. Example: `psci`, `usbsmmu` and
`timer` need (3 + 1) + 3 x 3 + 30 + 24 + 16 = 83 lines: 89 rows hold them, 60 do not. Adding `state` (22 lines and the
runner's 4) gives 109: past the unit's 89 rows, so a chain of all four is for QEMU, not the unit. A chain
that stops adds `PAYLOAD CHAIN STOPPED` (a hash also `PAYLOAD REFUSED=HASH_AT_EL2`) and calls nothing after it.

**Order.** A payload that may stall the board goes **last**, so that a stall costs only the lines after it: `timer` is
one (`state.bin psci.bin timer.bin`, never `timer.bin` first). `usbsmmu` may hang or reset the board at the first read of
a context bank, so it goes after `psci` and before `timer` (`psci.bin usbsmmu.bin timer.bin`): a stall in it costs only
`timer`'s lines, and a stall in `timer` costs none of `usbsmmu`'s. The manifest tool keeps the order it is given.

**The chain is not a sandbox.** Every payload is machine code at EL2 and may overwrite anything: another payload,
q1n1's records of the others, the runner's own code. The second hash catches accidents (a payload that scribbled
on a later one, memory the bounce did not preserve), not a hostile payload. What keeps a chain safe is what keeps
a single payload safe: every file is reviewed and pinned by its digest, the order is the manifest's, and a
payload that stores to a device register needs the separate authorization described in the last section.

## Payload ABI v1 (`platform/uefi/sp11-payload-abi.h`)

```c
uint64_t payload_entry(const struct q1n1_payload_args *a);   /* offset 0 of the file; x0 = a; AAPCS64 */
```

Entered at EL2 by a `BLR` from q1n1 with `x0 = a` and `SP` = the top of the payload stack, once per payload of the
chain; `payload_base` and `payload_size` describe the payload being called and nothing else in the structure
changes between calls. It returns in `x0`; q1n1 prints the value. It calls into q1n1 **only through `a->ops`**. The
layout is pinned by `_Static_assert` and by a native test that compares it with the table below
(`struct q1n1_payload_args` is 192 bytes, the ops table 32).

<!-- abi-table -->
| Offset | Size | Field | Meaning |
| --- | --- | --- | --- |
| 0 | 8 | `magic` | `Q1N1PAY1` (0x31594150314e3151) |
| 8 | 4 | `version` | 1 |
| 12 | 4 | `size` | `sizeof` the runner filled in; a payload refuses a smaller one |
| 16 | 8 | `payload_base` | where the runner loaded this payload (page aligned) |
| 24 | 8 | `payload_size` | the file size in bytes |
| 32 | 8 | `fb_base` | the framebuffer the panel is drawn in (never declared to the sweep) |
| 40 | 8 | `fb_bytes` | its size |
| 48 | 4 | `fb_width` | pixels |
| 52 | 4 | `fb_height` | pixels |
| 56 | 4 | `fb_stride` | pixels per scanline, 4 bytes per pixel |
| 60 | 4 | `fb_format` | EFI pixel format (0 RGBX, 1 BGRX) |
| 64 | 8 | `map_base` | the final UEFI memory map ExitBootServices was given |
| 72 | 8 | `map_size` | bytes |
| 80 | 8 | `map_stride` | descriptor size in bytes |
| 88 | 8 | `preload_table` | a `struct q1n1_preload_cache` (`preload.h`): the entry whose base is `payload_base` is this payload |
| 96 | 8 | `preload_size` | its size |
| 104 | 8 | `stack_base` | the payload stack is `[stack_base, stack_base + stack_size)` |
| 112 | 8 | `stack_size` | 64 KiB |
| 120 | 32 | `ops` | the ops table below |
| 152 | 40 | `reserved[5]` | zero in version 1; room for more ops or fields without moving any offset |

The ops table (offsets within `struct q1n1_payload_ops`; there is **no store** in it):

| Offset | Size | Op | Meaning |
| --- | --- | --- | --- |
| 0 | 8 | `ops.puts` | `void puts(const char *line)`: one line, drawn on the panel in the survey's region and mirrored to the UART when present, as the survey's `stk_emit` does. Truncated to 100 characters, lower case folded up, anything outside the page font (capitals, digits, `: - . / = ? ( ) _` and space) becomes `_`. At most 40 lines per call (each payload of a chain gets its own 40); later ones are counted as dropped. |
| 8 | 8 | `ops.hex` | `uint32_t hex(char *dst, uint32_t cap, uint64_t value)`: `0X` and the fewest upper-case digits (0 is `0X0`), cut to `cap`, returns the length |
| 16 | 8 | `ops.load32` | `int32_t load32(uint64_t addr, uint32_t *out)`: a recoverable-fault guarded read of one 32-bit word. Errors, not faults: 1 `out` is NULL, 2 misaligned, 3 `addr` beyond the 48-bit space, 4 `out` not inside the payload stack, 5 4096 loads already made in this call, 6 the load aborted. |
| 24 | 8 | `ops.counter` | `uint64_t counter(void)`: CNTPCT_EL0 |
<!-- /abi-table -->

`load32` is a load only: the guarded copy writes into a variable of the runner's, and only after it succeeded is the
word stored into the payload's own stack (so it cannot be turned into a store to a device register). A load can
still hang the bus (an unclocked block), which no guard recovers: that is for the payload's reviewer to rule out
(INFERRED from the survey's experience; nothing measured).

**The stack.** A separate 64 KiB `EfiLoaderData` block, 16-byte aligned, allocated before the bounce, `SP` at its
top. It is not declared to the sweep: nothing is written to it before the bounce. The runner writes two guard
words at its low end after the bounce, **again before every payload of a chain** (the payloads share the stack and
run one at a time), and reports `STACK=OVERFLOW` if the payload overwrote them. q1n1's own ops
run on it too, and an exception pushes a 272-byte frame onto it, so a payload should keep **at least 16 KiB free**
and may use the other 48 KiB. q1n1's own 256 KiB stack is untouched.

**No store is not a sandbox.** A payload is machine code at EL2: it can write wherever it likes. What keeps a
store to a device register out of it is that its bytes are reviewed and pinned by the SHA-256 in the manifest, and
that the runner verifies that digest twice (the second time right before that payload's call). A payload that
wants to write a device register needs a separate, explicitly authorized change (AGENTS.md hardware safety rules;
see the last section).

**Writing a payload.** `payloads/payload-util.h` (static inline helpers) and `payloads/state.c` are the template:
one C file, `uint64_t payload_entry(const struct q1n1_payload_args *a)`, check `pl_args_ok(a)`, no globals (a
writable `.data` or `.bss` is a link error: state lives on the stack), no libc. Constant data and strings in
`.rodata` are fine and are reached PC-relatively. `payloads/psci.c` shows a payload that is not MRS-only: its one
helper holds the only `smc`, and the test that disassembles it counts them. Name the file `<stem>.BIN` on the
stick, or the runner treats it as data and never calls it.

## The payload image

A flat binary. The linker script (`payloads/payload.ld`) links at 0 and puts the start stub (`payloads/start.S`:
`BTI c`, then `B payload_entry`) first, so the entry is offset 0; the firmware chooses the load address. The build
fails on any relocation outside the PC-relative list (an absolute pointer table, a MOVZ/MOVK address, a GOT
access), and a test links the reference payload at another address and compares the bytes.

## Reference payload `state` (read only)

`payloads/state.c` prints one line per register, `PAYLOAD STATE KEY=0XVALUE`, and nothing else; it executes `MRS` and
no instruction that writes. All of it, the register table included, is in [SP11-PAYLOAD-STATE.md](SP11-PAYLOAD-STATE.md).
EXPERIMENTAL; hardware NOT RUN: the payload has not run on the unit, and the only OBSERVED values are those q1n1's own
page showed.

## Payload `psci` (read-only PSCI queries)

`payloads/psci.c` asks the firmware's PSCI implementation what it supports, with `smc #0` at EL2: five function ids,
through one helper, which holds the only `smc` of the binary. All of it is in [SP11-PAYLOAD-PSCI.md](SP11-PAYLOAD-PSCI.md).
EXPERIMENTAL; hardware NOT RUN: nothing of it is OBSERVED on the unit.

## Payload `timer` (read-only timer and counter probe)

`payloads/timer.c` reads the generic timer and counter at EL2 to isolate the CNTVOFF_EL2 and CNTPOFF_EL2 reads that
stalled this board. It may stall the board, so it goes **last** in a chain. All of it is in
[SP11-PAYLOAD-TIMER.md](SP11-PAYLOAD-TIMER.md). EXPERIMENTAL; hardware NOT RUN: nothing of it is OBSERVED on the unit.

## Payload `usbsmmu` (S0b: read-only USB controller, SMMU and context bank survey)

`payloads/usbsmmu.c` reads, with loads only, the xHC and DWC3 registers of the stick's USB controller, the firmware's xHCI
structures in RAM and the SMMU context bank its DMA goes through, then walks that bank's stage-1 tables in software, to
decide whether an EL2 xHCI driver may let the xHC DMA into memory of its own and where. It may hang the board at the
first context bank register and goes between `psci` and `timer`. All of it is in
[SP11-PAYLOAD-USBSMMU.md](SP11-PAYLOAD-USBSMMU.md). EXPERIMENTAL; hardware NOT RUN: nothing of it is OBSERVED on the unit.

## Line catalogue

On the firmware console before the bounce, and on the page and the UART after it (the notes are replayed):

| Line | Where | Meaning |
| --- | --- | --- |
| `PAYLOAD LOADED INDEX=n BASE=0X.. BYTES=n SHA=<16 hex> TYPE=1\|2` | both | file n loaded; the first 8 bytes of its SHA-256; 1 EfiLoaderCode (a payload, named `<stem>.BIN`), 2 EfiLoaderData (data) |
| `PAYLOAD READY FILES=n RANGES=n CODE=k` | both | the precheck passed with n declared ranges; k of the n files are payloads |
| `PAYLOAD REFUSED=<NAME> ...` | firmware console | a refusal before the bounce (below) |
| `PAYLOAD VERIFY=OK` | page | the second check passed for the payload about to be called; printed once per payload |
| `PAYLOAD REFUSED=HASH_AT_EL2 INDEX=n WANT= HAVE=` | page | the second check failed for payload n; not called, the chain ends |
| `PAYLOAD CALL <n> <hash16>` | page | printed just before payload n (its manifest index) is called |
| `PAYLOAD DONE INDEX=n RETURN=0X.. STACK=OK\|OVERFLOW LOADS=.. FAULTS=.. REFUSED=.. LINES=.. DROPPED=..` | page | payload n returned: its value, the guard words, and what its ops did (loads tried, guarded loads that faulted, refused loads, lines kept, lines dropped); the counts are per payload |
| `PAYLOAD CHAIN STOPPED INDEX=n REASON=HASH_AT_EL2\|STACK_OVERFLOW` | page | the chain ends at payload n; later payloads are not called |
| `PAYLOAD STATE KEY=0XVALUE` | page | the `state` payload's lines ([SP11-PAYLOAD-STATE.md](SP11-PAYLOAD-STATE.md)) |
| `PAYLOAD PSCI ...` | page | the `psci` payload's lines ([SP11-PAYLOAD-PSCI.md](SP11-PAYLOAD-PSCI.md)) |
| `PAYLOAD TIMER ...` | page | the `timer` payload's lines ([SP11-PAYLOAD-TIMER.md](SP11-PAYLOAD-TIMER.md#what-it-prints)) |
| `PAYLOAD USBSMMU ...` | page | the `usbsmmu` payload's lines, at most 24 ([SP11-PAYLOAD-USBSMMU.md](SP11-PAYLOAD-USBSMMU.md#what-it-prints)) |
| `PAYLOAD SKIPPED=NOT_AT_EL2` | page | not at EL2: nothing called |

Every line is within the page font and at most 100 characters (a `DONE` line is about 85 characters; the counters
are decimal and a payload can drive them high, so the text helpers cut a line at 100 rather than overrun). The
region on the panel is the survey's (right of the page, or below it); lines past its last row are mirrored to the
UART but not drawn. The old `PAYLOAD RETURN`, `PAYLOAD STACK` and `PAYLOAD OPS` lines are now the one
`PAYLOAD DONE` line, and `PAYLOAD CALL` gained the index.

## Failure modes before the bounce

Each prints one `PAYLOAD REFUSED=<NAME>` line on the firmware console, returns `EFI_ABORTED` (the Shell shows
`%lasterror%` as 0x15), frees what it allocated, and never prints `Leaving firmware now`.

| Name | Cause | Extra fields |
| --- | --- | --- |
| `NO_IMAGE`, `NO_DEVICE`, `NO_VOLUME`, `OPEN_VOLUME` | the image has no loaded-image protocol, no device, no file system, or OpenVolume failed | `EFI=` |
| `NO_MANIFEST` | `\SP11\PAYLOAD.MAN` is not on the image's volume (a manifest on another volume is never read) | `EFI=` |
| `MANIFEST_OPEN`, `MANIFEST_IO` | opening or reading it failed, or it is a directory | `EFI=`, `GOT= WANT=` |
| `MANIFEST_BAD` | the validator refused it, or it is larger than any manifest | `GOT= WANT=` when too large |
| `TOO_MANY_FILES` | more than 5 files | `GOT=6 WANT=5` |
| `BAD_PATH` | a file outside `\SP11\`, or the manifest itself | `INDEX=` |
| `FILE0_NOT_BIN` | file 0 is not named `<stem>.BIN` (any case), so there is no first payload; checked after the per-file path and size rules | none |
| `FILE_OPEN`, `FILE_SIZE`, `FILE_READ` | missing, not the manifest's size (or a directory), short or long read | `INDEX= EFI= GOT= WANT=` |
| `FILE_TOO_BIG` | over 256 MiB | `INDEX= GOT= WANT=` |
| `NO_MEMORY` | AllocatePages failed (a file, the table or the stack) | `EFI= GOT=0 WANT=` bytes |
| `HASH` | SHA-256 differs | `INDEX= WANT=<hash16> HAVE=<hash16>` |
| `RANGES` | the declared table is unusable: `REASON=` `NO_TABLE`, `TOO_MANY_RANGES`, `CHUNK_CAP`, `EMPTY_RANGE`, `RANGE_WRAPS`, `RANGE_IN_FRAMEBUFFER`, `RANGES_OVERLAP`, `RANGE_TOO_LARGE`, or from the map `NOT_IN_ONE_DESCRIPTOR`, `TYPE_NOT_SWEPT`, `NOT_WRITE_BACK` | `RANGE=` index |
| `MAP` | the final memory map could not be read or parsed | `EFI=` |
| `DECLARE` | the declared table could not be written | `EFI=` |

If slbounce still refuses ExitBootServices after all of this, the existing `EXITBOOTSERVICES FAILED` page halts
(firmware may be partly shut down; it cannot return). The precheck mirrors slbounce's per-range rules so that this
does not happen for a table the runner built; slbounce stays the authority, and that the map read just before the
loop is the one it sweeps is INFERRED.

The ways a run ends **after** the bounce are in "The chain": the two stops (`HASH_AT_EL2`, `STACK_OVERFLOW`, each
with a `PAYLOAD CHAIN STOPPED` line), a hang (named by the last `PAYLOAD CALL` line) and a fault (q1n1's fault page).

## Tests

All host and QEMU only; hardware NOT RUN. Environment as for the other SP11 suites (`SLBOUNCE_SP11_DIR` adds the
comparison with slbounce's own `sp11_sweep_range`, `Q1N1_SP11_BASE_DIR` the byte-identity proofs, `SP11_UEFI_SHELL`
the run under the pinned UEFI Shell).

| Command | What it covers |
| --- | --- |
| `python3 tools/test-q1n1-sp11-payload.py` | eight native programs under ASan and UBSan: the loader against a fake firmware (ConnectController and every call outside its list is a tripwire; a manifest on a second volume is ignored; nothing is written; the kind of each file follows its name), the declared-range planner and slbounce's rules against synthetic and 30000 random maps, the text layer and the ABI layout, the EL2 sequence of one payload, the chain's run sequence on a fake platform (order, per-payload hash and arguments, stops, budget reset), the `state` payload against a scripted register file, the `psci` payload against a scripted SMC (only the five ids, only table arguments, no SMC off EL2, every decode, garbage answers), the `timer` payload against a scripted register file and counter, the `usbsmmu` payload against scripted MMIO windows, RAM and a memory map; 80 seeded-bug mutants and an unmutated control; source audits |
| `python3 tools/test-q1n1-sp11-payload-chain.py` | 48 more seeded-bug mutants the native programs must catch (9 in the loader, 19 in the chain loop, 20 in `psci.c`: calling data, calling in reverse order, skipping a second hash, not resetting the budgets or the guard words, running past a corrupted guard, synchronising only file 0's pages, `.bin` case-sensitive, another payload's base, an extra id, CPU_ON instead of a query, a call at EL1, a second `smc` call site...); 13 seeded `psci` binaries the disassembly check must reject; the manifest tool on chains with 10 seeded bugs; the agreement of this document with the sources (the planning table of "The chain" included), with 22 seeded mistakes in the document |
| `python3 tools/test-q1n1-sp11-payload-build.py` | the manifest tool, the ELF check (absolute pointers, MOVZ/MOVK addresses, writable globals, a PIE link, an unreadable file), the built binaries (entry at offset 0, identical when linked elsewhere, an allow-list per payload: `state` only the documented `MRS`; `psci` `MRS` of CurrentEL and MPIDR_EL1 and exactly one `smc #0`; `timer` `MRS` of its twelve registers and no barrier; `usbsmmu` `MRS` of CurrentEL and no barrier; none of the forbidden mnemonics, no CNTVOFF_EL2 or CNTPOFF_EL2 outside `timer`, reproducible in two runs), a payload with an absolute relocation failing the Makefile build, 13 seeded bugs in the two tools, and the default-off proof |
| `python3 tools/test-q1n1-sp11-payload-qemu.py` | QEMU/EDK2 at EL2 and EL1: the whole flow for `state`, every refusal, the call path with five test payloads (`tools/testdata/sp11-payload-fixture-*.c`) and two seeded variants of the runner |
| `python3 tools/test-q1n1-sp11-payload-qemu-chain.py` | QEMU/EDK2 at EL2: a chain of three in order, each with its own base and size; data never called (a data file that holds a working payload); mixed-case names; five files and eight ranges; a wrong hash before the bounce; a hash that changes after it (a seeded runner variant, and a payload that damages a later one); a stack overflow; a hanging and a faulting second payload with the first one's lines still on the page; the budgets of every payload; file 0 not a payload; `state` then `psci` |
| `python3 tools/test-q1n1-sp11-payload-timer.py` | `timer` ([SP11-PAYLOAD-TIMER.md](SP11-PAYLOAD-TIMER.md)): 31 seeded-bug mutants, the allow-list on `timer.bin` (20 seeded bad binaries, 6 that break the compiled order), the manifest tool and the runner's validator on `state psci timer`, the two documents against the source and each other (links included), with 41 seeded mistakes |
| `python3 tools/test-q1n1-sp11-payload-qemu-timer.py` | QEMU/EDK2 at EL2: `state`, `psci`, `timer` in one boot (72 lines); `timer` copies that hang or fault on a hazardous read: the NEXT line last on the page, or q1n1's fault page |
| `python3 tools/test-q1n1-sp11-payload-usbsmmu.py` | `usbsmmu` ([SP11-PAYLOAD-USBSMMU.md](SP11-PAYLOAD-USBSMMU.md)): the ten suites of its host test (scripted MMIO windows, RAM and memory map, the walk against independently built page tables, an abort at every load, hostile registers, the line and load budgets), 83 seeded-bug mutants and an unmutated control, the source audit of what it may touch, the allow-list on `usbsmmu.bin` (23 seeded bad binaries) and on the other policies, the manifest tool and the runner's validator on `psci usbsmmu timer` |
| `python3 tools/test-q1n1-sp11-payload-usbsmmu-doc.py` | the five payload documents against the source and each other (registers and their evidence labels, the printed blocks against the host test's own dump, numbers, reason names, decision tables, the QEMU block, links and anchors, the pointers in this document, the moved `state` and `psci` stubs), with 78 seeded mistakes in the documents |
| `python3 tools/test-q1n1-sp11-payload-qemu-usbsmmu.py` | QEMU/EDK2 at EL2: `psci`, `usbsmmu`, `timer` in one boot, `usbsmmu` alone, and `state`, `psci`, `usbsmmu`, `timer`: the USB windows abort and the SMMU window reads all ones, the payload prints its 10 lines and a normal `DONE` (4 loads, 2 faults) and every later payload runs |

The default-off proof (`PayloadDefaultOff`): with the gate at 0 every runner file compiles to an object with no
symbols, `main.c` preprocesses to the same text as at the commit before the runner (default, plain SP11 and SP11
with the survey), `make -n` lines are unchanged, and the default, plain-SP11 and survey builds are byte-identical
to it. `PAYLOAD=1` makes `q1n1-payload.efi` and changes no other artefact; only that image holds the runner's
strings.

What QEMU cannot show: the real region on the unit's panel (QEMU's ramfb is at most 800x600, the page fills it,
and the stock region has no rows there; a copy that forces a region shows that the drawing path renders the
lines), the sweep (slbounce is absent), the unit's firmware memory attributes, and any behaviour of the Oryon core.

## Safety

* No `ConnectController`, no enumeration of block devices or volumes, no access to any volume but the one the
  image came from, no write to any volume; files are opened for reading only. The A16's
  `\Snapintosh\q1n1-preload.bin` is never read.
* Fail closed: every refusal before the bounce returns to the Shell; a payload that does not verify at EL2 is not
  called and ends the chain; an unsupported request is an error, never a made-up success.
* The ops table has no store. `load32` is a guarded load with a destination restricted to the payload stack and a
  budget. The glue in `main.c` forwards loads only (a source audit checks it).
* The framebuffer is never declared. Nothing is allocated between the last GetMemoryMap and ExitBootServices.
* Every payload's hash is verified twice, the second time right before its call. A payload is not sandboxed, and
  neither is a chain (see "The chain").
* `psci` is the only payload with an `smc`: five function ids, one helper, one instruction in the binary, no id
  that changes the machine; the others are only the argument of PSCI_FEATURES.
* `usbsmmu` reads device registers of three fixed windows (the stick's USB controller, the other one and the SMMU) and
  RAM, with loads only: a window only after the block's identity looked plausible, and nothing more from it after an
  abort; RAM only where the UEFI memory map says it is usable. It can still hang or reset the board at a context bank
  register nobody has read, which nothing recovers (named by its last `NEXT CB<n>` line); it goes before `timer`.
* Hardware rules of `AGENTS.md` apply to every payload: AC power or at least 50% battery, the thermal guard, no
  single `CP_MEMCPY` over 1 MiB, one hardware client at a time, nothing that changes persistent firmware, clocks or
  voltages without explicit authorization.

## Limits

* Up to five files per run, the payloads among them called once each, in manifest order, at EL2 only, on the boot
  CPU. Secondary CPUs are neither run nor measured (whether the firmware leaves them off or parked is what the
  `AFFINITY` group of `psci` asks; UNKNOWN until it runs).
* At most 5 files of at most 256 MiB each (slbounce's capacity and chunk budget); no change to slbounce was made or
  is needed.
* No persistent log: the page and the UART (when there is one) are the only outputs. 40 lines per payload, 100
  characters each; the panel region holds about 89 lines on the unit's panel size (the layout asks for at least 60),
  and the runner's own three lines per payload count against it.
* A hang is not recovered (named by the last line); a fault ends in q1n1's fault page. Neither lets a later payload
  of the chain run.
* `main.c` was already over the 1500-line limit (2013 lines at the base commit); the glue added to it is about
  165 lines and kept thin, the policy is in the `sp11-payload-*` files, each well below the limit.

## Differences from the A16 preload

| | A16 `q1n1_preload` | This runner |
| --- | --- | --- |
| Manifest | `\Snapintosh\q1n1-preload.bin` | `\SP11\PAYLOAD.MAN` |
| Where it looks | connects **all** block devices and scans **every** volume | the volume the image was loaded from, nothing else |
| Writes | never | never; no volume other than the image's is even opened |
| Files | up to 16, 4 GiB in all, `EfiLoaderData` | up to 5, 256 MiB each; payloads (`<stem>.BIN`) in `EfiLoaderCode`, the rest `EfiLoaderData` |
| Table | `q1n1_preload_cache` | the same layout, so one reader serves both |
| Purpose | resident cache for the host-link flow | the payloads are code that is called, in manifest order; the data is found through the table |
| Declared to the sweep | not applicable | every allocation but the stack, within slbounce's 8 ranges |
| Hash checks | at load | at load **and** at EL2 before each payload's call |
| Shared code | | `q1n1_preload_manifest_valid`, `q1n1_preload_verify`, `sha256.c`, `tools/preload.py` |

## Deviations from the brief, and why

* A payload (a file named `<stem>.BIN`) is allocated as `EfiLoaderCode`, not `EfiLoaderData`: the firmware may map
  `EfiLoaderData` no-execute and nothing measured says the unit's does not (UNKNOWN). q1n1.efi itself runs from
  `EfiLoaderCode`. Data files stay `EfiLoaderData`; slbounce sweeps both. `tools/preload.py`'s `resident_cache` check
  expects `EfiLoaderData` and does not apply to this runner. OBSERVED once, by hand, on QEMU's EDK2
  (edk2-stable202408): a copy of the runner with file 0 in `EfiLoaderData` runs the same payload, so QEMU cannot
  tell the two apart and the choice is a precaution for the unit's firmware, not a measured need.
* The payload stack is allocated but not declared to the sweep: nothing is written to it before the bounce.
* The panel-region layout is a copy of the survey's `stk_layout`, pinned by a test against the survey's own
  function: no survey file may change, because the survey image must stay byte-identical.

## What the next payloads need from this ABI

The chain (several payloads in one boot) and the read-only `psci` queries now exist. Everything below is
UNIMPLEMENTED and, on the unit, UNKNOWN until `state` and `psci` have run there.

1. **PSCI `CPU_ON` of the secondaries into a payload-provided entry, to measure each one's arrival state.** This
   still needs more than the chain and `psci` give. A payload can issue the `SMC` itself (it is EL2 code, and `psci`
   shows how, with a whitelist and one helper); the conduit is SMC (OBSERVED, the FADT), and `psci` would say
   whether the firmware answers after the bounce, whether `CPU_ON` exists and whether the 11 secondaries read as
   OFF. What `CPU_ON` itself needs is not there: `psci` must never grow it, it is a separate, reviewed change that
   starts CPUs. A secondary starts at an entry address that must be a physical address (the payload knows
   `payload_base`, and the payload is position independent, so `payload_base + offset` works) with
   the MMU and caches off: the code must tolerate that, the code bytes are already clean (`sync_code`), and every
   word the payload shares with a secondary must be written non-cacheably or cleaned and invalidated by hand. It
   also needs memory the primary does not use: a **declared, zeroed scratch region** for per-CPU stacks and a
   mailbox, which the runner can describe in `reserved[]` without moving any field (a payload checks `a->size`).
   The CPU list (MPIDRs, parking addresses, PSCI conduit) comes from the ACPI tables (`psci` carries the twelve
   MPIDRs of the unit's MADT as constants, which is only right for this unit), so the EFI configuration table's RSDP
   pointer is the other thing to hand over. `puts` is not safe from a secondary: results go through the mailbox and
   the primary prints them.
2. **A payload that is the EL2 monitor and receives preloaded guest images.** The images are the data files 1-4,
   already loaded, hash-checked before the bounce, declared to the sweep and found through `preload_table`. It
   needs: a post-bounce `verify(index)` op for a data file (`q1n1_preload_verify` exists; only the payloads, the
   files named `.BIN`, are hashed at EL2 today, because a data file can be hundreds of megabytes); to take over
   `VBAR_EL2` and never return (a payload that does not return is already named by the `PAYLOAD CALL` line, and
   ends the chain); the memory map (already in `a`) to decide what is free, including q1n1's own image, table and
   stack; and, for guests over 256 MiB, either several files or a larger chunk budget in slbounce, which needs a
   change there and so its own decision.
3. **A payload that stores to device registers.** Needs an explicit authorization step before any such payload
   runs on hardware: a separate change that names the payload by SHA-256 and lists each register with its
   provenance (block, offset, SoC revision, evidence), reviewed under the `AGENTS.md` hardware-safety rules, and
   then a separate compile-time gate for a `store32` op (guarded, restricted to the listed windows, with its own
   budget) added behind a new ABI version. The op would keep the payload honest, not confine it: the review and the
   pinned digest are the real control.

## Open questions for the operator

* Does the unit's firmware map `EfiLoaderCode` executable? If the first run shows a fault page right after
  `PAYLOAD CALL`, a synchronous exception at ELR equal to the payload base with an instruction-abort class is the
  signature of a no-execute page.
* Is every page the firmware hands out mapped after the bounce, the high bank (from 0x880000000) included? The
  second hash reads each payload where it is.
* Does the firmware answer `smc #0` from EL2 after the bounce? With the stick above, the page after `PAYLOAD CALL 1`
  ends at `PAYLOAD PSCI NEXT VERSION` if it hangs there, or in a fault page (ELR inside `psci.bin`) if the `smc`
  raised an exception. Either is a result: say which group name was the last line.
* What do the eleven secondaries read as (`AFFINITY`), and are CPU_ON and SYSTEM_RESET implemented (`FEATURES`)?
* Should SMCCC_VERSION be asked only after PSCI_FEATURES says it exists, as Linux does? That needs the id
  `0x80000000` in the PSCI_FEATURES table, a change of the whitelist, so it is the operator's call.
* How should the Snapintosh autorun allow-list and staging (not changed here) name `SP11\Q1N1-PAYLOAD.EFI --el2`
  and the files `SP11\STATE.BIN`, `SP11\PSCI.BIN` and `SP11\PAYLOAD.MAN`?
