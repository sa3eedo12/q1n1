<!-- SPDX-License-Identifier: MIT -->
# SP11 stick payload runner: reviewed EL2 test code from the boot stick

A second q1n1 image, `Q1N1-PAYLOAD.EFI`, that loads a *payload* (a flat, position-independent binary) from the
volume it was started from, checks it, hands its pages to slbounce's scoped sweep, and after the Secure-Launch
bounce calls it at EL2 through a small ABI. The point is to run reviewed EL2 test code on the Surface Pro 11
**without rebuilding q1n1 and without a host link**: the unit has no UART, no USB link and no persistent log, so
a payload prints through q1n1's own page and the operator reads it with a phone camera. It is the foundation for
the next measurements (secondary CPUs through PSCI, an EL2 monitor, guest images; see the last section).

Evidence labels follow the Snapintosh `AGENTS.md`. Everything below is **EXPERIMENTAL**: built and tested on a
host and on QEMU's EDK2 (which gives the runner a real EL2); **hardware NOT RUN**. Facts about the unit are
labelled where they are used.

## Build

```sh
# the runner (a PE image) and the payloads (flat binaries)
make -f platform/uefi/Makefile SP11=1 PAYLOAD=1 \
    SP11_USB_TABLE_C=<file from sp11_usb_ports.py emit-c> \
    SP11_STAGE_TABLE_C=<file defining q1n1_sp11_stage_table_get()> \
    payload-runner payloads          # -> $(OUT)/q1n1-payload.efi and $(OUT)/payloads/state.bin
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
  keeps), and flattens it. Freestanding, no libc, general-regs-only, like the rest of q1n1.

## On the stick, and the one command

```sh
python3 tools/sp11_payload_manifest.py --out-dir build/stick build/uefi/payloads/state.bin [data1.bin ...]
```

writes `build/stick/SP11/PAYLOAD.MAN` and a capitalised 8.3 copy of every file below `build/stick/SP11/`, and
prints what to copy and what to run. Copy these to the stick, keeping the `SP11` directory:

| File on the stick | From |
| --- | --- |
| `SP11\Q1N1-PAYLOAD.EFI` | `$(OUT)/q1n1-payload.efi` (not written by the tool) |
| `SP11\PAYLOAD.MAN` | the tool |
| `SP11\STATE.BIN` | the tool (a copy of `state.bin`) |

Then, from the UEFI Shell, with slbounce loaded exactly as for q1n1 (`load SP11\SLBOUNCE-DEVHE-MARK.EFI`):

```
SP11\Q1N1-PAYLOAD.EFI --el2
```

There is no new option. The argument parser is unchanged: `--boot`, `--uart-proxy` and the no-argument preflight
never run the runner (QEMU test: the no-argument run prints no `PAYLOAD` line). The Snapintosh autorun allow-list
and staging are not touched here.

## The manifest

`\SP11\PAYLOAD.MAN`, on the volume the image was loaded from and nowhere else, in the A16 preload's `Q1N1PLD1`
format (`platform/uefi/preload.h`, `tools/preload.py`): a header, then per file its size, SHA-256 and path. File 0
is the payload; further files are data a payload finds through the preload table. The runner adds rules to the
shared validator: at most **5** files, every path below `\SP11\` (compared without regard to case), none of them
the manifest itself, each at most **256 MiB**. The tool enforces the same limits plus 8.3 names, which keeps FAT
long-name aliases out of the question, and writes nothing outside `--out-dir`. It holds no host path and no
machine identifier, and its output is deterministic.

Why 5 and 256 MiB: slbounce takes at most 8 declared ranges (`SP11_EBS_MAX_RANGES`) and the image, the memory-map
buffer and the preload table use 3; and it splits a range into at most 256 chunks (`SP11_SWEEP_MAX_OPS`) of the
1 MiB chunk cap q1n1 declares.

## What happens

**Before ExitBootServices** (every failure here returns to the Shell, nothing is bounced):

1. `sp11_payload_prepare`: EFI_LOADED_IMAGE.DeviceHandle -> SimpleFileSystem -> OpenVolume. No ConnectController,
   no enumeration of block devices or volumes, the internal disk is not looked at, nothing is written (files are
   opened for reading, mode 1). Reads and validates the manifest, then for each file: GetInfo size equals the
   manifest's, reads exactly that many bytes and probes for one more, AllocatePages, zeroes the rest of the last
   page, SHA-256 equals the manifest's. Then the preload table and the payload stack (below).
2. `leave_firmware`: allocates the memory-map buffer, then `sp11_declare_ranges` writes the declared table the
   sweep reads (`Q1N1Sp11EbsRanges`): **image, map buffer, preload table, then each file** (labels `image`, `map`,
   `preload`, `payload`, `file1`...). The framebuffer is never declared: it is RESERVED memory on the unit, which
   the sweep refuses by design, and nothing reads it after the bounce. `sp11_payload_precheck` then reads the map
   into the retry loop's buffer and applies slbounce's rules to each range, in its order (one descriptor, type
   1-6 or 9, write-back, at most 256 chunks). A refusal prints one `PAYLOAD REFUSED=...` line, **deletes the
   declared variable**, frees the map buffer and returns `EFI_ABORTED`; otherwise `PAYLOAD READY FILES=n RANGES=n`.
3. The retry loop (GetMemoryMap, ExitBootServices) is unchanged and nothing of the runner is in it: no allocation
   happens between the last GetMemoryMap and ExitBootServices (a source audit checks it).

**After the bounce, at EL2 only**, once q1n1's own page is drawn:

1. The notes from step 1 are replayed on the page. `PAYLOAD VERIFY=OK` follows a check that the preload table
   still describes what the runner loaded (count, and for each entry base, size, allocation and digest against the
   runner's own record) and that the payload, where it now is, still hashes to the manifest's digest. The payload
   is hashed twice, before and after the bounce; a payload that does not verify is **not called**
   (`PAYLOAD REFUSED=HASH_AT_EL2 INDEX=0 WANT= HAVE=`).
2. Data and instruction caches are synchronised over the payload's pages (DC CVAU, IC IVAU, with the line sizes
   from CTR_EL0), the guard words are written at the low end of the payload stack, and
   `PAYLOAD CALL <first 8 bytes of the hash>` is printed **before** the call, so a hang is named by the last line.
3. `q1n1_payload_call` keeps q1n1's callee-saved registers and its SP (in memory, not in a register) safe, puts SP
   at the top of the payload stack and calls the entry; a payload that breaks AAPCS64 still gives control back.
   Afterwards: `PAYLOAD RETURN=<value>`, `PAYLOAD STACK=OK|OVERFLOW` and `PAYLOAD OPS LOADS= FAULTS= REFUSED= LINES=
   DROPPED=`. A payload that faults lands in q1n1's existing fault page (QEMU test: its red bar).
4. Not at EL2 (QEMU with `virtualization=off`): `PAYLOAD SKIPPED=NOT_AT_EL2`, nothing is called, the survey-style
   page carries on.

The payload runs with D, A, I and F masked as q1n1 left them (`DAIF` 0x3C0, OBSERVED on the unit's page), so
q1n1's heartbeat and timer do not run while it does.

## Payload ABI v1 (`platform/uefi/sp11-payload-abi.h`)

```c
uint64_t payload_entry(const struct q1n1_payload_args *a);   /* offset 0 of the file; x0 = a; AAPCS64 */
```

Entered at EL2 by a `BLR` from q1n1 with `x0 = a` and `SP` = the top of the payload stack. It returns in `x0`; q1n1
prints the value. It calls into q1n1 **only through `a->ops`**. The layout is pinned by `_Static_assert` and by a
native test that compares it with the table below (`struct q1n1_payload_args` is 192 bytes, the ops table 32).

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
| 88 | 8 | `preload_table` | a `struct q1n1_preload_cache` (`preload.h`): entry 0 is this payload |
| 96 | 8 | `preload_size` | its size |
| 104 | 8 | `stack_base` | the payload stack is `[stack_base, stack_base + stack_size)` |
| 112 | 8 | `stack_size` | 64 KiB |
| 120 | 32 | `ops` | the ops table below |
| 152 | 40 | `reserved[5]` | zero in version 1; room for more ops or fields without moving any offset |

The ops table (offsets within `struct q1n1_payload_ops`; there is **no store** in it):

| Offset | Size | Op | Meaning |
| --- | --- | --- | --- |
| 0 | 8 | `ops.puts` | `void puts(const char *line)`: one line, drawn on the panel in the survey's region and mirrored to the UART when present, as the survey's `stk_emit` does. Truncated to 100 characters, lower case folded up, anything outside the page font (capitals, digits, `: - . / = ? ( ) _` and space) becomes `_`. At most 40 lines per call; later ones are counted as dropped. |
| 8 | 8 | `ops.hex` | `uint32_t hex(char *dst, uint32_t cap, uint64_t value)`: `0X` and the fewest upper-case digits (0 is `0X0`), cut to `cap`, returns the length |
| 16 | 8 | `ops.load32` | `int32_t load32(uint64_t addr, uint32_t *out)`: a recoverable-fault guarded read of one 32-bit word. Errors, not faults: 1 `out` is NULL, 2 misaligned, 3 `addr` beyond the 48-bit space, 4 `out` not inside the payload stack, 5 4096 loads already made, 6 the load aborted. |
| 24 | 8 | `ops.counter` | `uint64_t counter(void)`: CNTPCT_EL0 |
<!-- /abi-table -->

`load32` is a load only: the guarded copy writes into a variable of the runner's, and only after it succeeded is the
word stored into the payload's own stack (so it cannot be turned into a store to a device register). A load can
still hang the bus (an unclocked block), which no guard recovers: that is for the payload's reviewer to rule out
(INFERRED from the survey's experience; nothing measured).

**The stack.** A separate 64 KiB `EfiLoaderData` block, 16-byte aligned, allocated before the bounce, `SP` at its
top. It is not declared to the sweep: nothing is written to it before the bounce. The runner writes two guard
words at its low end after the bounce and reports `STACK=OVERFLOW` if the payload overwrote them. q1n1's own ops
run on it too, and an exception pushes a 272-byte frame onto it, so a payload should keep **at least 16 KiB free**
and may use the other 48 KiB. q1n1's own 256 KiB stack is untouched.

**No store is not a sandbox.** A payload is machine code at EL2: it can write wherever it likes. What keeps a
store to a device register out of it is that its bytes are reviewed and pinned by the SHA-256 in the manifest, and
that the runner verifies that digest twice. A payload that wants to write a device register needs a separate,
explicitly authorized change (AGENTS.md hardware safety rules; see the last section).

**Writing a payload.** `payloads/payload-util.h` (static inline helpers) and `payloads/state.c` are the template:
one C file, `uint64_t payload_entry(const struct q1n1_payload_args *a)`, check `pl_args_ok(a)`, no globals (a
writable `.data` or `.bss` is a link error: state lives on the stack), no libc. Constant data and strings in
`.rodata` are fine and are reached PC-relatively.

## The payload image

A flat binary. The linker script (`payloads/payload.ld`) links at 0 and puts the start stub (`payloads/start.S`:
`BTI c`, then `B payload_entry`) first, so the entry is offset 0; the firmware chooses the load address. The build
fails on any relocation outside the PC-relative list (an absolute pointer table, a MOVZ/MOVK address, a GOT
access), and a test links the reference payload at another address and compares the bytes.

## Reference payload `state` (read only)

Prints one line per register, `PAYLOAD STATE KEY=0XVALUE`, and nothing else. It executes `MRS` and no instruction
that writes a system register, a cache, a TLB or a device (a test disassembles the binary and refuses `MSR`, `SYS`,
`DC`, `IC`, `TLBI`, `AT`, `HVC`, `SMC`, `SVC`, `ERET`, `WFI`, `WFE`, exclusives and the rest). In particular it never
writes CNTKCTL_EL1, never reads CNTVOFF_EL2 or CNTPOFF_EL2, and does not depend on E2H (expected 0 on the unit,
OBSERVED through q1n1's page as HCR_EL2 0x88000010): TTBR1_EL2 is read exactly when HCR_EL2.E2H is set. CurrentEL
is read first and the EL2 block only when it says EL2, so the payload is also safe run any other way
(`EL2REGS=SKIPPED_NOT_AT_EL2`).

<!-- registers -->
| Key | Register | Readable at | Evidence |
| --- | --- | --- | --- |
| `CURRENTEL` | CurrentEL | EL1, EL2 | VERIFIED (architecture) |
| `MIDR_EL1` | MIDR_EL1 | EL1, EL2 | VERIFIED; unit value 0x512F0011 OBSERVED |
| `MPIDR_EL1` | MPIDR_EL1 | EL1, EL2 | VERIFIED |
| `ID_AA64MMFR0_EL1` | ID_AA64MMFR0_EL1 | EL1, EL2 | VERIFIED |
| `ID_AA64MMFR1_EL1` | ID_AA64MMFR1_EL1 | EL1, EL2 | VERIFIED |
| `ID_AA64MMFR2_EL1` | ID_AA64MMFR2_EL1 | EL1, EL2 | VERIFIED; read at EL2 by q1n1's X2 probe |
| `ID_AA64MMFR3_EL1` | S3_0_C0_C7_3 | EL1, EL2 | INFERRED: ID space, unallocated reads as zero, not UNDEFINED |
| `ID_AA64MMFR4_EL1` | S3_0_C0_C7_4 | EL1, EL2 | INFERRED: as above |
| `ID_AA64PFR0_EL1` | ID_AA64PFR0_EL1 | EL1, EL2 | VERIFIED |
| `ID_AA64PFR1_EL1` | ID_AA64PFR1_EL1 | EL1, EL2 | VERIFIED |
| `HCR_EL2` | HCR_EL2 | EL2 only | VERIFIED (architecture); value OBSERVED |
| `SCTLR_EL2` | SCTLR_EL2 | EL2 only | VERIFIED; value OBSERVED |
| `TCR_EL2` | TCR_EL2 | EL2 only | VERIFIED; value OBSERVED |
| `TTBR0_EL2` | TTBR0_EL2 | EL2 only | VERIFIED; value OBSERVED |
| `TTBR1_EL2` | S3_4_C2_C0_1 | EL2, only when E2H is set | VERIFIED (architecture); not expected to print |
| `MAIR_EL2` | MAIR_EL2 | EL2 only | VERIFIED; value OBSERVED |
| `VBAR_EL2` | VBAR_EL2 | EL2 only | VERIFIED; value OBSERVED |
| `CPTR_EL2` | CPTR_EL2 | EL2 only | VERIFIED; value OBSERVED |
| `CNTHCTL_EL2` | CNTHCTL_EL2 | EL2 only | VERIFIED; value OBSERVED |
| `CNTFRQ_EL0` | CNTFRQ_EL0 | EL0 and up | VERIFIED |
| `DAIF` | DAIF | EL1, EL2 | VERIFIED; 0x3C0 OBSERVED |
| `SPSEL` | SPSel | EL1, EL2 | VERIFIED |
| `EL2REGS` | (a note) | printed only when not at EL2 | `SKIPPED_NOT_AT_EL2` |
<!-- /registers -->

"VERIFIED (architecture)" means the Arm ARM says so, not that the unit was measured: **no hardware run exists**. The
values the unit showed on q1n1's own page are the only OBSERVED numbers.

## Line catalogue

On the firmware console before the bounce, and on the page and the UART after it (the notes are replayed):

| Line | Where | Meaning |
| --- | --- | --- |
| `PAYLOAD LOADED INDEX=n BASE=0X.. BYTES=n SHA=<16 hex> TYPE=1\|2` | both | file n loaded; the first 8 bytes of its SHA-256; 1 EfiLoaderCode (file 0), 2 EfiLoaderData |
| `PAYLOAD READY FILES=n RANGES=n` | both | the precheck passed with n declared ranges |
| `PAYLOAD REFUSED=<NAME> ...` | firmware console | a refusal before the bounce (below) |
| `PAYLOAD VERIFY=OK` | page | the second check passed |
| `PAYLOAD REFUSED=HASH_AT_EL2 INDEX=0 WANT= HAVE=` | page | the second check failed; not called |
| `PAYLOAD CALL <hash16>` | page | printed just before the call |
| `PAYLOAD STATE KEY=0XVALUE` | page | the reference payload's lines |
| `PAYLOAD RETURN=0X..` | page | what the payload returned |
| `PAYLOAD STACK=OK\|OVERFLOW` | page | the guard words |
| `PAYLOAD OPS LOADS= FAULTS= REFUSED= LINES= DROPPED=` | page | what the ops did: loads tried, guarded loads that faulted, refused loads, lines kept, lines dropped |
| `PAYLOAD SKIPPED=NOT_AT_EL2` | page | not at EL2: nothing called |

Every line is within the page font. The region on the panel is the survey's (right of the page, or below it); lines
past its last row are mirrored to the UART but not drawn.

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

## Tests

All host and QEMU only; hardware NOT RUN. Environment as for the other SP11 suites (`SLBOUNCE_SP11_DIR` adds the
comparison with slbounce's own `sp11_sweep_range`, `Q1N1_SP11_BASE_DIR` the byte-identity proofs, `SP11_UEFI_SHELL`
the run under the pinned UEFI Shell).

| Command | What it covers |
| --- | --- |
| `python3 tools/test-q1n1-sp11-payload.py` | four native programs under ASan and UBSan (the loader against a fake firmware, in which ConnectController and every other call outside the loader's list is a tripwire, a manifest on a second volume is ignored, nothing is written; the declared-range planner and slbounce's rules against synthetic maps shaped like the unit's and 30000 random maps; the text layer and the ABI layout; the EL2 sequence, the second hash, the ops and the load32 policy; the `state` payload against a scripted register file); 80 seeded-bug mutants and an unmutated control; source audits |
| `python3 tools/test-q1n1-sp11-payload-build.py` | the manifest tool, the ELF check (absolute pointers, MOVZ/MOVK addresses, writable globals, a PIE link, an unreadable file), the built binary (entry at offset 0, one page, identical when linked elsewhere, only the documented `MRS`), a payload with an absolute relocation failing the Makefile build, 13 seeded bugs in the two tools, and the default-off proof |
| `python3 tools/test-q1n1-sp11-payload-qemu.py` | QEMU/EDK2 at EL2 and EL1: the whole flow, every refusal, the call path with five test payloads (`tools/testdata/sp11-payload-fixture-*.c`) and two seeded variants of the runner |

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
  called; an unsupported request is an error, never a made-up success.
* The ops table has no store. `load32` is a guarded load with a destination restricted to the payload stack and a
  budget. The glue in `main.c` forwards loads only (a source audit checks it).
* The framebuffer is never declared. Nothing is allocated between the last GetMemoryMap and ExitBootServices.
* The payload hash is verified twice. A payload is not sandboxed (see above).
* Hardware rules of `AGENTS.md` apply to every payload: AC power or at least 50% battery, the thermal guard, no
  single `CP_MEMCPY` over 1 MiB, one hardware client at a time, nothing that changes persistent firmware, clocks or
  voltages without explicit authorization.

## Limits

* One payload per run, called once, at EL2 only, on the boot CPU. Secondary CPUs are parked by the firmware and not
  measured.
* At most 5 files of at most 256 MiB each (slbounce's capacity and chunk budget); no change to slbounce was made or
  is needed.
* No persistent log: the page and the UART (when there is one) are the only outputs. 40 lines per call, 100
  characters each; the panel region holds about 60.
* A hang is not recovered (named by the last line); a fault ends in q1n1's fault page.
* `main.c` was already over the 1500-line limit (2013 lines at the base commit); the glue added to it is about
  165 lines and kept thin, the policy is in the `sp11-payload-*` files, each well below the limit.

## Differences from the A16 preload

| | A16 `q1n1_preload` | This runner |
| --- | --- | --- |
| Manifest | `\Snapintosh\q1n1-preload.bin` | `\SP11\PAYLOAD.MAN` |
| Where it looks | connects **all** block devices and scans **every** volume | the volume the image was loaded from, nothing else |
| Writes | never | never; no volume other than the image's is even opened |
| Files | up to 16, 4 GiB in all, `EfiLoaderData` | up to 5, 256 MiB each; file 0 in `EfiLoaderCode`, the rest `EfiLoaderData` |
| Table | `q1n1_preload_cache` | the same layout, so one reader serves both |
| Purpose | resident cache for the host-link flow | file 0 is code that is called |
| Declared to the sweep | not applicable | every allocation but the stack, within slbounce's 8 ranges |
| Hash checks | at load | at load **and** at EL2 before the call |
| Shared code | | `q1n1_preload_manifest_valid`, `q1n1_preload_verify`, `sha256.c`, `tools/preload.py` |

## Deviations from the brief, and why

* File 0 is allocated as `EfiLoaderCode`, not `EfiLoaderData`: the firmware may map `EfiLoaderData` no-execute and
  nothing measured says the unit's does not (UNKNOWN). q1n1.efi itself runs from `EfiLoaderCode`. Data files stay
  `EfiLoaderData`; slbounce sweeps both. `tools/preload.py`'s `resident_cache` check expects `EfiLoaderData` and
  does not apply to this runner. OBSERVED once, by hand, on QEMU's EDK2 (edk2-stable202408): a copy of the runner
  with file 0 in `EfiLoaderData` runs the same payload, so QEMU cannot tell the two apart and the choice is a
  precaution for the unit's firmware, not a measured need.
* The payload stack is allocated but not declared to the sweep: nothing is written to it before the bounce.
* The panel-region layout is a copy of the survey's `stk_layout`, pinned by a test against the survey's own
  function: no survey file may change, because the survey image must stay byte-identical.

## What the next payloads need from this ABI

Nothing here is implemented.

1. **PSCI `CPU_ON` of the secondaries into a payload-provided entry, to measure each one's arrival state.** The
   payload can issue the `SMC`/`HVC` itself (it is EL2 code); whether a PSCI implementation answers after the
   bounce, and on which conduit, is UNKNOWN. A secondary starts at an entry address that must be a physical address
   (the payload knows `payload_base`, and the payload is position independent, so `payload_base + offset` works) with
   the MMU and caches off: the code must tolerate that, the code bytes are already clean (`sync_code`), and every
   word the payload shares with a secondary must be written non-cacheably or cleaned and invalidated by hand. It
   also needs memory the primary does not use: a **declared, zeroed scratch region** for per-CPU stacks and a
   mailbox, which the runner can describe in `reserved[]` without moving any field (a payload checks `a->size`).
   The CPU list (MPIDRs, parking addresses, PSCI conduit) comes from the ACPI tables, so the EFI configuration
   table's RSDP pointer is the other thing to hand over. `puts` is not safe from a secondary: results go through
   the mailbox and the primary prints them.
2. **A payload that is the EL2 monitor and receives preloaded guest images.** The images are the data files 1-4,
   already loaded, hash-checked before the bounce, declared to the sweep and found through `preload_table`. It
   needs: a post-bounce `verify(index)` op for a data file (`q1n1_preload_verify` exists; only file 0 is hashed
   at EL2 today, because a data file can be hundreds of megabytes); to take over `VBAR_EL2` and never return (a
   payload that does not return is already named by the `PAYLOAD CALL` line); the memory map (already in `a`) to
   decide what is free, including q1n1's own image, table and stack; and, for guests over 256 MiB, either several
   files or a larger chunk budget in slbounce, which needs a change there and so its own decision.
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
  second hash reads the payload where it is.
* How should the Snapintosh autorun allow-list and staging (not changed here) name `SP11\Q1N1-PAYLOAD.EFI --el2`?
