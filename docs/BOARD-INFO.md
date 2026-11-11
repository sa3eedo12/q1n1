# Board-info blob placement (default off)

Snapintosh's EL2 monitor can be told which board it is running on through a
small, versioned, CRC-protected blob (`compat/board-info.h` in Snapintosh,
packed by its `probes/boardinfo.py`). To q1n1 the blob is opaque bytes: no
payload code reads it, and no existing q1n1 file changed to carry it. This page
is the placement contract between the Snapintosh host tools and the monitor,
and the reference for the host-side carrier in `tools/q1n1_boardinfo.py`.

The feature is default off. Nothing imports the module, there is no default slot
offset, and a q1n1 build, stage or tool that does not construct a
`HostProxyTransport` behaves exactly as before.

## Placement contract

| Item | Contract |
| --- | --- |
| Carrier | q1n1's proxy heap: `bootinfo.heap_base`, `bootinfo.heap_size` |
| Slot | `heap_base + heap_offset`, 4096 bytes (`SLOT_BYTES`, the ABI's maximum blob length) |
| `heap_offset` | A non-negative multiple of 4096, chosen by the Snapintosh host tools, which own the heap layout. The transport has no default. |
| Content | The blob, then zero padding to 4096 bytes. Every `place()` and `clear()` rewrites the whole slot, so a shorter blob never leaves the tail of a longer one. |
| Validity | While the heap stays where it was. `Placement.heap_base` records it, and `read_back()` and `clear()` refuse a placement once bootinfo reports another heap. |
| Consumer | The monitor, which must be handed the slot address by the Snapintosh host tools and run `board_info_validate()` on it. An absent or zeroed slot fails that validation (bad magic), so a cleared slot means "no board", never a default board. |

The heap is 64 MiB, allocated with UEFI `AllocatePages` (`platform/uefi/main.c`,
`HEAP_BYTES` and the `allocate_pages` call), so its base is page aligned. The
USB arena is carved from its top (`main.c`, `Q1N1_USB_ARENA_SIZE`), so a slot in
the low megabytes does not collide with it. Which low offset is free is
Snapintosh's knowledge: its code reserve, report area, SMP configuration page
and monitor work area all live there. A candidate offset is proposed in the
Snapintosh patch notes for the maintainers to adopt; this repository does not
pin one.

## What `HostProxyTransport.place()` does

1. `check_framing()`: bytes-like, at least the 32-byte header, magic
   `SNAPBRDI`, declared `total_length` equal to the buffer, a multiple of 8 and
   at most 4096, and the CRC32 over the blob with the CRC field zeroed. It does
   not look at the ABI version, flags or field values.
2. The optional `validator` callable, for example Snapintosh's
   `probes.boardinfo.validate`, which must raise to refuse. Nothing has been
   written when either step refuses.
3. `Proxy.bootinfo()` and the heap checks: base nonzero and page aligned, heap
   large enough for the slot.
4. One whole-slot `writemem`, then `P_DC_CVAC` over the slot. The clean to the
   point of coherency is the conservative choice for a reader that does not hit
   q1n1's cache lines, such as the monitor with its MMU or caches off. The
   payload implements it as a `DC CVAC` loop followed by `dsb ish`
   (`platform/uefi/q1n1-proxy.c`, `CACHE_RANGE`).
5. A checksummed, non-live read-back compared with what was written.

`read_back()` re-checks the framing and that the slot still holds the placed
blob (same length and CRC), and runs the validator again. `clear()` zeroes the
slot with the same write, clean and read-back.

## What this does not prove

- The read-back goes through q1n1's own view of memory. It proves the write
  landed, not what a cache-bypassing reader will see; the cache clean is what
  covers that, and it cannot be observed from the host.
- `board_info_validate()` in the monitor is authoritative. A blob can have
  correct framing and still be refused by the monitor (an unknown ABI major, for
  example); the carrier does not judge that and a `validator` is optional.
- The monitor side is not wired: nothing yet passes the slot address to the
  monitor or calls `board_info_validate()` on it. Until it is, a placed blob has
  no effect.

## Removal path (D8: standalone operation)

`HostProxyTransport` is transitional: it needs a host attached over the proxy.
`BoardInfoTransport` is the interface that survives. For standalone execution
the blob moves into the monitor image or the UEFI stub, which hands the monitor
its address without a host, and a carrier with that behaviour replaces
`HostProxyTransport`. The interface is named for its payload because
`q1n1proxy.Transport` already names the byte transport under the proxy link.

## Tests

`python3 tools/test-q1n1-boardinfo.py` drives the real `q1n1proxy.Proxy` over a
fake byte link backed by a model of target memory: framing faults, offset and
heap refusals, whole-slot writes and stale tails, cache-clean ordering and
refusal, read-back mismatch, moved-heap staleness, validator ordering, and
default-off checks (the client does not load the module; no other q1n1 file
refers to it; it imports only the standard library). Set `SNAPINTOSH_DIR` to a
Snapintosh checkout to also pack its shipped board descriptors and check the
placed slot against its Python mirror of `board_info_validate()`; without it
that case is skipped.

The tests do not run on hardware and do not use the native protocol harness
(`tools/test-q1n1-proxy.py`), which models no cache maintenance and an unaligned
heap. A real proxy link and a real target are NOT RUN.

## Evidence labels

| Statement | Label |
| --- | --- |
| The heap is 64 MiB from `AllocatePages`; the USB arena is at its top; `P_DC_CVAC` is a `dc cvac` loop plus `dsb ish` | VERIFIED by reading this tree |
| The carrier's framing, ordering and refusals | VERIFIED by host tests against a modelled link |
| The monitor reads the slot after the clean, and the heap survives a chainload | INFERRED; nothing here exercises either |
| Monitor wiring and a standalone carrier | UNIMPLEMENTED |
