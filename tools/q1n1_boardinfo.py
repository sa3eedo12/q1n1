#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Carry Snapintosh's board-info blob to the EL2 monitor through q1n1's proxy heap.

Default off: nothing in q1n1 imports this module and no payload code reads the
slot, so while it is unused every q1n1 output is unchanged. A host tool opts in
by building a HostProxyTransport with an explicit heap offset; there is no
default offset on purpose.

The blob (Snapintosh compat/board-info.h, packed by Snapintosh
probes/boardinfo.py) is opaque here. Only its framing is checked -- magic,
self-declared length, size cap, CRC32 -- so a truncated or corrupted file never
reaches the target. What the fields mean is the monitor's business:
board_info_validate() in the monitor is the only authority. A caller that wants
Snapintosh's Python mirror of it to run first passes it as `validator` (for
example probes.boardinfo.validate); this module imports nothing from Snapintosh.

See docs/BOARD-INFO.md for the placement contract and the removal path.
"""
from __future__ import annotations

import abc
import struct
import zlib
from typing import Callable, NamedTuple, Optional

MAGIC = b'SNAPBRDI'
HEADER_BYTES = 32
LENGTH_OFFSET = 16   # u32 total_length
CRC_OFFSET = 20      # u32 crc32, computed with these four bytes zeroed
# The ABI maximum total_length. A slot is always written and cleared whole, so a
# shorter blob placed over a longer one can never leave a stale tail behind.
SLOT_BYTES = 4096
PAGE_BYTES = 4096


class BoardInfoCarrierError(RuntimeError):
    """The blob or the target was refused.

    After a failure that follows a write the slot content is unspecified and
    must not be booted on; the monitor's own validation refuses a damaged blob
    regardless."""


class Placement(NamedTuple):
    address: int        # absolute target address of the slot
    heap_offset: int    # slot offset from heap_base: the value the monitor side must agree on
    heap_base: int      # q1n1 heap base at placement; a moved heap makes the address stale
    length: int         # the blob's total_length
    crc32: int          # the blob's own CRC field


def check_framing(blob):
    """Return (length, crc32) of an intact blob, or raise BoardInfoCarrierError.

    Version-agnostic on purpose: ABI major/minor, flags and field values belong
    to the monitor, so a newer minor passes here. The declared length must equal
    the buffer so neither a truncated blob nor one padded with stale bytes is
    carried silently."""
    if not isinstance(blob, (bytes, bytearray, memoryview)):
        raise BoardInfoCarrierError(f'a blob must be bytes-like, not {type(blob).__name__}')
    data = bytes(blob)
    if len(data) < HEADER_BYTES:
        raise BoardInfoCarrierError(f'{len(data)} bytes is shorter than the {HEADER_BYTES}-byte header')
    if data[:len(MAGIC)] != MAGIC:
        raise BoardInfoCarrierError('bad magic: not a Snapintosh board-info blob')
    total, crc = struct.unpack_from('<II', data, LENGTH_OFFSET)
    if total != len(data):
        raise BoardInfoCarrierError(f'the blob declares {total} bytes but {len(data)} were supplied')
    if total % 8 or total > SLOT_BYTES:
        raise BoardInfoCarrierError(f'length {total} is not a multiple of 8 within the {SLOT_BYTES}-byte cap')
    if zlib.crc32(data[:CRC_OFFSET] + bytes(4) + data[CRC_OFFSET + 4:]) != crc:
        raise BoardInfoCarrierError('CRC32 mismatch: the blob is corrupted')
    return total, crc


class BoardInfoTransport(abc.ABC):
    """How a framed blob reaches the monitor.

    Named for what it carries: q1n1proxy.Transport is already the byte transport
    under the proxy link. HostProxyTransport is the transitional, host-driven
    implementation. For standalone operation (D8) the blob moves into the
    monitor image or the UEFI stub and a carrier that needs no host replaces it;
    callers depend only on this interface."""

    @abc.abstractmethod
    def place(self, blob) -> Placement:
        """Make `blob` available to the monitor, refusing anything that fails the framing check."""

    @abc.abstractmethod
    def read_back(self, placement: Placement) -> bytes:
        """The blob as the target now holds it, proven intact against `placement`."""

    @abc.abstractmethod
    def clear(self, placement: Placement) -> None:
        """Erase the slot so a later boot cannot pick up a stale board."""


class HostProxyTransport(BoardInfoTransport):
    """Write the blob into q1n1's heap over the proxy, from a host that stays attached.

    `proxy` is a q1n1proxy.Proxy. `heap_offset` is where the slot sits relative
    to bootinfo.heap_base. The heap layout is owned by the Snapintosh host
    tools, so the caller names the offset and agrees it with the monitor side;
    q1n1 never looks at the slot. `validator`, if given, is called with the blob
    bytes before anything is written and again on the read-back; it must raise
    to refuse, and what it raises propagates unchanged."""

    def __init__(self, proxy, heap_offset: int, validator: Optional[Callable[[bytes], object]] = None):
        if isinstance(heap_offset, bool) or not isinstance(heap_offset, int) or heap_offset < 0 \
                or heap_offset % PAGE_BYTES:
            raise BoardInfoCarrierError(f'heap_offset must be a non-negative multiple of {PAGE_BYTES}: {heap_offset!r}')
        if validator is not None and not callable(validator):
            raise BoardInfoCarrierError('validator must be callable')
        self.proxy = proxy
        self.heap_offset = heap_offset
        self.validator = validator

    def _locate(self):
        info = self.proxy.bootinfo()
        base, size = info['heap_base'], info['heap_size']
        # UEFI AllocatePages hands q1n1 a page-aligned heap; anything else means
        # bootinfo was misread, and a slot computed from it would be wrong.
        if not base or base % PAGE_BYTES:
            raise BoardInfoCarrierError(f'q1n1 heap base {base:#x} is unset or not page aligned')
        if size < self.heap_offset + SLOT_BYTES:
            raise BoardInfoCarrierError(
                f'the q1n1 heap is {size:#x} bytes: a {SLOT_BYTES:#x}-byte slot at {self.heap_offset:#x} does not fit')
        return base, base + self.heap_offset

    def _located_for(self, placement):
        base, address = self._locate()
        if base != placement.heap_base or address != placement.address:
            raise BoardInfoCarrierError('the q1n1 heap moved since the blob was placed: the address is stale')
        return address

    def _store(self, address, slot):
        self.proxy.writemem(address, slot)
        # Clean to the point of coherency so a reader that does not hit q1n1's
        # cache lines (the monitor with its MMU or caches off) sees these bytes.
        self.proxy.request(self.proxy.P_DC_CVAC, address, len(slot))
        # The read goes through q1n1's own view of memory: it proves the write
        # landed, not what a cache-bypassing reader sees.
        if self.proxy.readmem(address, len(slot)) != slot:
            raise BoardInfoCarrierError(f'read-back at {address:#x} differs from what was written')

    def place(self, blob):
        length, crc = check_framing(blob)
        data = bytes(blob)
        if self.validator is not None:
            self.validator(data)
        base, address = self._locate()
        self._store(address, data.ljust(SLOT_BYTES, b'\0'))
        return Placement(address, self.heap_offset, base, length, crc)

    def read_back(self, placement):
        if not HEADER_BYTES <= placement.length <= SLOT_BYTES:
            raise BoardInfoCarrierError(f'placement length {placement.length} is outside the slot')
        address = self._located_for(placement)
        data = self.proxy.readmem(address, placement.length)
        if check_framing(data) != (placement.length, placement.crc32):
            raise BoardInfoCarrierError('the slot holds a different blob than the one placed')
        if self.validator is not None:
            self.validator(data)
        return data

    def clear(self, placement):
        self._store(self._located_for(placement), bytes(SLOT_BYTES))
