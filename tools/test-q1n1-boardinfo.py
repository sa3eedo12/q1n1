#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Host tests for tools/q1n1_boardinfo.py, the default-off board-info carrier.

A real q1n1proxy.Proxy runs over a fake Link backed by a model of target
memory, so bootinfo parsing, request framing and memory access are the client's
own code; only the byte link below it is modelled. Nothing here touches
hardware or writes a file. The blobs are synthetic: valid framing around
filler, never a real board.

Set SNAPINTOSH_DIR to a Snapintosh checkout to also run the end-to-end case
that packs the shipped board descriptors with that tree's probes/boardinfo.py;
without it that case is skipped.
"""
import ast
import importlib.util
import inspect
import os
from pathlib import Path
import struct
import subprocess
import sys
import types
import unittest
import zlib

import q1n1_boardinfo as bi
import q1n1proxy

ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / 'tools'
DOC = ROOT / 'docs' / 'BOARD-INFO.md'
# Arbitrary model addresses: no hardware meaning.
HEAP_BASE = 0x40000000
HEAP_SIZE = 0x10000
OFFSET = 0x3000
BOOTINFO_AT = 0x20000000
CVAC = q1n1proxy.Proxy.P_DC_CVAC


def refresh_crc(blob):
    blob = bytearray(blob)
    blob[20:24] = bytes(4)
    struct.pack_into('<I', blob, 20, zlib.crc32(bytes(blob)))
    return bytes(blob)


def make_blob(total=2168, major=1, minor=0, seed=0x5a):
    """Valid framing around filler. Literal ABI constants, so a wrong constant in the module cannot hide."""
    blob = bytearray(total)
    blob[:8] = b'SNAPBRDI'
    struct.pack_into('<III', blob, 8, major, minor, total)
    for index in range(32, total):
        blob[index] = (seed + 7 * index) & 0xff
    return refresh_crc(blob)


def bootinfo_block(values):
    fields = q1n1proxy.BOOTINFO_FIELDS
    merged = dict.fromkeys(fields, 0)
    merged.update(magic=q1n1proxy.MAGIC, version=1, size=8 * len(fields))
    merged.update(values)
    return struct.pack(f'<{len(fields)}Q', *(merged[name] for name in fields))


class FakeLink:
    """The byte link under a real Proxy. `events` logs heap traffic and non-bootinfo requests in order."""

    def __init__(self, sentinel=0):
        self.heap = bytearray([sentinel]) * HEAP_SIZE
        self.values = {'heap_base': HEAP_BASE, 'heap_size': HEAP_SIZE}
        self.events = []
        self.reject = set()
        self.tamper = None
        self.transport = types.SimpleNamespace()
        self.features = 0
        self.exception_handler = None

    def _offset(self, address, size):
        offset = address - HEAP_BASE
        if not 0 <= offset <= HEAP_SIZE - size:
            raise q1n1proxy.ProxyError(f'transfer outside the modelled heap: {address:#x}+{size:#x}')
        return offset

    def proxyreq(self, request, no_reply=False, timeout=None):
        opcode, *args = struct.unpack('<7Q', request)
        status, value = 0, 0
        if opcode == q1n1proxy.Proxy.P_GET_BOOTARGS:
            value = BOOTINFO_AT
        else:
            self.events.append(('request', opcode, tuple(args[:2])))
            if opcode in self.reject or opcode != CVAC:
                status = -1
        return struct.pack('<QqQ', opcode, status, value)

    def readmem(self, address, size, timeout=None, attempts=3):
        if address == BOOTINFO_AT:
            return bootinfo_block(self.values)[:size]
        self.events.append(('read', address, size))
        offset = self._offset(address, size)
        return bytes(self.heap[offset:offset + size])

    def writemem(self, address, data, timeout=None):
        self.events.append(('write', address, len(data)))
        offset = self._offset(address, len(data))
        self.heap[offset:offset + len(data)] = self.tamper(data) if self.tamper else data


class Target(unittest.TestCase):
    def setUp(self):
        self.link = FakeLink()
        self.proxy = q1n1proxy.Proxy(self.link)
        self.transport = bi.HostProxyTransport(self.proxy, OFFSET)

    def slot(self):
        return bytes(self.link.heap[OFFSET:OFFSET + bi.SLOT_BYTES])


class Framing(unittest.TestCase):
    def test_the_framing_constants_are_the_abi_ones(self):
        self.assertEqual((bi.MAGIC, bi.HEADER_BYTES, bi.LENGTH_OFFSET, bi.CRC_OFFSET, bi.SLOT_BYTES, bi.PAGE_BYTES),
                         (b'SNAPBRDI', 32, 16, 20, 4096, 4096))
        self.assertEqual(bi.Placement._fields, ('address', 'heap_offset', 'heap_base', 'length', 'crc32'))

    def test_a_well_formed_blob_passes_at_every_legal_size(self):
        for total in (32, 40, 2168, 4096):
            blob = make_blob(total)
            self.assertEqual(bi.check_framing(blob), (total, struct.unpack_from('<I', blob, 20)[0]))

    def test_bytes_like_inputs_only(self):
        blob = make_blob()
        for accepted in (bytearray(blob), memoryview(blob)):
            self.assertEqual(bi.check_framing(accepted)[0], len(blob))
        for refused in (blob.hex(), 2168, None, [blob], object()):
            with self.assertRaisesRegex(bi.BoardInfoCarrierError, 'bytes-like'):
                bi.check_framing(refused)

    def test_every_framing_fault_is_refused_with_its_own_reason(self):
        good = make_blob()
        flipped_magic = bytes([good[0] ^ 1]) + good[1:]
        last_magic = good[:7] + bytes([good[7] ^ 1]) + good[8:]
        flipped_payload = good[:100] + bytes([good[100] ^ 1]) + good[101:]
        flipped_crc = good[:20] + bytes([good[20] ^ 1]) + good[21:]
        header_not_covered = bytearray(good)
        header_not_covered[20:24] = struct.pack('<I', zlib.crc32(good[bi.HEADER_BYTES:]))
        cases = [
            ('empty', b'', 'shorter than'),
            ('one byte short of a header', good[:31], 'shorter than'),
            ('first magic byte', flipped_magic, 'magic'),
            ('last magic byte', last_magic, 'magic'),
            ('buffer longer than declared', good + bytes(8), 'declares'),
            ('buffer one byte longer', good + b'\0', 'declares'),
            ('buffer shorter than declared', good[:-8], 'declares'),
            ('length not a multiple of 8', make_blob(2169), 'multiple of 8'),
            ('length a multiple of 4 only', make_blob(2172), 'multiple of 8'),
            ('length over the cap', make_blob(4104), 'cap'),
            ('corrupted payload', flipped_payload, 'CRC'),
            ('corrupted CRC field', flipped_crc, 'CRC'),
            ('CRC that leaves the header out', bytes(header_not_covered), 'CRC'),
        ]
        for label, blob, reason in cases:
            with self.subTest(label), self.assertRaisesRegex(bi.BoardInfoCarrierError, reason):
                bi.check_framing(blob)

    def test_the_carrier_does_not_judge_the_abi_version(self):
        for major, minor in ((2, 0), (1, 9), (0, 0)):
            self.assertEqual(bi.check_framing(make_blob(major=major, minor=minor))[0], 2168)


class Construction(unittest.TestCase):
    def test_heap_offset_must_be_a_non_negative_page_multiple(self):
        for bad in (-4096, -1, 1, 0x1800, 4097, '0x1000', None, True, False, 4096.0, [4096]):
            with self.subTest(repr(bad)), self.assertRaisesRegex(bi.BoardInfoCarrierError, 'heap_offset'):
                bi.HostProxyTransport(object(), bad)
        for good in (0, 4096, 0x4f1000):
            self.assertEqual(bi.HostProxyTransport(object(), good).heap_offset, good)

    def test_the_validator_must_be_callable(self):
        with self.assertRaisesRegex(bi.BoardInfoCarrierError, 'callable'):
            bi.HostProxyTransport(object(), 0, validator='probes.boardinfo.validate')

    def test_there_is_no_default_offset_so_the_feature_is_off_until_asked_for(self):
        parameter = inspect.signature(bi.HostProxyTransport).parameters['heap_offset']
        self.assertIs(parameter.default, inspect.Parameter.empty)
        with self.assertRaises(TypeError):
            bi.HostProxyTransport(object())

    def test_the_interface_is_abstract_and_complete(self):
        with self.assertRaises(TypeError):
            bi.BoardInfoTransport()

        class Incomplete(bi.BoardInfoTransport):
            def place(self, blob):
                raise NotImplementedError

            def read_back(self, placement):
                raise NotImplementedError

        with self.assertRaises(TypeError):
            Incomplete()
        self.assertTrue(issubclass(bi.HostProxyTransport, bi.BoardInfoTransport))
        self.assertEqual(bi.BoardInfoTransport.__abstractmethods__, {'place', 'read_back', 'clear'})


class Placement(Target):
    def test_place_writes_one_whole_slot_cleans_it_then_reads_it_back(self):
        blob = make_blob()
        placement = self.transport.place(blob)
        address = HEAP_BASE + OFFSET
        self.assertEqual(self.link.events, [('write', address, 4096), ('request', CVAC, (address, 4096)),
                                            ('read', address, 4096)])
        crc = struct.unpack_from('<I', blob, 20)[0]
        self.assertEqual(placement, bi.Placement(address, OFFSET, HEAP_BASE, 2168, crc))

    def test_the_slot_holds_the_blob_then_zeros_and_its_neighbours_are_untouched(self):
        self.link = FakeLink(sentinel=0xa5)
        self.proxy = q1n1proxy.Proxy(self.link)
        blob = make_blob()
        bi.HostProxyTransport(self.proxy, OFFSET).place(blob)
        self.assertEqual(self.slot(), blob + bytes(4096 - len(blob)))
        self.assertEqual(set(self.link.heap[:OFFSET]), {0xa5})
        self.assertEqual(set(self.link.heap[OFFSET + 4096:]), {0xa5})

    def test_replacing_a_larger_blob_leaves_no_stale_tail(self):
        self.transport.place(make_blob(4096))
        small = make_blob(2168, seed=0x11)
        placement = self.transport.place(small)
        self.assertEqual(self.slot(), small + bytes(4096 - 2168))
        self.assertEqual(self.transport.read_back(placement), small)

    def test_read_back_returns_the_placed_blob(self):
        blob = make_blob()
        self.assertEqual(self.transport.read_back(self.transport.place(blob)), blob)

    def test_a_blob_with_bad_framing_reaches_neither_the_target_nor_bootinfo(self):
        for bad in (make_blob()[:-8], make_blob(major=1)[:100] + bytes(2068)):
            with self.assertRaises(bi.BoardInfoCarrierError):
                self.transport.place(bad)
        self.assertEqual(self.link.events, [])
        self.assertEqual(set(self.link.heap), {0})

    def test_read_back_refuses_a_slot_damaged_after_placement(self):
        for position, reason in ((100, 'CRC'), (0, 'magic'), (21, 'CRC')):
            with self.subTest(position):
                placement = self.transport.place(make_blob())
                self.link.heap[OFFSET + position] ^= 1
                with self.assertRaisesRegex(bi.BoardInfoCarrierError, reason):
                    self.transport.read_back(placement)

    def test_read_back_refuses_a_different_valid_blob(self):
        placement = self.transport.place(make_blob())
        self.link.heap[OFFSET:OFFSET + 2168] = make_blob(2168, seed=0x11)
        with self.assertRaisesRegex(bi.BoardInfoCarrierError, 'different blob'):
            self.transport.read_back(placement)

    def test_a_moved_heap_makes_the_placement_stale_and_touches_nothing(self):
        placement = self.transport.place(make_blob())
        for moved in (HEAP_BASE + 0x1000, HEAP_BASE - 0x1000):
            self.link.values['heap_base'] = moved
            before = list(self.link.events)
            for action in (self.transport.read_back, self.transport.clear):
                with self.subTest(moved=hex(moved), action=action.__name__), \
                        self.assertRaisesRegex(bi.BoardInfoCarrierError, 'moved'):
                    action(placement)
            self.assertEqual(self.link.events, before)

    def test_a_placement_that_disagrees_with_the_live_heap_in_either_field_is_stale(self):
        placement = self.transport.place(make_blob())
        before = list(self.link.events)
        for label, forged in (('heap base', placement._replace(heap_base=HEAP_BASE + 0x1000)),
                              ('address', placement._replace(address=placement.address + 0x1000))):
            for action in (self.transport.read_back, self.transport.clear):
                with self.subTest(label, action=action.__name__), \
                        self.assertRaisesRegex(bi.BoardInfoCarrierError, 'moved'):
                    action(forged)
        self.assertEqual(self.link.events, before)

    def test_clear_erases_the_whole_slot_whatever_the_placement_says(self):
        placement = self.transport.place(make_blob(2168))
        self.link.heap[OFFSET + 3000] = 0xee      # another writer's stale tail, beyond the placed blob
        self.link.events.clear()
        self.transport.clear(placement)
        self.assertEqual(self.slot(), bytes(4096))
        self.assertEqual(self.link.events[0], ('write', HEAP_BASE + OFFSET, 4096))

    def test_a_forged_placement_length_is_refused_before_any_read(self):
        placement = self.transport.place(make_blob())
        before = list(self.link.events)
        for length in (0, 31, 4097, 1 << 40):
            with self.subTest(length), self.assertRaisesRegex(bi.BoardInfoCarrierError, 'outside the slot'):
                self.transport.read_back(placement._replace(length=length))
        self.assertEqual(self.link.events, before)

    def test_a_placement_of_exactly_a_header_or_exactly_a_slot_is_read_back(self):
        # Both ends are legal lengths, so neither may be mistaken for "outside the slot".
        for total in (32, 4096):
            with self.subTest(total):
                blob = make_blob(total)
                placement = self.transport.place(blob)
                self.assertEqual(placement.length, total)
                self.assertEqual(self.transport.read_back(placement), blob)

    def test_clear_zeroes_the_whole_slot_and_cleans_the_cache(self):
        placement = self.transport.place(make_blob(4096))
        self.link.events.clear()
        self.transport.clear(placement)
        address = HEAP_BASE + OFFSET
        self.assertEqual(self.slot(), bytes(4096))
        self.assertEqual(self.link.events, [('write', address, 4096), ('request', CVAC, (address, 4096)),
                                            ('read', address, 4096)])
        with self.assertRaisesRegex(bi.BoardInfoCarrierError, 'magic'):
            self.transport.read_back(placement)

    def test_an_unusable_heap_is_refused_before_any_write(self):
        cases = [('heap base unset', {'heap_base': 0}, 'not page aligned'),
                 ('heap base not page aligned', {'heap_base': HEAP_BASE + 8}, 'not page aligned'),
                 ('heap one byte too small', {'heap_size': OFFSET + 4095}, 'does not fit'),
                 ('heap empty', {'heap_size': 0}, 'does not fit')]
        for label, values, reason in cases:
            with self.subTest(label):
                self.link.values.update(values)
                with self.assertRaisesRegex(bi.BoardInfoCarrierError, reason):
                    self.transport.place(make_blob())
                self.assertEqual(self.link.events, [])
                self.link.values.update(heap_base=HEAP_BASE, heap_size=HEAP_SIZE)

    def test_a_heap_exactly_big_enough_is_accepted(self):
        self.link.values['heap_size'] = OFFSET + 4096
        self.assertEqual(self.transport.place(make_blob()).heap_offset, OFFSET)

    def test_a_failed_read_back_is_an_error_not_a_placement(self):
        self.link.tamper = lambda data: data[:-1] + bytes([data[-1] ^ 1])
        with self.assertRaisesRegex(bi.BoardInfoCarrierError, 'read-back'):
            self.transport.place(make_blob())

    def test_a_refused_cache_clean_is_not_swallowed_and_stops_before_the_read_back(self):
        self.link.reject = {CVAC}
        with self.assertRaises(q1n1proxy.ProxyRemoteError):
            self.transport.place(make_blob())
        self.assertEqual([event[0] for event in self.link.events], ['write', 'request'])

    def test_an_invalid_bootinfo_stops_everything(self):
        self.link.values['magic'] = 0
        with self.assertRaisesRegex(q1n1proxy.ProxyError, 'bootinfo'):
            self.transport.place(make_blob())
        self.assertEqual(self.link.events, [])


class Validator(Target):
    def test_it_sees_the_exact_bytes_before_the_write_and_again_on_read_back(self):
        calls = []
        transport = bi.HostProxyTransport(self.proxy, OFFSET, validator=calls.append)
        blob = make_blob()
        placement = transport.place(bytearray(blob))
        self.assertEqual(calls, [blob])
        self.assertIs(type(calls[0]), bytes)
        transport.read_back(placement)
        self.assertEqual(calls, [blob, blob])

    def test_a_refusal_propagates_unchanged_and_nothing_is_written(self):
        class Refused(Exception):
            pass

        def refuse(data):
            raise Refused(len(data))

        with self.assertRaises(Refused) as caught:
            bi.HostProxyTransport(self.proxy, OFFSET, validator=refuse).place(make_blob())
        self.assertEqual(caught.exception.args, (2168,))
        self.assertEqual(self.link.events, [])

    def test_a_refusal_on_read_back_propagates(self):
        transport = bi.HostProxyTransport(self.proxy, OFFSET)
        placement = transport.place(make_blob())
        transport.validator = lambda data: (_ for _ in ()).throw(ValueError('refused'))
        with self.assertRaisesRegex(ValueError, 'refused'):
            transport.read_back(placement)

    def test_it_runs_after_the_framing_check(self):
        calls = []
        with self.assertRaises(bi.BoardInfoCarrierError):
            bi.HostProxyTransport(self.proxy, OFFSET, validator=calls.append).place(make_blob()[:-8])
        self.assertEqual(calls, [])


class ProxyContract(unittest.TestCase):
    """What the carrier relies on in the client and the payload, pinned so drift is a failure here."""

    def test_the_client_surface_the_carrier_uses(self):
        proxy = q1n1proxy.Proxy
        self.assertEqual(CVAC, 0x308)
        self.assertEqual(list(inspect.signature(proxy.writemem).parameters), ['self', 'address', 'data'])
        self.assertEqual(list(inspect.signature(proxy.readmem).parameters), ['self', 'address', 'size', 'live'])
        self.assertEqual(list(inspect.signature(proxy.request).parameters),
                         ['self', 'opcode', 'args', 'no_reply', 'timeout'])
        self.assertLessEqual({'heap_base', 'heap_size'}, set(q1n1proxy.BOOTINFO_FIELDS))
        info = q1n1proxy.Proxy(FakeLink()).bootinfo()
        self.assertEqual((info['heap_base'], info['heap_size']), (HEAP_BASE, HEAP_SIZE))

    def test_the_payload_cleans_a_range_by_va_for_that_opcode(self):
        source = ROOT / 'platform' / 'uefi' / 'q1n1-proxy.c'
        if not source.is_file():
            self.skipTest('SKIP: platform/uefi/q1n1-proxy.c is absent')
        text = source.read_text()
        self.assertIn('case P_DC_CVAC: CACHE_RANGE("dc cvac", 0); break;', text)

    def test_the_heap_the_carrier_assumes_comes_from_page_allocation(self):
        source = ROOT / 'platform' / 'uefi' / 'main.c'
        if not source.is_file():
            self.skipTest('SKIP: platform/uefi/main.c is absent')
        text = source.read_text()
        self.assertIn('allocate_pages(0, 1 /* EfiLoaderCode */, HEAP_BYTES / 4096, &heap)', text)
        self.assertIn('info.heap_base = heap; info.heap_size = HEAP_BYTES;', text)


class DefaultOff(unittest.TestCase):
    def test_importing_the_client_does_not_load_the_feature(self):
        code = 'import q1n1proxy, sys; print("q1n1_boardinfo" in sys.modules)'
        done = subprocess.run([sys.executable, '-B', '-c', code], cwd=TOOLS, capture_output=True, text=True, check=True)
        self.assertEqual(done.stdout.strip(), 'False')

    def test_no_other_q1n1_source_refers_to_the_module(self):
        own = {TOOLS / 'q1n1_boardinfo.py', Path(__file__).resolve(), DOC}
        for base in ('tools', 'platform', 'proxyclient', 'src', 'docs'):
            for path in (ROOT / base).rglob('*'):
                if path.is_file() and path.resolve() not in own \
                        and path.suffix in ('.py', '.c', '.h', '.S', '.md', '.sh'):
                    with self.subTest(str(path.relative_to(ROOT))):
                        self.assertNotIn('q1n1_boardinfo', path.read_text(errors='ignore'))

    def test_the_module_imports_nothing_outside_the_standard_library_or_from_snapintosh(self):
        tree = ast.parse((TOOLS / 'q1n1_boardinfo.py').read_text())
        roots = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                roots.update(alias.name.split('.')[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                roots.add((node.module or '').split('.')[0])
        self.assertEqual(roots, {'__future__', 'abc', 'struct', 'typing', 'zlib'})


class Hygiene(unittest.TestCase):
    FILES = (TOOLS / 'q1n1_boardinfo.py', Path(__file__).resolve(), DOC)

    def test_license_header_and_no_machine_specific_text(self):
        forbidden = ('/' + 'Users' + '/', '/' + 'home' + '/', '/' + 'tmp' + '/', '/' + 'var' + '/folders')
        for path in self.FILES:
            text = path.read_text()
            with self.subTest(path.name):
                if path.suffix == '.py':
                    self.assertEqual(text.splitlines()[1], '# SPDX-License-Identifier: MIT')
                for fragment in forbidden:
                    self.assertNotIn(fragment, text)

    def test_the_doc_states_the_contract_the_default_and_the_removal_path(self):
        text = DOC.read_text()
        for needed in ('HostProxyTransport', 'BoardInfoTransport', 'D8', 'default off', 'DC CVAC',
                       'board_info_validate', 'heap_offset', 'NOT RUN'):
            self.assertIn(needed, text)


SNAPINTOSH = os.environ.get('SNAPINTOSH_DIR', '')


@unittest.skipUnless((Path(SNAPINTOSH) / 'probes' / 'boardinfo.py').is_file() if SNAPINTOSH else False,
                     'SKIP: set SNAPINTOSH_DIR to a Snapintosh checkout')
class SnapintoshBlob(Target):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location('snapintosh_boardinfo',
                                                      Path(SNAPINTOSH) / 'probes' / 'boardinfo.py')
        cls.boardinfo = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.boardinfo)

    def blob(self, board):
        return self.boardinfo.json_to_blob((Path(SNAPINTOSH) / 'config' / 'boards' / f'{board}.json').read_text())

    def test_each_shipped_board_round_trips_and_the_monitor_mirror_accepts_the_slot(self):
        for board in ('a16', 'sp11'):
            with self.subTest(board):
                blob = self.blob(board)
                self.assertEqual(refresh_crc(blob), blob, 'the test helper uses the ABI CRC convention')
                transport = bi.HostProxyTransport(self.proxy, OFFSET, validator=self.boardinfo.validate)
                placement = transport.place(blob)
                self.assertEqual(transport.read_back(placement), blob)
                self.assertEqual(self.boardinfo.check(self.slot()), self.boardinfo.OK)
                transport.clear(placement)
                self.assertNotEqual(self.boardinfo.check(self.slot()), self.boardinfo.OK)

    def test_a_blob_the_monitor_would_refuse_is_stopped_only_by_the_validator(self):
        blob = bytearray(self.blob('sp11'))
        struct.pack_into('<I', blob, 8, 2)
        blob = refresh_crc(blob)
        self.assertEqual(self.boardinfo.check(blob), self.boardinfo.ERR_MAJOR)
        self.assertEqual(bi.check_framing(blob)[0], len(blob))
        with self.assertRaises(self.boardinfo.BoardInfoError):
            bi.HostProxyTransport(self.proxy, OFFSET, validator=self.boardinfo.validate).place(blob)
        self.assertEqual(self.link.events, [])


if __name__ == '__main__':
    unittest.main()
