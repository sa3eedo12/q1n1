#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""The constants of payloads/nvmesnap.c against the reference copies they rest on (docs/SP11-PAYLOAD-NVMESNAP.md).

    SNAPINTOSH_DIR=<a Snapintosh checkout> python3 tools/test-q1n1-sp11-payload-nvmesnap-refs.py

  * The pinned Linux device tree (`hamoa.dtsi` of the revision docs/SP11-STICK-LOG.md section 10 of Snapintosh pins, kept in
    build/sp11-stick-log/refs/ of that tree, or in NVMESNAP_REFS_DIR): the platform window the second gate checks is the non-prefetchable window of
    `pcie6a`, the controller is `dma-coherent`, the port's bus range starts at the endpoint's bus, and the PCIe SMMU is `status = "reserved"`.
    The lines the document cites are the lines that say so.
  * The X2 test image's sources (probes/uefi/tests/ of the Snapintosh tree): the seven controller registers, their offsets and widths, a 64-bit
    register as two 32-bit loads low word first, the configuration offsets and the class code are the ones this payload reads. The image's order
    (CAP, VS, CC, CSTS, AQA, ASQ, ACQ) is deliberately not kept: this payload reads CAP, CSTS, CC, VS, then CSTS again, AQA, ASQ, ACQ. The configuration dwords the
    image read of the root port and of the endpoint, and so the ones that are new here, are the ones the table of the document lists.

A tree without the reference copies gets a SKIP, never a pass. VERIFIED in this file means a pinned copy says so; it never means that the unit does.
Writes nothing. Hardware: NOT RUN. Evidence: EXPERIMENTAL."""
import hashlib
import os
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / 'payloads' / 'nvmesnap.c'
DOC = ROOT / 'docs' / 'SP11-PAYLOAD-NVMESNAP.md'
# docs/SP11-STICK-LOG.md section 10 of Snapintosh: Linux 7475ea8b58616b33c04afb976cf0fbaad9dd63fb, SHA-256 of the fetched bytes.
DTSI_SHA256 = 'd5bb1f7ce37c721d75fb5b4cffc8f58bed4d3ef9786a231a0deca05e917529e0'


def refs_dir():
    direct = os.environ.get('NVMESNAP_REFS_DIR')
    tree = os.environ.get('SNAPINTOSH_DIR')
    found = Path(direct) if direct else (Path(tree) / 'build' / 'sp11-stick-log' / 'refs' if tree else None)
    return found if found and (found / 'hamoa.dtsi').is_file() else None


def x2_dir():
    tree = os.environ.get('SNAPINTOSH_DIR')
    found = Path(tree) / 'probes' / 'uefi' / 'tests' if tree else None
    return found if found and (found / 'pciio.h').is_file() and (found / 't_pcie.c').is_file() and (found / 'env.c').is_file() else None


def constant(code, name):
    return int(re.search(rf'#define {name} \(?(?:UINT64_C\()?(0x[0-9a-fA-F]+|\d+)', code).group(1), 0)


def node(lines, header):
    """The lines of the device tree node that starts at the line holding `header`, and the index of that line."""
    start = next(i for i, line in enumerate(lines) if header in line)
    depth, out = 0, []
    for line in lines[start:]:
        out.append(line)
        depth += line.count('{') - line.count('}')
        if depth == 0:
            break
    return out, start


def x2_table_cells(doc, code, reader):
    """What the document's table says the X2 image read of each function and what is new here, and the same worked out from the image's source (`reader`,
    probes/uefi/tests/t_pcie.c) and this payload's: {function: (cell of dwords read by the image, cell of dwords it did not read)}."""
    start, end = doc.index('<!-- nvmesnap-x2 -->'), doc.index('<!-- /nvmesnap-x2 -->')
    table = [[c.strip() for c in re.split(r'(?<!\\)\|', line.strip())[1:-1]] for line in doc[start:end].splitlines() if line.startswith('|')][2:]
    said = {row[0]: (row[1], row[2]) for row in table}
    ident, command, klass, header, bar0, bar1, buses, window, pointer = [int(o, 16) for o in re.findall(r'cfg\(a, c, f, (0x[0-9a-f]+)\)', code)][:9]
    assert re.findall(r'cfg\(a, c, f, (ptr(?: \+ 0x[0-9a-f]+u)?)\)', code) == ['ptr', 'ptr + 0x04u', 'ptr + 0x0cu', 'ptr + 0x10u'], 'the capability dwords it reads'
    port_header = {ident, command, klass, header, buses, window, pointer}
    endpoint_header = {ident, command, klass, header, bar0, bar1, pointer}
    port_seen = {int(o, 16) for o in re.findall(r'cfg_rd\(s, e, (?:0|b), dev, (0x[0-9A-Fa-f]+)', reader)}
    endpoint_seen = {int(o, 16) for o in re.findall(r'cfg_rd\(s, e, sec, 0, (0x[0-9A-Fa-f]+)', reader)}
    walks = bool(re.search(r'cfg_rd\(s, e, b, dev, ptr, &dw\)', reader))
    link_seen = {int(o, 16) for o in re.findall(r'cfg_rd\(s, e, b, dev, ptr \+ (0x[0-9A-Fa-f]+)u', reader)}

    def cell(*items):
        return ', '.join(item for group in items for item in group)

    def hexes(offsets):
        return [f'`0x{o:02x}`' for o in sorted(offsets)]

    first, pm = ['the first dword of each capability'], ['power management `+0x04`']
    pcie_seen = [f'PCI Express `+0x{o:02x}`' for o in (0x0c, 0x10) if o in link_seen]
    pcie_new = [f'PCI Express `+0x{o:02x}`' for o in (0x0c, 0x10) if o not in link_seen]
    worked = {'root port 00:00.0': (cell(hexes(port_header & port_seen), first if walks else [], pcie_seen),
                                    cell(hexes(port_header - port_seen), [] if walks else first, pcie_new)),
              'endpoint 01:00.0': (cell(hexes(endpoint_header & endpoint_seen)),
                                   cell(hexes(endpoint_header - endpoint_seen), first, pm, [f'PCI Express `+0x{o:02x}`' for o in (0x0c, 0x10)]))}
    return said, worked


class NvmesnapRefs(unittest.TestCase):
    code = SOURCE.read_text(encoding='utf-8')
    doc = DOC.read_text(encoding='utf-8')

    def dtsi(self):
        directory = refs_dir()
        if not directory:
            self.skipTest('no pinned copy of hamoa.dtsi (set SNAPINTOSH_DIR, or NVMESNAP_REFS_DIR for the directory): the window is not compared with it')
        data = (directory / 'hamoa.dtsi').read_bytes()
        self.assertEqual(hashlib.sha256(data).hexdigest(), DTSI_SHA256, 'hamoa.dtsi is not the pinned copy')
        return data.decode('utf-8').splitlines()

    def test_the_platform_window_is_the_non_prefetchable_window_of_pcie6a(self):
        lines = self.dtsi()
        text, _ = node(lines, 'pcie6a: pcie@1bf8000 {')
        found = re.search(r'ranges\s*=\s*((?:<[^>]*>,?\s*)+);', '\n'.join(text))
        self.assertIsNotNone(found)
        cells = [[int(c, 0) for c in group.split()] for group in re.findall(r'<([^>]*)>', found.group(1))]
        window = [c for c in cells if c[0] >> 24 & 3 == 2]                       # the PCI space code of a 32-bit memory window
        self.assertEqual(len(window), 1)
        cpu, size = window[0][3] << 32 | window[0][4], window[0][5] << 32 | window[0][6]
        self.assertEqual(cpu, constant(self.code, 'PCIE_MEM_BASE'))
        self.assertEqual(cpu + size, constant(self.code, 'PCIE_MEM_END'))

    def test_the_controller_is_dma_coherent_its_dbi_is_the_ecam_base_and_the_endpoints_bus_is_the_ports_secondary(self):
        lines = self.dtsi()
        text, _ = node(lines, 'pcie6a: pcie@1bf8000 {')
        joined = '\n'.join(text)
        self.assertRegex(joined, r'(?m)^\s*dma-coherent;', 'the document says the controller is dma-coherent')
        self.assertIn(f'0 0x{constant(self.code, "ECAM_BASE"):08x} 0 0xf20', joined, 'the DBI of the same controller is at the ECAM base the unit reported (INFERRED link)')
        port, _ = node(text, 'pcie6a_port0: pcie@0 {')
        bus = re.search(r'bus-range = <(0x[0-9a-f]+) (0x[0-9a-f]+)>', '\n'.join(port))
        self.assertEqual(int(bus.group(1), 16), constant(self.code, 'EP_BUS'))

    def test_the_pcie_smmu_is_reserved_and_controlled_by_gunyah(self):
        lines = self.dtsi()
        text, _ = node(lines, 'pcie_smmu: iommu@15400000 {')
        self.assertTrue(any('status = "reserved"; /* Controlled by Gunyah. */' in line for line in text))

    def test_the_lines_the_document_cites_say_what_it_says_they_do(self):
        lines = self.dtsi()
        cited = sorted(set(re.findall(r'hamoa\.dtsi:(\d+(?:-\d+)?)', self.doc)))
        self.assertEqual(cited, ['3451-3452', '3455', '8555'], 'the document cites these three places and no other')
        self.assertIn('ranges = <0x01000000', lines[3450])
        self.assertIn('<0x02000000 0x0 0x70300000 0x0 0x70300000 0x0 0x3d00000>;', lines[3451])
        self.assertIn('dma-coherent;', lines[3454])
        self.assertIn('status = "reserved"; /* Controlled by Gunyah. */', lines[8554])

    def test_the_x2_image_reads_the_registers_this_payload_reads_the_same_seven_at_the_same_offsets_and_widths_in_another_order(self):
        directory = x2_dir()
        if not directory:
            self.skipTest('no X2 image sources (set SNAPINTOSH_DIR): the registers are not compared with the image that read them')
        header = (directory / 'pciio.h').read_text(encoding='utf-8')
        image = {name: int(value, 16) for name, value in re.findall(r'#define TESTS_NVME_(\w+) (0x[0-9A-Fa-f]+)u', header)}
        mine = re.findall(r'\{"(\w+)", (0x[0-9a-f]+), (\d)\}', self.code)
        reader = (directory / 't_pcie.c').read_text(encoding='utf-8')
        calls = re.findall(r'tests_rd(32|64)\(s->c->bus, &s->allow, bar \+ TESTS_NVME_(\w+), &\w+\)', reader)
        theirs = [(name, 'wide' if width == '64' else 'narrow') for width, name in calls]
        self.assertEqual([name for name, _ in theirs], ['CAP', 'VS', 'CC', 'CSTS', 'AQA', 'ASQ', 'ACQ'], 'the order of the image, which this payload does not keep')
        ours = [(name, int(offset, 16), 'wide' if wide == '1' else 'narrow') for name, offset, wide in mine]
        self.assertEqual([name for name, _, _ in ours], ['CAP', 'CSTS', 'CC', 'VS', 'CSTS2', 'AQA', 'ASQ', 'ACQ'])
        once = [(name, offset, width) for name, offset, width in ours if name != 'CSTS2']
        self.assertEqual(sorted((name, offset, width) for name, offset, width in once), sorted((name, image[name], width) for name, width in theirs),
                         'the same seven registers at the same offsets and the same widths')
        self.assertEqual(ours[4][1], image['CSTS'], 'the one register read twice is CSTS')
        env = (directory / 'env.c').read_text(encoding='utf-8')
        body = env[env.index('int tests_rd64('):]
        body = body[:body.index('\n}\n')]
        self.assertLess(body.index('tests_rd32(bus, allow, addr, &lo)'), body.index('tests_rd32(bus, allow, addr + 4u, &hi)'), 'low word first')

    def test_the_document_says_which_dwords_the_x2_image_read_and_which_are_new_and_the_check_can_fail(self):
        directory = x2_dir()
        if not directory:
            self.skipTest('no X2 image sources (set SNAPINTOSH_DIR): the table of what the image read is not compared with it')
        reader = (directory / 't_pcie.c').read_text(encoding='utf-8')
        said, worked = x2_table_cells(self.doc, self.code, reader)
        self.assertEqual(said, worked)
        self.assertEqual(sorted(said), ['endpoint 01:00.0', 'root port 00:00.0'])
        wrong_documents = (('a new dword said to have been read', self.doc.replace('| `0x00`, `0x04`, `0x08`, `0x10`, `0x14` |', '| `0x00`, `0x04`, `0x08`, `0x10`, `0x14`, `0x34` |', 1)),
                           ('a new dword left out', self.doc.replace('| `0x0c`, `0x34`, the first dword of each capability, power management', '| `0x34`, the first dword of each capability, power management', 1)))
        for label, doc in wrong_documents:
            with self.subTest(case=label):
                self.assertNotEqual(doc, self.doc)
                self.assertNotEqual(*x2_table_cells(doc, self.code, reader))
        wrong_images = (('an image that read the link capabilities and not the link dword', reader.replace('ptr + 0x10u', 'ptr + 0x0cu')),
                        ('an image that read the endpoint\'s capability pointer', reader.replace('cfg_rd(s, e, sec, 0, 0x14,', 'cfg_rd(s, e, sec, 0, 0x34,')))
        for label, image in wrong_images:
            with self.subTest(case=label):
                self.assertNotEqual(image, reader)
                self.assertNotEqual(*x2_table_cells(self.doc, self.code, image))

    def test_the_x2_images_configuration_offsets_and_class_are_the_ones_read_here(self):
        directory = x2_dir()
        if not directory:
            self.skipTest('no X2 image sources (set SNAPINTOSH_DIR): the offsets are not compared with the image that read them')
        header = (directory / 'pciio.h').read_text(encoding='utf-8')
        image = {name: int(value, 16) for name, value in re.findall(r'#define TESTS_PCIIO_(\w+) (0x[0-9A-Fa-f]+)u', header)}
        offsets = re.findall(r'cfg\(a, c, f, (0x[0-9a-f]+)\)', self.code)
        self.assertEqual([int(o, 16) for o in offsets[:9]], [image['CFG_ID'], image['CFG_COMMAND'], image['CFG_CLASS_REV'], image['CFG_HEADER'], image['CFG_BAR0'],
                                                           image['CFG_BAR0'] + 4, image['CFG_BUSES'], 0x20, 0x34],
                         'the dwords of the header; the bridge window (0x20) and the capability pointer (0x34) are the specification\'s')
        self.assertEqual(image['CLASS_NVME'], constant(self.code, 'CLASS_NVME'))
        self.assertEqual(image['CMD_MEMORY'], 2)


if __name__ == '__main__':
    unittest.main(verbosity=1)
