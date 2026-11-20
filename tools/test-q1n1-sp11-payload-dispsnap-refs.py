#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Tests of the pinned reference copies behind the payload dispsnap (payloads/dispsnap-regs.h, docs/SP11-PAYLOAD-DISPSNAP.md).

    python3 tools/test-q1n1-sp11-payload-dispsnap-refs.py

Every test here is a SKIP, never a pass, when the pinned copies are not found (tools/sp11_payload_dispsnap_refs.py says where they are looked for:
DISPSNAP_REFS_DIR, SNAPINTOSH_DIR/build/sp11-stick-log/refs, build/sp11-dispsnap/refs). With them, it holds to the pinned Linux files: every digest; every file:line
the ledger lists (and so every citation of the document); every register offset of the table by NAME in the file that defines it; every bit position and field of
the code; every window against the device tree; the catalog numbers of the interface and the CTL pages. The payload sources are read from DISPSNAP_PAYLOAD_DIR when
that names a directory (the mutants are run through it) and from payloads/ otherwise. Hardware: NOT RUN. Evidence: EXPERIMENTAL (host model and pinned files only)."""
from pathlib import Path
import os
import re
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import sp11_payload_dispsnap_refs as refs  # noqa: E402

PAYLOAD_DIR = Path(os.environ.get('DISPSNAP_PAYLOAD_DIR') or ROOT / 'payloads')
REGS = (PAYLOAD_DIR / 'dispsnap-regs.h').read_text(encoding='utf-8')
DOC = ROOT / 'docs' / 'SP11-PAYLOAD-DISPSNAP.md'


class Pinned(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not refs.available():
            raise unittest.SkipTest('the pinned Linux copies are not here (DISPSNAP_REFS_DIR)')

    def test_every_digest_is_the_pinned_one(self):
        for name, (want, _) in refs.PINNED.items():
            with self.subTest(file=name):
                self.assertEqual(refs.digest(refs.locate(name)), want)

    def test_the_ledger_is_what_the_pinned_files_show(self):
        for key in refs.LEDGER:
            with self.subTest(citation=key):
                self.assertEqual(refs.ledger_problems(key), [])

    def test_every_offset_of_the_table_is_the_pinned_files(self):
        rows = refs.parse_rows(REGS)
        self.assertEqual(len(rows), 25)
        intf = {'ST': 'INTF_STATUS', 'EN': 'INTF_TIMING_ENGINE_EN', 'CFG': 'INTF_CONFIG', 'CFG2': 'INTF_CONFIG2', 'HS': 'INTF_HSYNC_CTL', 'VP': 'INTF_VSYNC_PERIOD_F0',
                'DVS': 'INTF_DISPLAY_V_START_F0', 'DVE': 'INTF_DISPLAY_V_END_F0', 'AVS': 'INTF_ACTIVE_V_START_F0', 'AVE': 'INTF_ACTIVE_V_END_F0', 'DHC': 'INTF_DISPLAY_HCTL',
                'AHC': 'INTF_ACTIVE_HCTL', 'FLC': 'INTF_FRAME_LINE_COUNT_EN', 'FRA': 'INTF_FRAME_COUNT'}
        intf_page = refs.catalog_base('intf_5')[0]
        for key, window, expression, dec, flags in rows:
            with self.subTest(key=key):
                offset = refs.row_offset(REGS, expression)
                if key == 'DAHB':
                    # a critical CBCR: no clock struct, only the entry of the list of clocks Linux keeps on
                    self.assertIn(f'0x{offset:x}, /* GCC_DISP_AHB_CLK */', '\n'.join(refs.lines_of('gcc-x1e80100.c')))
                elif key == 'GDSC':
                    self.assertEqual(refs.struct_field('dispcc-x1e80100.c', 'mdss_gdsc', 'gdscr', 'gdsc'), offset)
                elif key == 'AHBC':
                    self.assertEqual(refs.struct_field('dispcc-x1e80100.c', 'disp_cc_mdss_ahb_clk', 'halt_reg'), offset)
                    self.assertEqual(refs.struct_field('dispcc-x1e80100.c', 'disp_cc_mdss_ahb_clk', 'enable_reg'), offset)
                elif key == 'MDPC':
                    self.assertEqual(refs.struct_field('dispcc-x1e80100.c', 'disp_cc_mdss_mdp_clk', 'halt_reg'), offset)
                    self.assertEqual(refs.struct_field('dispcc-x1e80100.c', 'disp_cc_mdss_mdp_clk', 'enable_reg'), offset)
                elif key == 'VER':
                    # REG_MDSS_HW_VERSION is in a generated header that is not pinned (UV2): the value is the study's, and the read is at the MDSS base
                    self.assertEqual(offset, 0)
                elif key in intf:
                    self.assertEqual(offset, intf_page + refs.define_value('dpu_hw_intf.c', intf[key]))
                elif re.fullmatch(r'C\d', key):
                    n = int(key[1])
                    self.assertEqual(offset, refs.catalog_base(f'ctl_{n}')[0] + refs.define_value('dpu_hw_ctl.c', 'CTL_INTF_ACTIVE'))
                else:
                    self.fail(f'no pinned source for {key}')

    def test_the_decode_and_the_window_of_every_row_is_the_documents_kind(self):
        kinds = {'DAHB': ('WIN_GCC', 'D_CBCR'), 'GDSC': ('WIN_DISPCC', 'D_GDSCR'), 'AHBC': ('WIN_DISPCC', 'D_CBCR'), 'MDPC': ('WIN_DISPCC', 'D_CBCR'),
                 'VER': ('WIN_MDSS', 'D_VER')}
        for key, window, expression, dec, flags in refs.parse_rows(REGS):
            with self.subTest(key=key):
                want = kinds.get(key, ('WIN_DPU', 'D_NONE'))
                self.assertEqual((window, dec), want)
                self.assertEqual(flags, 'F_NEEDS_FLC' if key == 'FRA' else '0')

    def test_the_windows_are_those_of_the_device_tree(self):
        windows = dict(zip(refs.window_names(REGS), refs.windows_of(REGS)))
        self.assertEqual(list(windows), ['GCC', 'DISPCC', 'MDSS', 'DPU'])
        wanted = {'GCC': refs.dt_reg(r'gcc: clock-controller@100000'), 'DISPCC': refs.dt_reg(r'dispcc: clock-controller@af00000'),
                  'MDSS': refs.dt_reg(r'mdss: display-subsystem@ae00000'), 'DPU': refs.dt_reg(r'mdss_mdp: display-controller@ae01000')}
        for name, want in wanted.items():
            with self.subTest(window=name):
                self.assertIsNotNone(want)
                self.assertEqual(windows[name], want)

    def test_every_row_lies_inside_its_window_and_in_the_block_it_names(self):
        windows = dict(zip(['WIN_GCC', 'WIN_DISPCC', 'WIN_MDSS', 'WIN_DPU'], refs.windows_of(REGS)))
        intf_first, intf_len = refs.catalog_base('intf_5')
        for key, window, expression, dec, flags in refs.parse_rows(REGS):
            with self.subTest(key=key, window=window):
                offset = refs.row_offset(REGS, expression)
                base, size = windows[window]
                self.assertTrue(offset % 4 == 0 and 0 <= offset and offset + 4 <= size)
                if window == 'WIN_DPU' and not key.startswith('C'):
                    self.assertTrue(intf_first <= offset < intf_first + intf_len, 'an INTF word lies inside the 0x280 bytes of INTF_5')
                if window == 'WIN_DPU' and re.fullmatch(r'C\d', key):
                    first, length = refs.catalog_base(f'ctl_{key[1]}')
                    self.assertTrue(first <= offset < first + length)

    def test_the_geometry_of_the_dpu_window_is_the_catalog(self):
        d = refs.defines(REGS)
        self.assertEqual(d['INTF_PAGE_OFF'], refs.catalog_base('intf_5')[0])
        self.assertEqual(d['CTL_FIRST_OFF'], refs.catalog_base('ctl_0')[0])
        for n in range(d['CTL_COUNT']):
            self.assertEqual(refs.catalog_base(f'ctl_{n}')[0], d['CTL_FIRST_OFF'] + n * d['CTL_STEP'])
        self.assertIsNone(refs.catalog_base(f'ctl_{d["CTL_COUNT"]}'), 'the catalog has exactly the six CTL paths the table reads')
        self.assertEqual(d['CTL_INTF_ACTIVE_OFF'], refs.define_value('dpu_hw_ctl.c', 'CTL_INTF_ACTIVE'))
        self.assertEqual(d['INTF_INDEX'], 5)
        self.assertEqual(refs.catalog_base('intf_5')[1], 0x280)

    def test_the_bit_positions_of_the_code_are_the_pinned_macros(self):
        d = refs.defines(REGS)
        fields = {
            'CBCR_CLK_OFF_BIT': refs.bit_define('clk-branch.h', 'CBCR_CLK_OFF'),
            'CBCR_ENABLE_BIT': refs.bit_define('clk-branch.h', 'CBCR_CLOCK_ENABLE'),
            'GDSC_PWR_ON_BIT': refs.bit_define('gdsc.c', 'PWR_ON_MASK'),
            'GDSC_SW_COLLAPSE_BIT': refs.bit_define('gdsc.c', 'SW_COLLAPSE_MASK'),
            'GDSC_HW_CONTROL_BIT': refs.bit_define('gdsc.c', 'HW_CONTROL_MASK'),
        }
        for name, want in fields.items():
            with self.subTest(field=name):
                self.assertIsNotNone(want)
                self.assertEqual(d[name], want)
        with self.subTest(field='CBCR_FSM'):
            high, low = refs.genmask('clk-branch.h', 'CBCR_NOC_FSM_STATUS')
            self.assertEqual(d['CBCR_FSM_SHIFT'], low)
            self.assertEqual(d['CBCR_FSM_MASK'], (1 << (high - low + 1)) - 1)
            self.assertEqual(d['CBCR_FSM_ON'], 2, 'FSM_STATUS_ON is BIT(1) of the shifted field')
            self.assertEqual(refs.bit_define('clk-branch.h', 'FSM_STATUS_ON') if refs.bit_define('clk-branch.h', 'FSM_STATUS_ON') is not None else 1, 1)
        with self.subTest(field='VER'):
            macro = '\n'.join(refs.span('msm_mdss.c', 241, 244).splitlines())
            self.assertIn('<< 28', macro)
            self.assertIn('<< 16', macro)
            self.assertEqual((d['VER_MAJOR_SHIFT'], d['VER_MAJOR_MASK'], d['VER_MINOR_SHIFT'], d['VER_MINOR_MASK']), (28, 0xf, 16, 0xfff))

    def test_the_gate_inputs_are_the_clocks_of_the_mdss_node_and_the_gdsc_of_its_power_domain(self):
        # hamoa.dtsi:5560-5562 lists the MDSS AHB clock, GCC_DISP_HF_AXI and the MDP clock; the two the register access needs are the first and the last (mm:276-283)
        node = refs.span('hamoa.dtsi', 5560, 5562)
        self.assertLess(node.index('DISP_CC_MDSS_AHB_CLK'), node.index('GCC_DISP_HF_AXI_CLK'))
        self.assertLess(node.index('GCC_DISP_HF_AXI_CLK'), node.index('DISP_CC_MDSS_MDP_CLK'))
        self.assertIn('power-domains = <&dispcc MDSS_GDSC>', refs.span('hamoa.dtsi', 5553, 5600))
        d = refs.defines(REGS)
        self.assertEqual(d['GATE_CLOCKS'], 2)

    def test_no_window_of_the_table_is_one_the_study_says_not_to_read(self):
        # the eDP controller (mdss_dp3), its PHY and the DPU's VBIF are not in any window of the table
        windows = refs.windows_of(REGS)
        for forbidden in (0x0aea0000, 0x0aec5a00, 0x0aeb0000):
            self.assertFalse(any(base <= forbidden < base + size for base, size in windows), hex(forbidden))


class Document(unittest.TestCase):
    def test_every_uv_item_of_the_module_is_listed_in_the_document_and_no_other(self):
        if not DOC.exists():
            self.skipTest('no document')
        text = DOC.read_text(encoding='utf-8')
        self.assertEqual(set(re.findall(r'\bUV\d\b', text)), set(refs.UNVERIFIED))


if __name__ == '__main__':
    unittest.main(verbosity=2)
