#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""The register table and the field positions of the payload gpusnap against the pinned Linux files (docs/SP11-PAYLOAD-GPUSNAP.md).

    python3 tools/test-q1n1-sp11-payload-gpusnap-refs.py

Reads every offset of payloads/gpusnap-regs.h BY NAME from the pinned copies (the clock or GDSC struct of gcc-x1e80100.c and gpucc-x1e80100.c, a register of
a6xx_gmu.xml or a6xx.xml, a #define of arm-smmu.h), the windows and the clock lists of the device tree, and the bit positions of the code against the
#define macros of the clock, GDSC, RCG and SMMU headers; the ledger of tools/sp11_payload_gpusnap_refs.py holds each file:line the document cites to the line.
The payload sources come from GPUSNAP_PAYLOAD_DIR when set (a copy with a seeded bug), else from payloads/.

SKIPs, never passes, when a pinned copy is missing: set SNAPINTOSH_DIR to a Snapintosh tree that has build/sp11-stick-log/refs/ and GPUSNAP_REFS_DIR to the
directory that holds the files fetched at the same Linux revision (the list and the URLs are in the module and in the document).
Evidence: VERIFIED means a pinned file says so, never that the unit does. Hardware: NOT RUN."""
import os
from pathlib import Path
import re
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import sp11_payload_gpusnap_refs as refs  # noqa: E402

PAYLOADS = Path(os.environ.get('GPUSNAP_PAYLOAD_DIR') or ROOT / 'payloads')
WINDOW_NAMES = ('GCC', 'GPUCC', 'CXMISC', 'GMU', 'RSCC', 'SMMU')


def number(text, name):
    """The value of `#define name <number>u` of the payload header (or the value in parentheses)."""
    found = re.search(rf'#define {name} \(?(0x[0-9a-f]+|\d+)u?\)?', text)
    if not found:
        raise AssertionError(f'{name} is not a #define of gpusnap-regs.h')
    return int(found.group(1), 0)


class Refs(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        absent = refs.missing()
        if absent:
            raise unittest.SkipTest(f'no pinned copies of {absent} (see the module docstring: SNAPINTOSH_DIR and GPUSNAP_REFS_DIR)')
        cls.files = refs.load()
        cls.header = (PAYLOADS / 'gpusnap-regs.h').read_text(encoding='utf-8')
        cls.source = (PAYLOADS / 'gpusnap.c').read_text(encoding='utf-8')
        cls.rows = refs.parse_rows(cls.header)
        cls.windows = refs.parse_windows(cls.header)

    # ---- digests and the ledger ----------------------------------------------------------------------------------------------------------------
    def test_every_pinned_copy_is_the_one_whose_digest_is_recorded(self):
        for name in refs.PINNED:
            with self.subTest(file=name):
                self.assertIn(name, self.files)
        self.assertEqual(set(self.files), set(refs.PINNED))

    def test_the_ledger_entries_say_what_the_lines_show(self):
        self.assertEqual(refs.ledger_problems(self.files), [])

    # ---- the windows ----------------------------------------------------------------------------------------------------------------------------
    def test_the_windows_are_those_of_the_device_tree(self):
        dt = self.files['hamoa.dtsi']
        gcc, gpu, gmu, gpucc, smmu = (refs.dt_node_regs(dt, label) for label in ('gcc', 'gpu', 'gmu', 'gpucc', 'adreno_smmu'))
        expected = {'GCC': gcc[0], 'GPUCC': gpucc[0], 'CXMISC': gpu[1], 'GMU': gmu[0], 'RSCC': gmu[1], 'SMMU': smmu[0]}
        self.assertEqual(len(self.windows), len(WINDOW_NAMES))
        for name, window in zip(WINDOW_NAMES, self.windows):
            with self.subTest(window=name):
                self.assertEqual(window, expected[name])

    def test_the_gpu_window_and_the_blocks_the_payload_does_not_name_are_never_read(self):
        dt = self.files['hamoa.dtsi']
        gpu, gmu = refs.dt_node_regs(dt, 'gpu'), refs.dt_node_regs(dt, 'gmu')
        forbidden = [('the GPU window', gpu[0]), ('cx_dbgc', gpu[2]), ('gmu_pdc', gmu[2])]
        for key, window, expression, dec, flags in self.rows:
            base = self.windows[WINDOW_NAMES.index(window)][0]
            address = base + refs.macro_offset(self.header, window, expression)
            for what, (start, size) in forbidden:
                with self.subTest(key=key, block=what):
                    self.assertFalse(start <= address < start + size, f'{key} is at {address:#x}, inside {what}')

    # ---- the register table, by name ------------------------------------------------------------------------------------------------------------
    def expected_offsets(self):
        """{key: (window, byte offset in the window)} from the pinned files, each by the name of the struct, register or #define it is."""
        gcc, gpucc, gdsc, rcg = self.files['gcc-x1e80100.c'], self.files['gpucc-x1e80100.c'], self.files['gdsc.c'], self.files['clk-rcg2.c']
        gmu_xml, a6xx, smmu = refs.xml_registers(self.files['a6xx_gmu.xml']), refs.xml_registers(self.files['a6xx.xml']), self.files['arm-smmu.h']
        dt = self.files['hamoa.dtsi']
        gmu_from_gpu = refs.dt_node_regs(dt, 'gmu')[0][0] - refs.dt_node_regs(dt, 'gpu')[0][0]

        def halt(lines, struct):
            return int(refs.struct_field(lines, struct, 'halt_reg'), 0)

        def xml(table, name, variant=None):
            options = [d for d, v in table[name] if variant is None or variant in v or not v]
            self.assertEqual(len(options), 1, f'{name} must have one offset for {variant}: {table[name]}')
            return options[0]

        want = {
            'QMIP': ('GCC', halt(gcc, 'gcc_qmip_gpu_ahb_clk')), 'MNOC': ('GCC', halt(gcc, 'gcc_gpu_memnoc_gfx_clk')), 'SNOC': ('GCC', halt(gcc, 'gcc_gpu_snoc_dvm_gfx_clk')),
            'AXI_NW': ('GCC', halt(gcc, 'gcc_ddrss_gpu_axi_clk')),
            'VOTE': ('GCC', int(refs.struct_field(gcc, 'gcc_gpu_gpll0_cph_clk_src', 'enable_reg'), 0)),
            'GP0V': ('GCC', int(refs.struct_field(gcc, 'gcc_gpll0', 'enable_reg'), 0)),
            'CXGD': ('GPUCC', int(refs.struct_field(gpucc, 'gpu_cx_gdsc', 'gdscr'), 0)), 'CXHW': ('GPUCC', int(refs.struct_field(gpucc, 'gpu_cx_gdsc', 'gds_hw_ctrl'), 0)),
            'AHB': ('GPUCC', halt(gpucc, 'gpu_cc_ahb_clk')), 'CGMU': ('GPUCC', halt(gpucc, 'gpu_cc_cx_gmu_clk')), 'CXO': ('GPUCC', halt(gpucc, 'gpu_cc_cxo_clk')),
            'HUB': ('GPUCC', halt(gpucc, 'gpu_cc_hub_cx_int_clk')), 'DMT': ('GPUCC', halt(gpucc, 'gpu_cc_demet_clk')),
            'HLOS': ('GPUCC', halt(gpucc, 'gpu_cc_hlos1_vote_gpu_smmu_clk')),
            'GXGD': ('GPUCC', int(refs.struct_field(gpucc, 'gpu_gx_gdsc', 'gdscr'), 0)),
            'GXCF': ('GPUCC', int(refs.struct_field(gpucc, 'gpu_gx_gdsc', 'gdscr'), 0) + refs.evaluate(gdsc, 'CFG_GDSCR_OFFSET')),
            'CXOA': ('GPUCC', halt(gpucc, 'gpu_cc_cxo_aon_clk')), 'HUBA': ('GPUCC', halt(gpucc, 'gpu_cc_hub_aon_clk')), 'GXGM': ('GPUCC', halt(gpucc, 'gpu_cc_gx_gmu_clk')),
            'TCMR': ('CXMISC', 4 * xml(a6xx, 'CX_MISC_TCM_RET_CNTL', 'A7XX')),
            'RST': ('GMU', 4 * xml(gmu_xml, 'GMU_CM3_SYSRESET') - gmu_from_gpu), 'BUSY': ('GMU', 4 * xml(gmu_xml, 'GMU_CM3_FW_BUSY') - gmu_from_gpu),
            'INIT': ('GMU', 4 * xml(gmu_xml, 'GMU_CM3_FW_INIT_RESULT') - gmu_from_gpu), 'CFG': ('GMU', 4 * xml(gmu_xml, 'GMU_CM3_CFG') - gmu_from_gpu),
            'GXST': ('GMU', 4 * xml(gmu_xml, 'GMU_SPTPRAC_PWR_CLK_STATUS', 'A7XX') - gmu_from_gpu), 'FENS': ('GMU', 4 * xml(gmu_xml, 'GMU_AHB_FENCE_STATUS') - gmu_from_gpu),
            'ST0': ('RSCC', 4 * xml(gmu_xml, 'GPU_RSCC_RSC_STATUS0_DRV0')), 'PDCS': ('RSCC', 4 * xml(gmu_xml, 'RSCC_PDC_SEQ_START_ADDR')),
            'BSY': ('RSCC', 4 * xml(gmu_xml, 'RSCC_SEQ_BUSY_DRV0')),
            'SCR0': ('SMMU', refs.evaluate(smmu, 'ARM_SMMU_GR0_sCR0')), 'GFSR': ('SMMU', refs.evaluate(smmu, 'ARM_SMMU_GR0_sGFSR')),
            'ID7': ('SMMU', refs.evaluate(smmu, 'ARM_SMMU_GR0_ID7')), 'ID0': ('SMMU', refs.evaluate(smmu, 'ARM_SMMU_GR0_ID0')),
            'ID1': ('SMMU', refs.evaluate(smmu, 'ARM_SMMU_GR0_ID1')), 'ID2': ('SMMU', refs.evaluate(smmu, 'ARM_SMMU_GR0_ID2')),
        }
        # the critical CBCR of the GPU CFG AHB clock has no struct: it is the entry of the list
        found = re.search(r'\t(0x[0-9a-f]+), /\* GCC_GPU_CFG_AHB_CLK \*/', '\n'.join(gcc))
        self.assertIsNotNone(found)
        want['CFGA'] = ('GCC', int(found.group(1), 0))
        # the RCGs: the command word of the struct, the configuration word 4 up (clk-rcg2.c CFG_REG)
        cfg = refs.evaluate(rcg, 'CFG_REG')
        for key, struct in (('GR', 'gpu_cc_gmu_clk_src'), ('HR', 'gpu_cc_hub_clk_src'), ('XR', 'gpu_cc_xo_clk_src')):
            cmd = int(refs.struct_field(gpucc, struct, 'cmd_rcgr'), 0)
            want[key + 'C'], want[key + 'F'] = ('GPUCC', cmd), ('GPUCC', cmd + cfg)
        # the ten TCS status words, each with the a740 family's four dwords more (a6xx_gmu.c:1105-1108)
        for n in range(10):
            want[f'T{n}'] = ('RSCC', 4 * (xml(gmu_xml, f'RSCC_TCS{n}_DRV0_STATUS', 'A7XX') + 4))
        return want

    def test_every_offset_of_the_table_is_the_pinned_files(self):
        want = self.expected_offsets()
        keys = [row[0] for row in self.rows]
        self.assertEqual(len(keys), len(set(keys)), 'a key is used twice')
        self.assertEqual(sorted(keys), sorted(want), 'the table and the pinned names list different registers')
        for key, window, expression, dec, flags in self.rows:
            with self.subTest(key=key):
                offset = refs.macro_offset(self.header, window, expression)
                self.assertEqual((window, offset), want[key])

    def test_every_row_lies_inside_its_window_and_in_the_block_it_names(self):
        for key, window, expression, dec, flags in self.rows:
            base, size = self.windows[WINDOW_NAMES.index(window)]
            offset = refs.macro_offset(self.header, window, expression)
            with self.subTest(key=key, window=window):
                self.assertEqual(offset % 4, 0)
                self.assertTrue(0 <= offset and offset + 4 <= size, f'{key} at {offset:#x} is outside the {size:#x} window')

    def test_every_gpucc_row_is_a_register_the_driver_declares(self):
        found = re.search(r'\.max_register = (0x[0-9a-f]+),', '\n'.join(self.files['gpucc-x1e80100.c']))
        self.assertIsNotNone(found)
        last = int(found.group(1), 0)
        for key, window, expression, dec, flags in self.rows:
            if window == 'GPUCC':
                with self.subTest(key=key):
                    self.assertLessEqual(refs.macro_offset(self.header, window, expression), last)

    def test_the_table_is_in_the_order_the_page_reads_it(self):
        self.assertEqual([row[1] for row in self.rows], sorted((row[1] for row in self.rows), key=WINDOW_NAMES.index), 'rows of one window are not contiguous and in window order')

    # ---- the order of a window: what Linux reads first, what it never reads last ----------------------------------------------------------------
    # The name each row of the GMU, CX_MISC and RSC blocks has in the register files, as the pinned driver spells it after REG_A6XX_ / REG_A7XX_.
    LINUX_NAME = {
        'TCMR': 'CX_MISC_TCM_RET_CNTL', 'GXST': 'GMU_SPTPRAC_PWR_CLK_STATUS', 'INIT': 'GMU_CM3_FW_INIT_RESULT', 'FENS': 'GMU_AHB_FENCE_STATUS',
        'RST': 'GMU_CM3_SYSRESET', 'CFG': 'GMU_CM3_CFG', 'BUSY': 'GMU_CM3_FW_BUSY',
        'BSY': 'RSCC_SEQ_BUSY_DRV0', 'ST0': 'GPU_RSCC_RSC_STATUS0_DRV0', 'PDCS': 'RSCC_PDC_SEQ_START_ADDR',
        **{f'T{n}': f'RSCC_TCS{n}_DRV0_STATUS' for n in range(10)},
    }

    def driver_calls(self, call, name):
        text = '\n'.join(self.files['a6xx_gmu.c'] + self.files['a6xx_gpu.c'])
        return re.findall(rf'\b({call})\((?:gmu|a6xx_gpu), REG_A[67]XX_{name}\b', text)

    def driver_reads(self, name):
        return self.driver_calls(r'gmu_read\w*|gmu_poll_timeout\w*|gmu_rmw|a6xx_cx_misc_read', name)

    def test_a_word_is_late_exactly_when_no_pinned_driver_line_reads_it(self):
        for key, window, expression, dec, flags in self.rows:
            with self.subTest(key=key):
                if key in self.LINUX_NAME:
                    self.assertEqual('F_LATE' in flags, not self.driver_reads(self.LINUX_NAME[key]), 'F_LATE must be set exactly for the words the pinned driver never reads')
                else:
                    self.assertNotIn('F_LATE', flags, 'only words of the GMU and RSC blocks can have no Linux read to follow: the others are read by the clock and GDSC code')
        late = {row[0] for row in self.rows if 'F_LATE' in row[4]}
        self.assertEqual(late, {'RST', 'CFG', 'BUSY', 'PDCS'})
        for key in ('RST', 'CFG', 'PDCS'):
            with self.subTest(written=key):
                self.assertTrue(self.driver_calls(r'gmu_write\w*', self.LINUX_NAME[key]), f'{key} is a word the driver writes')
        self.assertEqual('\n'.join(self.files['a6xx_gmu.c'] + self.files['a6xx_gpu.c'] + self.files['a6xx_gmu.h']).count('FW_BUSY'), 0, 'no pinned driver line names GMU_CM3_FW_BUSY')

    def test_the_late_words_follow_every_other_word_of_their_window(self):
        for window in WINDOW_NAMES:
            late = ['F_LATE' in row[4] for row in self.rows if row[1] == window]
            with self.subTest(window=window):
                self.assertEqual(late, sorted(late), 'a word Linux never reads comes before a word it reads')

    def test_the_first_word_of_every_window_is_one_that_linux_reads(self):
        first = {}
        for key, window, expression, dec, flags in self.rows:
            first.setdefault(window, key)
        self.assertEqual(first, {'GCC': 'CFGA', 'GPUCC': 'CXGD', 'CXMISC': 'TCMR', 'GMU': 'GXST', 'RSCC': 'BSY', 'SMMU': 'ID0'})
        for window in ('CXMISC', 'GMU', 'RSCC'):
            with self.subTest(window=window):
                self.assertTrue(self.driver_reads(self.LINUX_NAME[first[window]]), f'the pinned driver never reads {first[window]}')
        # GCC and GPUCC: the clock and GDSC code reads these CBCRs and GDSCRs (the ledger holds the lines), the SMMU ones are arm-smmu.c reads: INFERRED, not pinned
        for entry in (('cmn', 317, 318), ('cb', 106, 109), ('gdsc', 127, 141), ('gdsc', 424, 424)):
            with self.subTest(ledger=entry):
                self.assertIn(entry, refs.ledger_index())

    # ---- the flags and the decodes --------------------------------------------------------------------------------------------------------------
    def test_the_hardware_gating_and_skipped_halt_flags_are_the_pinned_clock_structs(self):
        gcc = self.files['gcc-x1e80100.c']
        structs = {'QMIP': 'gcc_qmip_gpu_ahb_clk', 'MNOC': 'gcc_gpu_memnoc_gfx_clk', 'SNOC': 'gcc_gpu_snoc_dvm_gfx_clk', 'AXI_NW': 'gcc_ddrss_gpu_axi_clk'}
        for key, window, expression, dec, flags in self.rows:
            if key not in structs:
                continue
            with self.subTest(key=key):
                self.assertEqual('F_HWCG' in flags, refs.struct_field(gcc, structs[key], 'hwcg_reg') is not None)
                self.assertEqual('F_NOHALT' in flags, refs.struct_field(gcc, structs[key], 'halt_check') == 'BRANCH_HALT_SKIP')
                self.assertEqual(refs.struct_field(gcc, structs[key], 'hwcg_bit'), '1' if 'F_HWCG' in flags else None)
        for key, window, expression, dec, flags in self.rows:
            if window == 'GPUCC':
                with self.subTest(key=key):
                    self.assertNotIn('F_HWCG', flags, 'no GPUCC clock of the pinned file has a hardware gating bit')
                    self.assertNotIn('F_NOHALT', flags)
        by_key = {row[0]: row for row in self.rows}
        self.assertEqual(by_key['CFGA'][4], '0', 'the GPU CFG AHB clock has no clock struct, so no hardware gating bit and a halt check that is Linux’s default')
        self.assertEqual(by_key['CFGA'][3], 'D_CBCR')
        self.assertEqual(by_key['AXI_NW'][3], 'D_NW', 'a clock whose halt check is skipped has no .ON/.OFF token')

    def test_the_gate_inputs_are_the_clocks_of_the_two_device_tree_nodes_in_their_order(self):
        dt = self.files['hamoa.dtsi']
        by_address = {}
        for key, window, expression, dec, flags in self.rows:
            by_address[(window, refs.macro_offset(self.header, window, expression))] = key

        def clock_keys(first, last):
            names = re.findall(r'<&(gpucc|gcc) (\w+)>', '\n'.join(dt[first - 1:last]))
            keys = []
            for provider, macro in names:
                struct = macro.lower()
                lines = self.files['gpucc-x1e80100.c' if provider == 'gpucc' else 'gcc-x1e80100.c']
                keys.append(by_address[('GPUCC' if provider == 'gpucc' else 'GCC', int(refs.struct_field(lines, struct, 'halt_reg'), 0))])
            return keys

        gmu_nodes = clock_keys(4184, 4190)
        smmu_nodes = clock_keys(4268, 4271)
        array = lambda name: re.search(rf'{name}\[\w+\] = \{{([^}}]*)\}};', self.source).group(1)       # noqa: E731
        enum = re.search(r'enum \{(?:[^{}]|\n)*?R_CFGA(?:[^{}]|\n)*?R_COUNT\n\};', self.header).group(0)
        names = [n for n in re.findall(r'\bR_[A-Z0-9]+\b', enum) if n != 'R_COUNT']
        self.assertEqual(len(names), len(self.rows), 'one enumerator per row of the table, in the order of the table')
        keyof = {name: row[0] for name, row in zip(names, self.rows)}
        self.assertEqual([keyof[x.strip()] for x in array('gmu_clocks').split(',')], gmu_nodes)
        self.assertEqual([keyof[x.strip()] for x in array('smmu_clocks').split(',')], smmu_nodes)
        self.assertEqual(gmu_nodes, ['AHB', 'CGMU', 'CXO', 'AXI_NW', 'MNOC', 'HUB', 'DMT'])
        self.assertEqual(smmu_nodes, ['HLOS', 'MNOC', 'SNOC', 'AHB'])
        self.assertEqual(number(self.header, 'GMU_CLOCKS'), 7)
        self.assertEqual(number(self.header, 'SMMU_CLOCKS'), 4)

    def test_the_bit_positions_of_the_code_are_the_pinned_macros(self):
        cb, gdsc, rcg, smmu = self.files['clk-branch.h'], self.files['gdsc.c'], self.files['clk-rcg2.c'], self.files['arm-smmu.h']
        gcc = self.files['gcc-x1e80100.c']
        xml = self.files['a6xx_gmu.xml']
        checks = {
            'CBCR_CLK_OFF_BIT': refs.bit_of(cb, 'CBCR_CLK_OFF'), 'CBCR_ENABLE_BIT': refs.bit_of(cb, 'CBCR_CLOCK_ENABLE'),
            'CBCR_HW_CTL_BIT': int(refs.struct_field(gcc, 'gcc_gpu_memnoc_gfx_clk', 'hwcg_bit')),
            'GDSC_PWR_ON_BIT': refs.bit_of(gdsc, 'PWR_ON_MASK'), 'GDSC_SW_COLLAPSE_BIT': refs.bit_of(gdsc, 'SW_COLLAPSE_MASK'),
            'GDSC_HW_CONTROL_BIT': refs.bit_of(gdsc, 'HW_CONTROL_MASK'),
            'GXCFG_UP_BIT': refs.bit_of(gdsc, 'GDSC_POWER_UP_COMPLETE'), 'GXCFG_DOWN_BIT': refs.bit_of(gdsc, 'GDSC_POWER_DOWN_COMPLETE'),
            'VOTE_CPH_BIT': refs.evaluate(gcc, refs.struct_field(gcc, 'gcc_gpu_gpll0_cph_clk_src', 'enable_mask')).bit_length() - 1,
            'VOTE_DIV_BIT': refs.evaluate(gcc, refs.struct_field(gcc, 'gcc_gpu_gpll0_div_cph_clk_src', 'enable_mask')).bit_length() - 1,
            'RCG_SRC_SHIFT': refs.evaluate(rcg, 'CFG_SRC_SEL_SHIFT'), 'RCG_SRC_MASK': refs.evaluate(rcg, 'CFG_SRC_SEL_MASK') >> refs.evaluate(rcg, 'CFG_SRC_SEL_SHIFT'),
            'SMMU_ID0_NUMSMRG_MASK': refs.field_of(smmu, 'ARM_SMMU_ID0_NUMSMRG')[1], 'SMMU_ID1_NUMCB_MASK': refs.field_of(smmu, 'ARM_SMMU_ID1_NUMCB')[1],
            'SMMU_ID1_PAGESIZE_BIT': refs.bit_of(smmu, 'ARM_SMMU_ID1_PAGESIZE'), 'SMMU_ID1_NUMPAGENDXB_SHIFT': refs.field_of(smmu, 'ARM_SMMU_ID1_NUMPAGENDXB')[0],
            'SMMU_ID2_PTFS_SHIFT': refs.bit_of(smmu, 'ARM_SMMU_ID2_PTFS_4K'), 'SMMU_ID2_UBS_SHIFT': refs.field_of(smmu, 'ARM_SMMU_ID2_UBS')[0],
            'SMMU_ID2_OAS_SHIFT': refs.field_of(smmu, 'ARM_SMMU_ID2_OAS')[0],
        }
        for name, value in checks.items():
            with self.subTest(field=name):
                self.assertEqual(number(self.header, name), value)
        fields = refs.xml_bitfields(xml, 'GMU_SPTPRAC_PWR_CLK_STATUS', 'A7XX')
        with self.subTest(field='GXST_OFF_MASK'):
            self.assertEqual(number(self.header, 'GXST_OFF_MASK'), (1 << fields['GX_HM_GDSC_POWER_OFF']) | (1 << fields['GX_HM_CLK_OFF']))
        # the page table format bits are three adjacent bits starting at the 4K one: 4K, 16K, 64K
        self.assertEqual([refs.bit_of(smmu, n) for n in ('ARM_SMMU_ID2_PTFS_4K', 'ARM_SMMU_ID2_PTFS_16K', 'ARM_SMMU_ID2_PTFS_64K')], [12, 13, 14])
        self.assertEqual((number(self.header, 'SMMU_ID2_UBS_SHIFT') - number(self.header, 'SMMU_ID2_OAS_SHIFT')), 4)

    def test_the_tcs_offset_is_the_a740_family_one(self):
        self.assertEqual(number(self.header, 'RSC_TCS_SEQMEM_DWORDS'), 4)
        self.assertEqual(number(self.header, 'GMU_WINDOW_FROM_GPU_BASE'), refs.dt_node_regs(self.files['hamoa.dtsi'], 'gmu')[0][0] - refs.dt_node_regs(self.files['hamoa.dtsi'], 'gpu')[0][0])

    def test_the_decodes_the_table_names_exist_in_the_source(self):
        for name in sorted({row[3] for row in self.rows}):
            with self.subTest(decode=name):
                self.assertRegex(self.header, rf'\b{name}\b')


if __name__ == '__main__':
    unittest.main(verbosity=2)
