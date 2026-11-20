#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""The register table of payloads/inputsnap-regs.h and the field positions of payloads/inputsnap.c against the pinned Linux files.

    python3 tools/test-q1n1-sp11-payload-inputsnap-refs.py

The pinned copies are git-ignored: build/sp11-stick-log/refs/ of the Snapintosh tree (SNAPINTOSH_DIR, or INPUTSNAP_SNAP_REFS_DIR) and build/inputsnap-refs/ of this
tree (INPUTSNAP_REFS_DIR; docs/SP11-PAYLOAD-INPUTSNAP-REGISTERS.md has the fetch commands). Without them every test here is a SKIP, never a pass. Every file is checked against
its SHA-256 first. INPUTSNAP_PAYLOAD_DIR points the test at another copy of payloads/inputsnap.c and inputsnap-regs.h: that is how the seeded bugs of
tools/sp11_payload_inputsnap_mutants.py are shown to be refused by this check.

  Ledger     every file:line the document may cite shows what the ledger says it shows
  Table      every register of the table is the one the pinned file names: the clock words (halt register, vote register, hardware gating bit, the engine each one
             gates), the GENI words and the UART engine's own, the GIC words of each interrupt (derived from the interrupt number and the GICD base offsets), the pin
             words (derived from the pin number and the pin controller's layout), the windows (the device tree's) and the bit positions and masks of the derived items

Hardware: NOT RUN. Evidence: EXPERIMENTAL for the payload; VERIFIED means that a pinned file says so, nothing more."""
import os
from pathlib import Path
import re
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import sp11_payload_inputsnap_refs as refs  # noqa: E402

PAYLOADS = Path(os.environ.get('INPUTSNAP_PAYLOAD_DIR') or ROOT / 'payloads')

# The clock struct each GCC row of the table is, and the engine its word gates (a bit per engine: the UART engine 1, the SPI engine 2).
CLOCKS = {
    'MA0': ('gcc_qupv3_wrap_0_m_ahb_clk', 1), 'SA0': ('gcc_qupv3_wrap_0_s_ahb_clk', 1), 'CR0': ('gcc_qupv3_wrap0_core_clk', 1), 'C20': ('gcc_qupv3_wrap0_core_2x_clk', 0),
    'SE0': ('gcc_qupv3_wrap0_s2_clk', 1), 'MA1': ('gcc_qupv3_wrap_1_m_ahb_clk', 2), 'SA1': ('gcc_qupv3_wrap_1_s_ahb_clk', 2), 'CR1': ('gcc_qupv3_wrap1_core_clk', 2),
    'C21': ('gcc_qupv3_wrap1_core_2x_clk', 0), 'SE1': ('gcc_qupv3_wrap1_s2_clk', 2), 'QS1': ('gcc_qupv3_wrap1_qspi_s2_clk', 2),
}
VOTES = {'VT0': '0x52020', 'VT1': '0x52008', 'VT2': '0x52028'}
# The #define each engine row is (geni-se.h unless the name starts with SE_UART_, which is qcom_geni_serial.c's).
ENGINE_DEFINES = {
    'FW': 'GENI_FW_REVISION_RO', 'IFD': 'GENI_IF_DISABLE_RO', 'ST': 'SE_GENI_STATUS', 'DMA': 'SE_GENI_DMA_MODE_EN', 'DIF': 'DMA_IF_EN_RO', 'HW0': 'SE_HW_PARAM_0',
    'HW1': 'SE_HW_PARAM_1', 'CM': 'GENI_SER_M_CLK_CFG', 'CS': 'GENI_SER_S_CLK_CFG', 'CK': 'SE_GENI_CLK_SEL', 'CC': 'GENI_CLK_CTRL_RO', 'IOM': 'SE_UART_IO_MACRO_CTRL',
    'TCF': 'SE_UART_TX_TRANS_CFG', 'TWL': 'SE_UART_TX_WORD_LEN', 'TSB': 'SE_UART_TX_STOP_BIT_LEN', 'RCF': 'SE_UART_RX_TRANS_CFG', 'RWL': 'SE_UART_RX_WORD_LEN',
    'STL': 'SE_UART_RX_STALE_CNT', 'TPA': 'SE_UART_TX_PARITY_CFG', 'RPA': 'SE_UART_RX_PARITY_CFG', 'MRF': 'SE_UART_MANUAL_RFR', 'TWM': 'SE_GENI_TX_WATERMARK_REG',
    'RWM': 'SE_GENI_RX_WATERMARK_REG', 'RFW': 'SE_GENI_RX_RFR_WATERMARK_REG', 'TXF': 'SE_GENI_TX_FIFO_STATUS', 'RXF': 'SE_GENI_RX_FIFO_STATUS',
    'MIS': 'SE_GENI_M_IRQ_STATUS', 'MIE': 'SE_GENI_M_IRQ_EN', 'SIS': 'SE_GENI_S_IRQ_STATUS', 'SIE': 'SE_GENI_S_IRQ_EN', 'IOS': 'SE_GENI_IOS',
}
# What the payload prints beside a word: key -> (shift, mask) of the field it takes from it, and the pinned names that give them.
DERIVED = {'PR': ('FW_REV_PROTOCOL_MSK', 'gse'), 'M': ('M_GENI_CMD_ACTIVE', 'gse'), 'S': ('S_GENI_CMD_ACTIVE', 'gse'), 'TXN': ('TX_FIFO_WC', 'gse'),
           'RXN': ('RX_FIFO_WC_MSK', 'gse'), 'CTS': ('IO2_DATA_IN', 'gse')}


def lowest_bit(mask):
    return (mask & -mask).bit_length() - 1


class Pinned(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        snap, fetched = refs.snap_refs_dir(), refs.fetched_dir()
        if snap is None or fetched is None:
            raise unittest.SkipTest('no pinned reference copies (SNAPINTOSH_DIR with build/sp11-stick-log/refs, and build/inputsnap-refs): a SKIP, not a pass')
        cls.files = refs.load(snap, fetched)
        cls.regs_text = (PAYLOADS / 'inputsnap-regs.h').read_text(encoding='utf-8')
        cls.source = (PAYLOADS / 'inputsnap.c').read_text(encoding='utf-8')
        cls.rows = refs.parse_rows(cls.regs_text)
        cls.by_key = {}
        for row in cls.rows:
            cls.by_key.setdefault((row['block'], row['key']), row)

    def f(self, name):
        return self.files[refs.PREFIX[name] if name in refs.PREFIX else name]

    def test_every_ledger_entry_shows_what_it_says(self):
        self.assertEqual(refs.ledger_problems(self.files), [])

    def test_the_table_has_the_rows_the_code_counts(self):
        self.assertEqual(len(self.rows), 110)
        self.assertEqual([r['block'] for r in self.rows].count('B_GCC'), 14)
        for block in ('B_GIC', 'B_U2', 'B_S10', 'B_TLMM', 'B_XU2', 'B_XS10', 'B_XGIC'):
            keys = [r['key'] for r in self.rows if r['block'] == block]
            self.assertEqual(len(keys), len(set(keys)), f'a key is used twice in {block}')

    def test_the_gcc_words_are_the_clocks_the_table_names(self):
        gcc = self.f('gcc')
        for key, (struct, engine) in CLOCKS.items():
            row = self.by_key[('B_GCC', key)]
            with self.subTest(key=key, clock=struct):
                self.assertEqual(refs.struct_field(gcc, struct, 'halt_reg'), f'0x{row["off"]:x}')
                self.assertEqual(refs.struct_field(gcc, struct, 'halt_check'), 'BRANCH_HALT_VOTED')
                self.assertEqual(bool(refs.struct_field(gcc, struct, 'hwcg_reg')), 'F_HWCG' in row['flags'], 'only a clock that names a hardware gating bit has F_HWCG')
                if refs.struct_field(gcc, struct, 'hwcg_reg'):
                    self.assertEqual(refs.struct_field(gcc, struct, 'hwcg_reg'), f'0x{row["off"]:x}')
                    self.assertEqual(refs.struct_field(gcc, struct, 'hwcg_bit'), '1')
                self.assertEqual({'GATE_U2': 1, 'GATE_S10': 2, '0': 0}[row['gate']], engine)
                self.assertEqual(row['grp'], 'G_W0' if '0' in key[-1:] else 'G_W1', 'the group is the wrapper the clock is in')
                self.assertEqual('F_S2' in row['flags'], True)
        for key, vote in VOTES.items():
            with self.subTest(vote=key):
                row = self.by_key[('B_GCC', key)]
                self.assertEqual(f'0x{row["off"]:x}', vote)
                self.assertEqual(row['grp'], 'G_VOTE')
        # The vote words are the ones the clocks are voted in: every clock's enable_reg is one of them.
        for struct, _ in CLOCKS.values():
            self.assertIn(refs.struct_field(gcc, struct, 'enable_reg'), VOTES.values())

    def test_the_gates_are_the_clocks_each_engine_needs(self):
        gcc = self.f('gcc')
        # The UART engine (uart2, wrapper 0) needs the wrapper's two AHB clocks, its core clock and its own s2 clock; the SPI engine (spi10, wrapper 1) the same of wrapper
        # 1 and its QSPI clock. The core 2x clocks are voted by the wrappers' drivers and gate nothing here.
        dt = self.f('dt')
        self.assertIn('GCC_QUPV3_WRAP_0_M_AHB_CLK', '\n'.join(dt[2144:2146]))
        self.assertIn('GCC_QUPV3_WRAP_0_S_AHB_CLK', '\n'.join(dt[2144:2146]))
        self.assertIn('GCC_QUPV3_WRAP0_S2_CLK', dt[2342])
        self.assertIn('GCC_QUPV3_WRAP1_S2_CLK', dt[1693])
        gated = {1: set(), 2: set()}
        for key, (struct, engine) in CLOCKS.items():
            for e in (1, 2):
                if engine & e:
                    gated[e].add(struct)
        self.assertEqual(gated[1], {'gcc_qupv3_wrap_0_m_ahb_clk', 'gcc_qupv3_wrap_0_s_ahb_clk', 'gcc_qupv3_wrap0_core_clk', 'gcc_qupv3_wrap0_s2_clk'})
        self.assertEqual(gated[2], {'gcc_qupv3_wrap_1_m_ahb_clk', 'gcc_qupv3_wrap_1_s_ahb_clk', 'gcc_qupv3_wrap1_core_clk', 'gcc_qupv3_wrap1_s2_clk',
                                    'gcc_qupv3_wrap1_qspi_s2_clk'})
        self.assertIsNotNone(refs.struct_field(gcc, 'gcc_qupv3_wrap1_qspi_s2_clk', 'halt_reg'))

    def test_the_engine_words_are_the_named_defines(self):
        for block in ('B_U2', 'B_S10', 'B_XU2', 'B_XS10'):
            for row in (r for r in self.rows if r['block'] == block):
                name = ENGINE_DEFINES.get(row['key'])
                with self.subTest(block=block, key=row['key']):
                    self.assertIsNotNone(name, 'a key the test does not know')
                    lines = self.f('gser') if name.startswith('SE_UART_') else self.f('gse')
                    self.assertEqual(refs.evaluate(lines, refs.define(lines, name)), row['off'])
        s10 = {r['key'] for r in self.rows if r['block'] in ('B_S10', 'B_XS10')}
        u2 = {r['key'] for r in self.rows if r['block'] in ('B_U2', 'B_XU2')}
        self.assertEqual(u2 - s10, {k for k, v in ENGINE_DEFINES.items() if v.startswith('SE_UART_') or k in ('TWM', 'RWM', 'RFW')}, 'the SPI engine reads the common words only')
        # Neither FIFO window (a receive read pops bytes) and nothing past the first page.
        gse = self.f('gse')
        for window in ('SE_GENI_TX_FIFOn', 'SE_GENI_RX_FIFOn'):
            start = refs.evaluate(gse, refs.define(gse, window))
            for row in self.rows:
                if row['block'] in ('B_U2', 'B_S10', 'B_XU2', 'B_XS10'):
                    self.assertFalse(start <= row['off'] < start + 0x40, f'{row["key"]} is in the {window} window')
        self.assertTrue(all(r['off'] < 0x1000 for r in self.rows if r['block'] in ('B_U2', 'B_S10', 'B_XU2', 'B_XS10')))

    def test_the_derived_items_use_the_pinned_masks(self):
        found = {m.group(1): (int(m.group(2)), int(m.group(3), 0)) for m in
                 re.finditer(r'put_field\(c, o, "(\w+)", v, (\d+), (0x[0-9a-f]+|\d+)u?, D_NONE\)', self.source)}
        self.assertEqual(set(found), set(DERIVED))
        for key, (name, prefix) in DERIVED.items():
            mask = refs.evaluate(self.f(prefix), refs.define(self.f(prefix), name))
            with self.subTest(item=key):
                self.assertEqual(found[key], (lowest_bit(mask), mask >> lowest_bit(mask)), f'{key} is not the field {name}')

    def test_the_protocol_numbers_the_page_leans_on(self):
        gse = self.f('gse')
        text = '\n'.join(gse[33:40])
        order = re.findall(r'GENI_SE_\w+', text)
        self.assertEqual(order[:6], ['GENI_SE_NONE', 'GENI_SE_SPI', 'GENI_SE_UART', 'GENI_SE_I2C', 'GENI_SE_I3C', 'GENI_SE_SPI_SLAVE'])
        self.assertIn('GENI_SE_INVALID_PROTO = 255', text)
        self.assertEqual(order.index('GENI_SE_UART'), 2)

    def test_the_gic_words_are_where_the_interrupts_live(self):
        gic = self.f('gic')
        base = {name: refs.evaluate(gic, refs.define(gic, f'GICD_{name}')) for name in ('IGROUPR', 'ISENABLER', 'ISPENDR', 'ICFGR', 'IROUTER', 'CTLR', 'TYPER')}
        self.assertEqual(self.by_key[('B_GIC', 'CTL')]['off'], base['CTLR'])
        self.assertEqual(self.by_key[('B_GIC', 'TYP')]['off'], base['TYPER'])
        dt = self.f('dt')
        spis = {240: 208, 616: 584, 834: 802}      # the device tree's GIC_SPI numbers of the pin controller, uart2 and spi10; the INTID is the SPI number plus 32
        self.assertIn('GIC_SPI 208', dt[6122])
        self.assertIn('GIC_SPI 584', dt[2340])
        self.assertIn('GIC_SPI 802', dt[1691])
        for intid, spi in spis.items():
            self.assertEqual(intid, spi + 32)
            for letter, family, block in (('E', 'ISENABLER', 'B_GIC'), ('P', 'ISPENDR', 'B_GIC'), ('G', 'IGROUPR', 'B_XGIC')):
                row = self.by_key[(block, f'{letter}{intid}')]
                with self.subTest(intid=intid, family=family):
                    self.assertEqual(row['off'], base[family] + intid // 32 * 4)
                    self.assertEqual((row['dec'], row['shift'], row['width']), ('D_FIELD', intid % 32, 1))
            row = self.by_key[('B_GIC', f'C{intid}')]
            self.assertEqual(row['off'], base['ICFGR'] + intid // 16 * 4)
            self.assertEqual((row['dec'], row['shift'], row['width']), ('D_FIELD', intid % 16 * 2, 2), 'a two-bit field of the configuration word')
            row = self.by_key[('B_XGIC', f'R{intid}')]
            self.assertEqual(row['off'], base['IROUTER'] + intid * 8)
            self.assertIn('F_WIDE', row['flags'])
        self.assertEqual(sum(r['block'] == 'B_GIC' for r in self.rows), 2 + 3 * 3)
        self.assertEqual(sum(r['block'] == 'B_XGIC' for r in self.rows), 2 * 3)

    def test_the_pin_words_follow_the_pin_controllers_layout(self):
        pin = self.f('pin')
        size = refs.evaluate(pin, refs.define(pin, 'REG_SIZE'))
        pins = (8, 9, 10, 11, 40, 41, 42, 43, 2, 48, 51, 64, 91)
        self.assertLess(max(pins), 239)
        self.assertFalse(set(pins) & {44, 45, 46, 47, 238}, 'the TPM pins and the UFS reset are never read')
        seen = set()
        for number in pins:
            for key, off in ((f'F{number}', 0), (f'L{number}', 4)):
                row = self.by_key[('B_TLMM', key)]
                seen.add(key)
                with self.subTest(pin=number, word=key):
                    self.assertEqual(row['off'], number * size + off)
        for key, number, off in (('N51', 51, 8), ('S51', 51, 0xc), ('N91', 91, 8), ('S91', 91, 0xc)):
            seen.add(key)
            self.assertEqual(self.by_key[('B_TLMM', key)]['off'], number * size + off)
        self.assertEqual(seen, {r['key'] for r in self.rows if r['block'] == 'B_TLMM'})
        macro = '\n'.join(pin[11:53])
        self.assertIn('.io_reg = 0x4 + REG_SIZE * id', macro)
        self.assertIn('.intr_cfg_reg = 0x8 + REG_SIZE * id', macro)
        self.assertIn('.intr_status_reg = 0xc + REG_SIZE * id', macro)

    def test_the_windows_are_the_device_trees(self):
        dt = self.f('dt')
        windows = [(int(a, 16), int(s, 16)) for a, s in re.findall(r'\{(0x[0-9a-f]+)u, (0x[0-9a-f]+)u, 0\}', self.regs_text)]
        self.assertEqual(len(windows), 5)
        expected = [refs.dt_reg(dt, 'gcc: clock-controller@100000'), refs.dt_reg(dt, 'intc: interrupt-controller@17000000'), refs.dt_reg(dt, 'uart2: serial@b88000'),
                    refs.dt_reg(dt, 'spi10: spi@a88000'), refs.dt_reg(dt, 'tlmm: pinctrl@f100000')]
        for name, (base, size), (dt_base, dt_size) in zip(('GCC', 'GIC', 'U2', 'S10', 'TLMM'), windows, expected):
            with self.subTest(window=name):
                self.assertEqual(base, dt_base)
                self.assertLessEqual(size, dt_size, 'the window is inside the device tree\'s')
        self.assertEqual(windows[2][1], 0x1000)
        self.assertEqual(windows[3][1], 0x1000)

    def test_the_pins_and_the_uart_of_the_unit_agree_with_the_device_trees(self):
        den = self.f('den')
        self.assertIn('<44 4>', den[1197])
        self.assertIn('<238 1>', den[1198])
        self.assertIn('gpio91', den[1221])
        self.assertIn('microsoft,surface-sam', den[1319])
        self.assertIn('current-speed = <4000000>', den[1323])
        pin = self.f('pin')
        self.assertIn('qup0_se2', pin[1574])       # gpio8
        self.assertIn('qup1_se2', pin[1606])       # gpio40

    def test_a_row_is_in_a_late_block_exactly_when_no_pinned_driver_reads_its_word(self):
        # The order of the page rests on this: what a Linux driver reads comes first, what none reads comes last, after snapshot 2 (the F_FRESH rows, in the late blocks).
        by_name = {name: digest for name, (_, digest) in refs.FETCHED.items()}
        self.assertIn('spi-geni-qcom.c', by_name)
        index = refs.ledger_index()
        for row in self.rows:
            late = row['block'] in ('B_XU2', 'B_XS10', 'B_XGIC')
            with self.subTest(block=row['block'], key=row['key']):
                self.assertEqual('F_FRESH' in row['flags'], late)
                reads = refs.reads_for(row['block'], row['key'])
                self.assertEqual(bool(reads), not late, 'a row has a read precedent in the ledger exactly when it is not a late row')
                for entry in reads:
                    self.assertIn(entry, index, 'a read precedent that is not a ledger entry')
                if late:
                    name, writes = refs.never_read(row['block'], row['key'])
                    self.assertEqual(refs.read_sites(self.files, name), [], f'a pinned driver reads {name}')
                    for entry in writes:
                        self.assertIn(entry, index)
                    self.assertTrue(any(name in '\n'.join(self.files[f]) for f in refs.DRIVER_FILES), f'{name} is not in the pinned files: the scan is vacuous')

    def test_the_scan_for_a_read_does_find_a_read(self):
        # The scan of the previous test must be able to say yes: these words are read by the drivers, and the scan finds the read.
        for name in ('SE_GENI_STATUS', 'SE_GENI_M_IRQ_STATUS', 'SE_UART_IO_MACRO_CTRL', 'GENI_IF_DISABLE_RO', 'GICD_ISENABLER', 'GICD_ISPENDR', 'GENI_FW_REVISION_RO'):
            with self.subTest(register=name):
                self.assertTrue(refs.read_sites(self.files, name), f'the scan finds no read of {name}')


if __name__ == '__main__':
    unittest.main(verbosity=2)
