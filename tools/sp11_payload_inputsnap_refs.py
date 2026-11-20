# SPDX-License-Identifier: MIT
"""The pinned reference copies behind docs/SP11-PAYLOAD-INPUTSNAP.md, its companion docs/SP11-PAYLOAD-INPUTSNAP-REGISTERS.md and the register table of payloads/inputsnap-regs.h,
and how to read them from a test.

Two directories hold them, both git-ignored. The Snapintosh fork keeps the Linux files it cites in build/sp11-stick-log/refs/ (docs/SP11-STICK-LOG.md section 10 pins
the revision and the SHA-256 of each file); this module finds it from SNAPINTOSH_DIR, or INPUTSNAP_SNAP_REFS_DIR for the directory itself. The other files (geni-se.h,
qcom_geni_serial.c, the SPI, GENI core, clock regmap, GIC and pin controller files) are fetched at the same Linux revision into build/inputsnap-refs/ of this tree, or
INPUTSNAP_REFS_DIR (docs/SP11-PAYLOAD-INPUTSNAP-REGISTERS.md has the fetch commands and the digests). Both are checked against the
digests below. This module offers:

  LEDGER      every file:line the document may cite, with what that line must show in the pinned copy. The document test holds each citation of the document to
              this list; tools/test-q1n1-sp11-payload-inputsnap-refs.py holds each entry of it to the files.
  extractors  the same registers read by NAME (a clock struct of gcc-x1e80100.c, a #define of geni-se.h), so that a register table whose line numbers are right
              and whose offsets are not is still caught.
  parse_rows  the register table of payloads/inputsnap-regs.h.

VERIFIED in this module means: a pinned file says so. It never means that the unit does. Nothing here reads hardware."""
import hashlib
import os
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]

# docs/SP11-STICK-LOG.md section 10: Linux 7475ea8b58616b33c04afb976cf0fbaad9dd63fb, SHA-256 of the fetched bytes.
PINNED = {
    'hamoa.dtsi': 'd5bb1f7ce37c721d75fb5b4cffc8f58bed4d3ef9786a231a0deca05e917529e0',
    'gcc-x1e80100.c': 'f1c3779c7bc273dfe170ea2ff4d40f975083ee149e3b02a4f42d5939596eb775',
    'clk-branch.h': 'bac7dcf51a0da5b27eaa0d4dc276f540fec80013bd4862cfbbc115a50161ef72',
    'x1-microsoft-denali.dtsi': 'afbea2d7b48c1725b34a742b4c34432015ac237e6c390e94458551fb4213a239',
}
# Not in that table. refs/ holds a copy that was fetched with the others; its digest is recorded here and the document says so wherever it cites the file.
UNPINNED = {'clk-branch.c': 'd29259eb77a5d1d6a07adf4aa835588f8e04d1fa3c14be2b7d4162cce737abfa'}
# Fetched for this payload at the same revision (https://raw.githubusercontent.com/torvalds/linux/<revision>/<path>), SHA-256 of the fetched bytes.
LINUX_REVISION = '7475ea8b58616b33c04afb976cf0fbaad9dd63fb'
FETCHED = {
    'geni-se.h': ('include/linux/soc/qcom/geni-se.h', '6aab274a8a269605887d426b71022ad018d5b9439f4e5fdfc980041a457c322d'),
    'qcom_geni_serial.c': ('drivers/tty/serial/qcom_geni_serial.c', 'b37708d4d4a71d33e49b771065c10986d412eb18397ba251c4025b55bd4c2d2e'),
    'arm-gic-v3.h': ('include/linux/irqchip/arm-gic-v3.h', 'b11308e0281508b648d648cd652bce38a1fba774dbd47ed51de613a8533a3d13'),
    'irq-gic-common.c': ('drivers/irqchip/irq-gic-common.c', '3e322d8067549bb33adb59c893f49e7665957b1f6613ae53bb3403fb3029c3f1'),
    'irq-gic-v3.c': ('drivers/irqchip/irq-gic-v3.c', '8e2a7ce97bf52a1ade7a7ce89d75399b03aa2c96a4101710605434fb83b60dad'),
    'pinctrl-x1e80100.c': ('drivers/pinctrl/qcom/pinctrl-x1e80100.c', 'fd70c0b9013800a4016351a08b4d86aaefaa75e88758f9a02fde380e84642259'),
    'pinctrl-msm.c': ('drivers/pinctrl/qcom/pinctrl-msm.c', 'a593e9d2facdf4b07fb15d467ad374ab36ffd83eb97b74e43f177540992c4984'),
    'pinctrl-msm.h': ('drivers/pinctrl/qcom/pinctrl-msm.h', '02d034432dd718dab883d1e9e5e3f5124387753af723e7c7839675dbf29427bb'),
    # Added for the "Linux reads it" column of the register table: which of the table's words a pinned driver reads, and which it only writes or never touches.
    'spi-geni-qcom.c': ('drivers/spi/spi-geni-qcom.c', '5ea2354f2efd520f16c3aceeae1b1225fedeeb622ea84060756e7ef65722bda4'),
    'qcom-geni-se.c': ('drivers/soc/qcom/qcom-geni-se.c', 'f8f7fc2a68e1ac8c927ac7d37c9d901c9aef75ef78f4ccc668ebe0a0ba71825e'),
    'clk-regmap.c': ('drivers/clk/qcom/clk-regmap.c', '2438f057d67c3cd0229e710494dcf0a381bc69021591fe9cb89219734b8e633d'),
}
PREFIX = {'gcc': 'gcc-x1e80100.c', 'cb': 'clk-branch.h', 'cbc': 'clk-branch.c', 'dt': 'hamoa.dtsi', 'den': 'x1-microsoft-denali.dtsi', 'gse': 'geni-se.h',
          'gser': 'qcom_geni_serial.c', 'gic': 'arm-gic-v3.h', 'gicc': 'irq-gic-common.c', 'gic3': 'irq-gic-v3.c', 'pin': 'pinctrl-x1e80100.c',
          'msm': 'pinctrl-msm.c', 'msmh': 'pinctrl-msm.h', 'spi': 'spi-geni-qcom.c', 'gsec': 'qcom-geni-se.c', 'clkr': 'clk-regmap.c'}
CITATION = re.compile(r'\b(gicc|gic3|gic|gcc|cbc|cb|dt|den|gser|gsec|gse|pin|msmh|msm|spi|clkr):(\d+)(?:-(\d+))?\b')

# What no pinned file says: the document's "What could not be verified" lists these ids and no others, and no register offset or bit position of the table or the
# code rests on an item of this list except where the item says so.
UNVERIFIED = {
    'UV1': 'the unit-specific facts of the design note: the bus, base address, interrupt and pins of each input device are decoded from the unit\'s own dumped ACPI '
           'tables (OBSERVED; no table bytes in this tree) and agree with hamoa.dtsi and x1-microsoft-denali.dtsi where those say anything; no pinned file holds them',
    'UV2': 'the protocol number 9 of the SPI engine (a third party reports it for QSPI; geni-se.h has no QSPI value: it prints raw and is read as "not 0, 1, 2, 3, 4, 5 or '
           '255")',
    'UV3': 'how the GICD registers answer a non-secure read when GICD_CTLR.DS is clear (IGROUPR and IROUTER may read as zero: the GIC architecture, not a pinned file; the '
           'words print raw and GICD_CTLR is OBSERVED as 0x10 in boots 3, 12 and 14)',
    'UV4': 'whether TLMM words of pins that firmware gave to the secure world read normally at EL2 (never read on the unit; an abort prints FAULT:6 and ends the block)',
    'UV5': 'the meaning of the bits of GENI_CLK_CTRL_RO, SE_GENI_CLK_SEL, the SER_M and SER_S clock configuration words, SE_HW_PARAM_0 and SE_HW_PARAM_1 (printed raw; geni-se.h '
           'defines their fields and the printed number is the whole word)',
    'UV6': 'that a read of an engine whose clocks all read ON cannot hang: only a non-secure access of an engine whose clock is stopped is documented to (INFERRED from the '
           'usbsnap review); no guard recovers a hang or an SError',
    'UV7': 'that no Linux driver reads the words of the late blocks: the scan covers the pinned UART, SPI, GENI core and irqchip files only (the I2C, I3C and QSPI drivers, '
           'and firmware, may read them), and a word read by none of them is not thereby safe to read: it is read last, which is all the order claims',
}


def snap_refs_dir():
    """The directory of the Snapintosh pinned copies, or None."""
    direct = os.environ.get('INPUTSNAP_SNAP_REFS_DIR')
    tree = os.environ.get('SNAPINTOSH_DIR')
    found = Path(direct) if direct else (Path(tree) / 'build' / 'sp11-stick-log' / 'refs' if tree else None)
    return found if found and found.is_dir() else None


def fetched_dir():
    """The directory of the copies this payload's design note fetched, or None."""
    direct = os.environ.get('INPUTSNAP_REFS_DIR')
    found = Path(direct) if direct else ROOT / 'build' / 'inputsnap-refs'
    return found if found.is_dir() else None


def load(snap_dir, fetched=None):
    """{file name: [lines]} of the pinned copies in `snap_dir` and, when given, of the fetched ones in `fetched`, each checked against its digest (ValueError on a
    mismatch: a changed file is not a reference)."""
    files = {}
    wanted = [(name, digest, Path(snap_dir)) for name, digest in {**PINNED, **UNPINNED}.items()]
    if fetched is not None:
        wanted += [(name, digest, Path(fetched)) for name, (_, digest) in FETCHED.items()]
    for name, digest, directory in wanted:
        data = (directory / name).read_bytes()
        if hashlib.sha256(data).hexdigest() != digest:
            raise ValueError(f'{name} is not the pinned copy')
        files[name] = data.decode('utf-8').splitlines()
    return files


def cited(text):
    """[(prefix, first line, last line)] of every file:line citation of `text`, in order."""
    return [(m.group(1), int(m.group(2)), int(m.group(3) or m.group(2))) for m in CITATION.finditer(text)]


# ---- The ledger ------------------------------------------------------------------------------------------------------------------------------------
# (prefix, first line, last line, pattern over the joined lines, what it shows). Every pattern was written from the line as read in the pinned copy.
def _clk(first, halt, vote, bit, what, hwcg=False):
    gap = r'\.halt_check = BRANCH_HALT_VOTED,\s*' + (rf'\.hwcg_reg = {halt},\s*\.hwcg_bit = 1,\s*' if hwcg else '') + r'\.clkr = \{\s*'
    return ('gcc', first, first + (6 if hwcg else 4), rf'\.halt_reg = {halt},\s*{gap}\.enable_reg = {vote},\s*\.enable_mask = BIT\({bit}\),', what)


LEDGER = [
    # gcc-x1e80100.c: the clocks of QUP wrapper 0 and 1 (halt word, voted, the vote bit)
    _clk(4337, '0x23018', '0x52020', 9, 'qupv3 wrap0 core 2x clock: halt word 0x23018, voted by bit 9 of 0x52020'),
    _clk(4350, '0x23008', '0x52020', 8, 'qupv3 wrap0 core clock: halt word 0x23008, voted by bit 8 of 0x52020'),
    _clk(4435, '0x42274', '0x52020', 12, 'qupv3 wrap0 s2 clock (the "se" clock of uart2): halt word 0x42274, voted by bit 12 of 0x52020'),
    _clk(4543, '0x23168', '0x52008', 18, 'qupv3 wrap1 core 2x clock: halt word 0x23168, voted by bit 18 of 0x52008'),
    _clk(4556, '0x23158', '0x52008', 19, 'qupv3 wrap1 core clock: halt word 0x23158, voted by bit 19 of 0x52008'),
    _clk(4569, '0x18280', '0x52028', 4, 'qupv3 wrap1 qspi_s2 clock: halt word 0x18280, voted by bit 4 of 0x52028'),
    _clk(4641, '0x18274', '0x52008', 24, 'qupv3 wrap1 s2 clock (the "se" clock of spi10): halt word 0x18274, voted by bit 24 of 0x52008'),
    _clk(4955, '0x23000', '0x52020', 6, 'qupv3 wrap0 m_ahb clock: halt word 0x23000 with a hardware gating bit 1, voted by bit 6 of 0x52020', hwcg=True),
    _clk(4970, '0x23004', '0x52020', 7, 'qupv3 wrap0 s_ahb clock: halt word 0x23004 with a hardware gating bit 1, voted by bit 7 of 0x52020', hwcg=True),
    _clk(4985, '0x23150', '0x52008', 20, 'qupv3 wrap1 m_ahb clock: halt word 0x23150 with a hardware gating bit 1, voted by bit 20 of 0x52008', hwcg=True),
    _clk(5000, '0x23154', '0x52008', 21, 'qupv3 wrap1 s_ahb clock: halt word 0x23154 with a hardware gating bit 1, voted by bit 21 of 0x52008', hwcg=True),
    # clk-branch.h, clk-branch.c
    ('cb', 63, 63, r'CBCR_CLK_OFF\s+BIT\(31\)', 'CLK_OFF is bit 31'),
    ('cb', 64, 65, r'CBCR_NOC_FSM_STATUS\s+GENMASK\(30, 28\).*FSM_STATUS_ON\s+BIT\(1\)', 'the NoC FSM status is bits 30:28 and ON is the value 2'),
    ('cb', 15, 16, r'@hwcg_reg: dynamic hardware clock gating register.*@hwcg_bit: ORed with @hwcg_reg', 'hwcg_reg and hwcg_bit are a clock\'s own hardware gating control'),
    ('cbc', 17, 26, r'clk_branch_in_hwcg_mode.*if \(!br->hwcg_reg\)\s*return false;.*BIT\(br->hwcg_bit\)', 'a clock is in hardware gating mode only if it names a hwcg_reg'),
    ('cbc', 54, 57, r'if \(enabling\) \{.*CBCR_CLK_OFF\) == \(invert \? CBCR_CLK_OFF : 0\) \|\|.*FSM_STATUS_ON', 'an enabled clock is on when CLK_OFF is clear or the NoC FSM says ON'),
    ('cbc', 72, 72, r'BRANCH_HALT_SKIP \|\| clk_branch_in_hwcg_mode\(br\)', 'Linux does not wait for the halt bit of a clock in hardware gating mode'),
    # hamoa.dtsi
    ('dt', 758, 760, r'gcc: clock-controller@100000.*reg = <0 0x00100000 0 0x200000>;', 'the GCC window'),
    ('dt', 1491, 1496, r'qupv3_1: geniqup@ac0000.*GCC_QUPV3_WRAP_1_M_AHB_CLK.*GCC_QUPV3_WRAP_1_S_AHB_CLK', 'QUP wrapper 1 and its two AHB clocks'),
    ('dt', 1688, 1694, r'spi10: spi@a88000.*reg = <0 0x00a88000 0 0x4000>;.*GIC_SPI 802 IRQ_TYPE_LEVEL_HIGH.*GCC_QUPV3_WRAP1_S2_CLK', 'spi10: window, interrupt and clock'),
    ('dt', 2141, 2146, r'qupv3_0: geniqup@bc0000.*GCC_QUPV3_WRAP_0_M_AHB_CLK.*GCC_QUPV3_WRAP_0_S_AHB_CLK', 'QUP wrapper 0 and its two AHB clocks'),
    ('dt', 2337, 2343, r'uart2: serial@b88000.*"qcom,geni-uart".*reg = <0 0x00b88000 0 0x4000>;.*GIC_SPI 584 IRQ_TYPE_LEVEL_HIGH.*GCC_QUPV3_WRAP0_S2_CLK',
     'uart2: window, interrupt and clock'),
    ('dt', 2356, 2356, r'pinctrl-0 = <&qup_uart2_default>;', 'uart2 pin state'),
    ('dt', 6119, 6123, r'tlmm: pinctrl@f100000.*reg = <0 0x0f100000 0 0xf00000>;.*GIC_SPI 208 IRQ_TYPE_LEVEL_HIGH', 'the pin controller window and its summary interrupt'),
    ('dt', 6692, 6719, r'qup_uart2_default: qup-uart2-default-state.*"gpio8".*"qup0_se2".*"gpio9".*"qup0_se2".*"gpio10".*"qup0_se2".*"gpio11".*"qup0_se2"',
     'the uart2 pins gpio8-11 take the function qup0_se2'),
    ('dt', 8558, 8560, r'intc: interrupt-controller@17000000.*"arm,gic-v3".*reg = <0 0x17000000 0 0x10000>,\s*/\* GICD \*/', 'the GIC distributor window'),
    # x1-microsoft-denali.dtsi
    ('den', 20, 49, r'gpio-keys \{.*pm8550_gpios 8 GPIO_ACTIVE_LOW.*pm8550_gpios 6 GPIO_ACTIVE_LOW.*switch-lid \{\s*gpios = <&tlmm 2 GPIO_ACTIVE_LOW>;',
     'the volume keys are pm8550 gpio 8 and 6, the lid switch is tlmm gpio 2'),
    ('den', 1198, 1199, r'gpio-reserved-ranges = <44 4>, /\* SPI \(TPM\) \*/\s*<238 1>; /\* UFS Reset \*/', 'tlmm gpio 44-47 (the TPM) and 238 are reserved'),
    ('den', 1221, 1223, r'ssam_state: ssam-state-state \{\s*pins = "gpio91";\s*function = "gpio";', 'the Surface Aggregator\'s line is tlmm gpio 91'),
    ('den', 1316, 1327, r'&uart2 \{.*"microsoft,surface-sam".*<&tlmm 91 IRQ_TYPE_EDGE_RISING>.*current-speed = <4000000>;', 'uart2 carries the Surface Aggregator at 4 Mbps, interrupt gpio 91'),
    # geni-se.h
    ('gse', 34, 40, r'GENI_SE_NONE,\s*GENI_SE_SPI,\s*GENI_SE_UART,\s*GENI_SE_I2C,\s*GENI_SE_I3C,\s*GENI_SE_SPI_SLAVE,\s*GENI_SE_INVALID_PROTO = 255',
     'the protocol numbers: none 0, SPI 1, UART 2, I2C 3, I3C 4, SPI slave 5, invalid 255'),
    ('gse', 87, 92, r'SE_GENI_STATUS\s+0x40.*GENI_SER_M_CLK_CFG\s+0x48.*GENI_SER_S_CLK_CFG\s+0x4c.*GENI_CLK_CTRL_RO\s+0x60.*GENI_IF_DISABLE_RO\s+0x64.*GENI_FW_REVISION_RO\s+0x68',
     'STATUS, the two clock configuration words, CLK_CTRL_RO, IF_DISABLE_RO and FW_REVISION_RO'),
    ('gse', 94, 94, r'SE_GENI_CLK_SEL\s+0x7c', 'CLK_SEL'), ('gse', 96, 96, r'SE_GENI_DMA_MODE_EN\s+0x258', 'DMA_MODE_EN'),
    ('gse', 99, 100, r'SE_GENI_M_IRQ_STATUS\s+0x610.*SE_GENI_M_IRQ_EN\s+0x614', 'the main sequencer\'s interrupt status and enable'),
    ('gse', 108, 109, r'SE_GENI_S_IRQ_STATUS\s+0x640.*SE_GENI_S_IRQ_EN\s+0x644', 'the secondary sequencer\'s interrupt status and enable'),
    ('gse', 113, 114, r'SE_GENI_TX_FIFOn\s+0x700.*SE_GENI_RX_FIFOn\s+0x780', 'the FIFO windows, which this payload never reads'),
    ('gse', 115, 120, r'SE_GENI_TX_FIFO_STATUS\s+0x800.*SE_GENI_RX_FIFO_STATUS\s+0x804.*SE_GENI_TX_WATERMARK_REG\s+0x80c.*SE_GENI_RX_WATERMARK_REG\s+0x810.*'
     r'SE_GENI_RX_RFR_WATERMARK_REG\s+0x814.*SE_GENI_IOS\s+0x908', 'the FIFO status words, the watermarks and IOS'),
    ('gse', 152, 154, r'DMA_IF_EN_RO\s+0xe20.*SE_HW_PARAM_0\s+0xe24.*SE_HW_PARAM_1\s+0xe28', 'DMA_IF_EN_RO and the two hardware parameter words'),
    ('gse', 168, 169, r'M_GENI_CMD_ACTIVE\s+BIT\(0\).*S_GENI_CMD_ACTIVE\s+BIT\(12\)', 'STATUS bits 0 (main command active) and 12 (secondary command active)'),
    ('gse', 180, 181, r'FW_REV_PROTOCOL_MSK\s+GENMASK\(15, 8\).*FW_REV_PROTOCOL_SHFT\s+8', 'the protocol is bits 15:8 of FW_REVISION_RO'),
    ('gse', 272, 272, r'TX_FIFO_WC\s+GENMASK\(27, 0\)', 'the TX FIFO word count is bits 27:0'),
    ('gse', 278, 278, r'RX_FIFO_WC_MSK\s+GENMASK\(24, 0\)', 'the RX FIFO word count is bits 24:0'),
    ('gse', 281, 281, r'IO2_DATA_IN\s+BIT\(1\)', 'IOS bit 1 is IO2 data in'),
    # qcom_geni_serial.c
    ('gser', 37, 47, r'SE_UART_IO_MACRO_CTRL\s+0x240.*SE_UART_TX_TRANS_CFG\s+0x25c.*SE_UART_TX_WORD_LEN\s+0x268.*SE_UART_TX_STOP_BIT_LEN\s+0x26c.*'
     r'SE_UART_RX_TRANS_CFG\s+0x280.*SE_UART_RX_WORD_LEN\s+0x28c.*SE_UART_RX_STALE_CNT\s+0x294.*SE_UART_TX_PARITY_CFG\s+0x2a4.*SE_UART_RX_PARITY_CFG\s+0x2a8.*'
     r'SE_UART_MANUAL_RFR\s+0x2ac', 'the UART engine\'s own registers'),
    ('gser', 243, 245, r'geni_ios = readl\(uport->membase \+ SE_GENI_IOS\);\s*if \(!\(geni_ios & IO2_DATA_IN\)\)\s*mctrl \|= TIOCM_CTS;', 'CTS is asserted when IO2_DATA_IN is low'),
    ('gser', 1343, 1350, r'proto = geni_se_read_proto\(&port->se\);\s*if \(proto == GENI_SE_INVALID_PROTO\) \{.*else if \(proto != GENI_SE_UART\) \{',
     'the UART driver loads firmware only when the protocol reads 255 and refuses an engine whose protocol is not UART'),
    # arm-gic-v3.h and the two irqchip files
    ('gic', 13, 14, r'GICD_CTLR\s+0x0000.*GICD_TYPER\s+0x0004', 'GICD_CTLR and GICD_TYPER'),
    ('gic', 22, 25, r'GICD_IGROUPR\s+0x0080.*GICD_ISENABLER\s+0x0100.*GICD_ISPENDR\s+0x0200', 'IGROUPR, ISENABLER and ISPENDR'),
    ('gic', 30, 30, r'GICD_ICFGR\s+0x0C00', 'ICFGR'), ('gic', 42, 42, r'GICD_IROUTER\s+0x6000', 'IROUTER'),
    ('gic', 60, 63, r'GICD_CTLR_DS\s+\(1U << 6\).*GICD_CTLR_ARE_NS\s+\(1U << 4\).*GICD_CTLR_ENABLE_G1A\s+\(1U << 1\).*GICD_CTLR_ENABLE_G1\s+\(1U << 0\)',
     'GICD_CTLR: DS bit 6, ARE_NS bit 4, ENABLE_G1A bit 1, ENABLE_G1 bit 0'),
    ('gic', 97, 98, r'GICD_IROUTER_SPI_MODE_ONE\s+\(0U << 31\).*GICD_IROUTER_SPI_MODE_ANY\s+\(1U << 31\)', 'IROUTER bit 31 selects any-PE routing'),
    ('gicc', 51, 52, r'confmask = BIT\(\(\(irq % 16\) \* 2\) \+ 1\);\s*u32 confoff = \(irq / 16\) \* 4;', 'ICFGR holds a two-bit field per interrupt, sixteen per word'),
    ('gic3', 456, 469, r'gic_peek_irq.*mask = BIT\(index % 32\);.*base \+ offset \+ \(index / 32\) \* 4', 'ISENABLER, ISPENDR and IGROUPR hold a bit per interrupt, 32 per word'),
    ('gic3', 976, 977, r'for \(i = 32; i < GIC_LINE_NR; i\+\+\)\s*gic_write_irouter\(affinity, base \+ GICD_IROUTER \+ i \* 8\);', 'IROUTER is one 64-bit register per interrupt at 8 * n'),
    # pinctrl-x1e80100.c, pinctrl-msm.c, pinctrl-msm.h
    ('pin', 12, 12, r'REG_SIZE 0x1000', 'a pin\'s registers are 0x1000 apart'),
    ('pin', 32, 35, r'\.ctl_reg = REG_SIZE \* id,.*\.io_reg = 0x4 \+ REG_SIZE \* id,.*\.intr_cfg_reg = 0x8 \+ REG_SIZE \* id,.*\.intr_status_reg = 0xc \+ REG_SIZE \* id,',
     'CFG at 0x1000 * pin, IN_OUT at +4, INTR_CFG at +8, INTR_STATUS at +0xc'),
    ('pin', 36, 52, r'\.mux_bit = 2,.*\.pull_bit = 0,.*\.drv_bit = 6,.*\.oe_bit = 9,.*\.in_bit = 0,.*\.out_bit = 1,.*\.intr_enable_bit = 0,.*\.intr_status_bit = 0,.*'
     r'\.intr_target_bit = 5,.*\.intr_raw_status_bit = 4,.*\.intr_polarity_bit = 1,.*\.intr_detection_bit = 2,.*\.intr_detection_width = 2,',
     'the bit positions of a pin\'s words: function 5:2, pull 1:0, drive 8:6, output enable 9; input bit 0, output bit 1; interrupt enable 0, polarity 1, detection 3:2'),
    ('pin', 1569, 1569, r'\[2\] = PINGROUP\(2, qup0_se0,', 'gpio2'),
    ('pin', 1575, 1578, r'\[8\] = PINGROUP\(8, qup0_se2,.*\[9\] = PINGROUP\(9, qup0_se2,.*\[10\] = PINGROUP\(10, qup0_se2,.*\[11\] = PINGROUP\(11, qup0_se2,',
     'gpio8-11: function 1 is qup0_se2'),
    ('pin', 1607, 1610, r'\[40\] = PINGROUP\(40, qup1_se2,.*\[41\] = PINGROUP\(41, qup1_se2,.*\[42\] = PINGROUP\(42, qup1_se2,.*\[43\] = PINGROUP\(43, qup1_se2,',
     'gpio40-43: function 1 is qup1_se2'),
    ('pin', 1615, 1615, r'\[48\] = PINGROUP\(48, qup1_se4,', 'gpio48'),
    ('pin', 1618, 1618, r'\[51\] = PINGROUP\(51, qup1_se4, qup1_se2,', 'gpio51: function 1 is qup1_se4, function 2 qup1_se2'),
    ('pin', 1631, 1631, r'\[64\] = PINGROUP\(64, qup2_se0,', 'gpio64'), ('pin', 1658, 1658, r'\[91\] = PINGROUP\(91, qup2_se6,', 'gpio91'),
    ('pin', 1837, 1837, r'\.ngpios = 239,', 'the pin controller has 239 pins'),
    ('msm', 185, 185, r'mask = GENMASK\(g->mux_bit \+ order_base_2\(g->nfuncs\) - 1, g->mux_bit\);', 'the function field is four bits at the mux bit for a ten-function pin'),
    ('msm', 626, 626, r'return !!\(val & BIT\(g->in_bit\)\);', 'a pin\'s level is the input bit of its IN_OUT word'),
    ('msmh', 45, 53, r'@mux_bit:.*@pull_bit:.*@drv_bit:.*@od_bit:.*@oe_bit:.*@in_bit: .*@out_bit: .*@intr_enable_bit:.*@intr_status_bit:',
     'the pin controller\'s field descriptions'),
    # What the pinned drivers READ (a read precedent for a row of the table). Linux reads a branch clock's halt word (its CBCR) and, through is_enabled, the enable register
    # (for these clocks the vote word)
    ('cbc', 52, 52, r'regmap_read\(br->clkr\.regmap, br->halt_reg, &val\);', 'Linux reads a branch clock\'s halt word, its CBCR, when it enables one'),
    ('cbc', 175, 178, r'clk_branch2_ops = \{.*\.is_enabled = clk_is_enabled_regmap,', 'the branch clock ops read the enable register through clk_is_enabled_regmap'),
    ('clkr', 22, 37, r'clk_is_enabled_regmap.*ret = regmap_read\(rclk->regmap, rclk->enable_reg, &val\);.*return \(val & rclk->enable_mask\) != 0;',
     'clk_is_enabled_regmap reads enable_reg: for the QUP clocks the vote word'),
    ('gse', 375, 379, r'geni_se_read_proto\(struct geni_se \*se\).*val = readl_relaxed\(se->base \+ GENI_FW_REVISION_RO\);', 'geni_se_read_proto reads FW_REVISION_RO'),
    ('gse', 495, 495, r'val = readl_relaxed\(se->base \+ SE_HW_PARAM_0\);', 'the TX FIFO depth is read from SE_HW_PARAM_0'),
    ('gse', 541, 541, r'val = readl_relaxed\(se->base \+ SE_HW_PARAM_1\);', 'the RX FIFO depth is read from SE_HW_PARAM_1'),
    ('gser', 314, 319, r'readl\(uport->membase \+ SE_GENI_STATUS\) & M_GENI_CMD_ACTIVE;.*readl\(uport->membase \+ SE_GENI_STATUS\) & S_GENI_CMD_ACTIVE;',
     'the UART driver reads STATUS'),
    ('gser', 401, 407, r'readl\(uport->membase \+ SE_GENI_M_IRQ_STATUS\);.*readl\(uport->membase \+ SE_GENI_S_IRQ_STATUS\);.*readl\(uport->membase \+ SE_GENI_RX_FIFO_STATUS\);',
     'the UART driver reads the two interrupt status words and RX_FIFO_STATUS'),
    ('gser', 720, 720, r'm_irq_en = readl\(uport->membase \+ SE_GENI_M_IRQ_EN\);', 'the UART driver reads M_IRQ_EN'),
    ('gser', 792, 792, r'readl\(uport->membase \+ SE_GENI_TX_FIFO_STATUS\)', 'the UART driver reads TX_FIFO_STATUS'),
    ('gser', 952, 952, r'irq_en = readl\(uport->membase \+ SE_GENI_S_IRQ_EN\);', 'the UART driver reads S_IRQ_EN'),
    ('gser', 1237, 1241, r'readl\(uport->membase \+ SE_GENI_M_IRQ_STATUS\);.*readl\(uport->membase \+ SE_GENI_STATUS\);\s*dma = readl\(uport->membase \+ SE_GENI_DMA_MODE_EN\);.*'
     r'readl\(uport->membase \+ SE_GENI_M_IRQ_EN\);', 'the interrupt handler reads the main status, STATUS, the DMA mode word (and decodes the FIFO or the DMA registers by it) and M_IRQ_EN'),
    ('gser', 1363, 1363, r'pin_swap = readl\(uport->membase \+ SE_UART_IO_MACRO_CTRL\);', 'the UART driver reads IO_MACRO_CTRL'),
    ('gser', 1507, 1510, r'tx_trans_cfg = readl\(.*SE_UART_TX_TRANS_CFG\);\s*tx_parity_cfg = readl\(.*SE_UART_TX_PARITY_CFG\);\s*rx_trans_cfg = readl\(.*SE_UART_RX_TRANS_CFG\);\s*'
     r'rx_parity_cfg = readl\(.*SE_UART_RX_PARITY_CFG\);', 'the UART driver reads the transfer and parity configuration words'),
    ('spi', 290, 291, r'm_irq = readl\(se->base \+ SE_GENI_M_IRQ_STATUS\);\s*m_irq_en = readl\(se->base \+ SE_GENI_M_IRQ_EN\);', 'the SPI driver reads M_IRQ_STATUS and M_IRQ_EN'),
    ('spi', 645, 645, r'proto = geni_se_read_proto\(se\);', 'the SPI driver reads the protocol'),
    ('spi', 663, 663, r'mas->tx_fifo_depth = geni_se_get_tx_fifo_depth\(se\);', 'the SPI driver reads the FIFO depth'),
    ('spi', 684, 684, r'fifo_disable = readl\(se->base \+ GENI_IF_DISABLE_RO\) & FIFO_IF_DISABLE;', 'the SPI driver reads IF_DISABLE_RO'),
    ('spi', 788, 788, r'rx_fifo_status = readl\(se->base \+ SE_GENI_RX_FIFO_STATUS\);', 'the SPI driver reads RX_FIFO_STATUS'),
    ('spi', 1102, 1102, r'readl_relaxed\(se->base \+ SE_GENI_STATUS\) & M_GENI_CMD_ACTIVE', 'the SPI driver reads STATUS'),
    ('gic3', 162, 162, r'readl_relaxed\(gic_data\.dist_base \+ GICD_CTLR\) & GICD_CTLR_DS;', 'the GIC driver reads GICD_CTLR'),
    ('gic3', 571, 579, r'gic_peek_irq\(d, GICD_ISPENDR\);.*gic_peek_irq\(d, GICD_ISACTIVER\);.*gic_peek_irq\(d, GICD_ISENABLER\);', 'the GIC driver reads ISPENDR and ISENABLER (gic_peek_irq)'),
    ('gic3', 2003, 2003, r'typer = readl_relaxed\(gic_data\.dist_base \+ GICD_TYPER\);', 'the GIC driver reads GICD_TYPER'),
    ('gicc', 62, 62, r'val = oldval = readl_relaxed\(base \+ confoff\);', 'the GIC driver reads ICFGR when it configures an interrupt'),
    ('msm', 211, 211, r'val = msm_readl_ctl\(pctrl, g\);', 'the pin controller driver reads a pin\'s CFG word'),
    ('msm', 853, 853, r'val = msm_readl_intr_cfg\(pctrl, g\);', 'the pin controller driver reads INTR_CFG'),
    ('msm', 960, 960, r'val = msm_readl_io\(pctrl, g\) & BIT\(g->in_bit\);', 'the pin controller driver reads a pin\'s IN_OUT word for its level'),
    ('msm', 1348, 1348, r'\*val = msm_readl_intr_status\(pctrl, g\);', 'the pin controller driver reads INTR_STATUS'),
    # What they only WRITE (the late blocks' words: no read of them anywhere in the pinned drivers; tools/test-q1n1-sp11-payload-inputsnap-refs.py scans for one)
    ('gser', 267, 267, r'writel\(uart_manual_rfr, uport->membase \+ SE_UART_MANUAL_RFR\);', 'the UART driver writes MANUAL_RFR'),
    ('gser', 605, 605, r'writel\(DEF_TX_WM, uport->membase \+ SE_GENI_TX_WATERMARK_REG\);', 'the UART driver writes the TX watermark'),
    ('gser', 1361, 1361, r'writel\(rxstale, uport->membase \+ SE_UART_RX_STALE_CNT\);', 'the UART driver writes the receive stale count'),
    ('gser', 1477, 1480, r'writel\(ser_clk_cfg, uport->membase \+ GENI_SER_M_CLK_CFG\);\s*writel\(ser_clk_cfg, uport->membase \+ GENI_SER_S_CLK_CFG\);.*'
     r'writel\(clk_idx & CLK_SEL_MSK, uport->membase \+ SE_GENI_CLK_SEL\);', 'the UART driver writes the two serial clock configuration words and the clock selection'),
    ('gser', 1580, 1582, r'writel\(bits_per_char, uport->membase \+ SE_UART_TX_WORD_LEN\);\s*writel\(bits_per_char, uport->membase \+ SE_UART_RX_WORD_LEN\);\s*'
     r'writel\(stop_bit_len, uport->membase \+ SE_UART_TX_STOP_BIT_LEN\);', 'the UART driver writes the word lengths and the stop bit length'),
    ('gsec', 372, 373, r'writel_relaxed\(rx_wm, se->base \+ SE_GENI_RX_WATERMARK_REG\);\s*writel_relaxed\(rx_rfr, se->base \+ SE_GENI_RX_RFR_WATERMARK_REG\);',
     'the GENI core writes the RX and RX RFR watermarks'),
    ('gic3', 940, 940, r'writel_relaxed\(~0, base \+ GICD_IGROUPR \+ i / 8\);', 'the GIC driver writes IGROUPR'),
]


def ledger_index():
    """{(prefix, first, last): pattern} of the ledger."""
    return {(p, a, b): pattern for p, a, b, pattern, _ in LEDGER}


def ledger_problems(files):
    """[problem] for every ledger entry whose lines do not match in the pinned copy."""
    problems = []
    for prefix, first, last, pattern, what in LEDGER:
        lines = files[PREFIX[prefix]]
        if last > len(lines):
            problems.append(f'{prefix}:{first}-{last} is past the end of {PREFIX[prefix]}')
        elif not re.search(pattern, '\n'.join(lines[first - 1:last]), re.S):
            problems.append(f'{prefix}:{first}-{last} ({what}) does not show {pattern!r}: {lines[first - 1][:100]!r}')
    return problems


# ---- What the pinned drivers read: the "Linux reads it" column of the register table ----------------------------------------------------------------
# For each row of the table the ledger entries that show a pinned driver reading the word. A row with none is in a late block (F_FRESH): it is read after snapshot 2 only.
# The engine words are common to every GENI engine: the UART driver reads most, the SPI driver and the helpers of geni-se.h the rest.
ENGINE_READS = {
    'FW': [('gse', 375, 379), ('gser', 1343, 1350), ('spi', 645, 645)], 'IFD': [('spi', 684, 684)], 'ST': [('gser', 314, 319), ('spi', 1102, 1102)],
    'DMA': [('gser', 1237, 1241)], 'TXF': [('gser', 792, 792)], 'RXF': [('gser', 401, 407), ('spi', 788, 788)],
    'MIS': [('gser', 401, 407), ('spi', 290, 291)], 'MIE': [('gser', 720, 720), ('spi', 290, 291)], 'SIS': [('gser', 401, 407)], 'SIE': [('gser', 952, 952)],
    'IOS': [('gser', 243, 245)], 'IOM': [('gser', 1363, 1363)], 'TCF': [('gser', 1507, 1510)], 'RCF': [('gser', 1507, 1510)], 'TPA': [('gser', 1507, 1510)],
    'RPA': [('gser', 1507, 1510)], 'HW0': [('gse', 495, 495), ('spi', 663, 663)], 'HW1': [('gse', 541, 541)],
}
CLOCK_READS = [('cbc', 52, 52), ('cbc', 175, 178)]
VOTE_READS = [('clkr', 22, 37)]
GIC_READS = {'CTL': [('gic3', 162, 162)], 'TYP': [('gic3', 2003, 2003)], 'E': [('gic3', 571, 579)], 'P': [('gic3', 571, 579)], 'C': [('gicc', 62, 62)]}
PIN_READS = {'F': [('msm', 211, 211)], 'L': [('msm', 960, 960)], 'N': [('msm', 853, 853)], 'S': [('msm', 1348, 1348)]}
# What the late blocks hold, by the name the pinned files give the register and the entries that show the driver writing it (none for the two words nothing touches).
NEVER_READ = {
    'CM': ('GENI_SER_M_CLK_CFG', [('gser', 1477, 1480)]), 'CS': ('GENI_SER_S_CLK_CFG', [('gser', 1477, 1480)]), 'CK': ('SE_GENI_CLK_SEL', [('gser', 1477, 1480)]),
    'CC': ('GENI_CLK_CTRL_RO', []), 'DIF': ('DMA_IF_EN_RO', []), 'TWL': ('SE_UART_TX_WORD_LEN', [('gser', 1580, 1582)]),
    'TSB': ('SE_UART_TX_STOP_BIT_LEN', [('gser', 1580, 1582)]), 'RWL': ('SE_UART_RX_WORD_LEN', [('gser', 1580, 1582)]),
    'STL': ('SE_UART_RX_STALE_CNT', [('gser', 1361, 1361)]), 'MRF': ('SE_UART_MANUAL_RFR', [('gser', 267, 267)]),
    'TWM': ('SE_GENI_TX_WATERMARK_REG', [('gser', 605, 605)]), 'RWM': ('SE_GENI_RX_WATERMARK_REG', [('gsec', 372, 373)]),
    'RFW': ('SE_GENI_RX_RFR_WATERMARK_REG', [('gsec', 372, 373)]), 'G': ('GICD_IGROUPR', [('gic3', 940, 940)]), 'R': ('GICD_IROUTER', [('gic3', 976, 977)]),
}
DRIVER_FILES = ('qcom_geni_serial.c', 'spi-geni-qcom.c', 'qcom-geni-se.c', 'geni-se.h', 'irq-gic-v3.c', 'irq-gic-common.c')


def reads_for(block, key):
    """[(prefix, first, last)] of the ledger entries that show a pinned driver reading the word of row `key` of `block`, or [] for a word no pinned driver reads."""
    if block == 'B_GCC':
        return VOTE_READS if key.startswith('VT') else CLOCK_READS
    if block == 'B_GIC':
        return GIC_READS.get(key) or GIC_READS.get(key[0], [])
    if block in ('B_U2', 'B_S10'):
        return ENGINE_READS.get(key, [])
    if block == 'B_TLMM':
        return PIN_READS.get(key[0], [])
    return []


def never_read(block, key):
    """(register name, [write entries]) of a late-block row, or None."""
    if block == 'B_XGIC':
        return NEVER_READ.get(key[0])
    return NEVER_READ.get(key) if block in ('B_XU2', 'B_XS10') else None


def read_sites(files, name):
    """[(file, line)]: every statement of the driver files that reads the register `name`: a read call (readb, readw, readl, readq, each with _relaxed), the read-modify-write
    macros of qcom-geni-se.c, or a read helper that takes it as an argument."""
    found = []
    for file in DRIVER_FILES:
        text = '\n'.join(files[file])
        for m in re.finditer(r'\b(?:read[bwlq](?:_relaxed)?|geni_setbits32|geni_clrbits32|gic_peek_irq|msm_readl_\w+)\s*\([^;]*?\b' + re.escape(name) + r'\b', text):
            found.append((file, text.count('\n', 0, m.start()) + 1))
    return found


# ---- By name ---------------------------------------------------------------------------------------------------------------------------------------
def struct_field(lines, struct, field):
    """The value of `.field = value,` in `static struct <type> <struct> = {` of a Linux clock file (as text), or None. A field inside the nested `.clkr = {` counts."""
    for index, line in enumerate(lines):
        if re.match(rf'static struct \w+ {struct} = \{{', line):
            for body in lines[index + 1:index + 40]:
                found = re.match(rf'\s*\.{field} = (\S+?),$', body)
                if found:
                    return found.group(1)
                if body.startswith('}'):
                    break
    return None


def define(lines, name):
    """The text after `#define name` (a continuation joined, comments dropped), or None."""
    for index, line in enumerate(lines):
        found = re.match(rf'\s*#define {re.escape(name)}(?=[\s(]|$)(.*)$', line)
        if found:
            text = found.group(1)
            while text.rstrip().endswith('\\'):
                index += 1
                text = text.rstrip()[:-1] + ' ' + lines[index].strip()
            return re.sub(r'/\*.*?\*/', '', text).strip()
    return None


def evaluate(lines, expression):
    """An integer macro expression of the pinned files: hex numbers, BIT(n), GENMASK(h, l), 1U << n, |, +, <<, >>, * and the names of other #defines."""
    expression = re.sub(r'BIT\((\d+)\)', r'(1<<\1)', expression)
    expression = re.sub(r'GENMASK\((\d+),\s*(\d+)\)', lambda m: f'(((1<<({int(m.group(1)) - int(m.group(2)) + 1}))-1)<<{m.group(2)})', expression)
    expression = re.sub(r'\b(\d+|0x[0-9a-fA-F]+)[Uu]\b', r'\1', expression)
    for name in set(re.findall(r'\b[A-Za-z_]\w*\b', expression)):
        if re.fullmatch(r'0x[0-9a-fA-F]+|\d+', name):
            continue
        body = define(lines, name)
        if body is None:
            raise ValueError(f'{name} is not a #define of the file')
        expression = re.sub(rf'\b{name}\b', f'({evaluate(lines, body)})', expression)
    if not re.fullmatch(r'[0-9a-fA-Fx()<>|+*&\s-]+', expression):
        raise ValueError(f'not an integer expression: {expression!r}')
    return eval(expression, {'__builtins__': {}}, {})  # noqa: S307 (the text is one of the pinned files', checked above)


def dt_reg(lines, header):
    """(address, size) of the first `reg = <0 A 0 S>` after the line that contains `header` (two address and two size cells)."""
    start = next(i for i, line in enumerate(lines) if header in line)
    for line in lines[start:start + 12]:
        found = re.search(r'reg = <0 (0x[0-9a-f]+) 0 (0x[0-9a-f]+)>', line)
        if found:
            return int(found.group(1), 16), int(found.group(2), 16)
    raise ValueError(f'no reg after {header}')


# ---- The table of payloads/inputsnap-regs.h --------------------------------------------------------------------------------------------------------
ROW = re.compile(r'^\s+X\((\w+), "(\w+)", (0x[0-9a-f]+), (WIN_\w+), (\w+), ([^,]+), ([^,]+), (D_\w+), (\d+), (\d+), (B_\w+)\)(?: \\)?$', re.M)


def parse_rows(text):
    """[dict] of the register table of inputsnap-regs.h, in table order: id, key, offset (int), window, group, gate, flags (a set of names), decode, shift, width, block."""
    rows = []
    for m in ROW.finditer(text):
        rows.append({'id': m.group(1), 'key': m.group(2), 'off': int(m.group(3), 16), 'win': m.group(4), 'grp': m.group(5), 'gate': m.group(6).strip(),
                     'flags': {f.strip() for f in m.group(7).split('|') if f.strip() != '0'}, 'dec': m.group(8), 'shift': int(m.group(9)), 'width': int(m.group(10)),
                     'block': m.group(11)})
    return rows
