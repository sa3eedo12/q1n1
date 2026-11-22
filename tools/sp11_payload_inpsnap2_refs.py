# SPDX-License-Identifier: MIT
"""The pinned reference copies behind docs/SP11-PAYLOAD-INPSNAP2.md and the table of payloads/inpsnap2-regs.h, and how to read them from a test.

Every Linux file this payload leans on is read at one revision (7475ea8b58616b33c04afb976cf0fbaad9dd63fb, from https://raw.githubusercontent.com/torvalds/linux/<revision>/<path>); the
digests below were checked against a fresh fetch of each file from that URL. Seven of the nine are files the Snapintosh fork's other payload tests pin too (hamoa.dtsi,
gcc-x1e80100.c, clk-branch.c, clk-branch.h, common.c, clk-rcg2.c, clk-alpha-pll.c); the two geni files are the ones tools/test-q1n1-sp11-payload-inputsnap-refs.py reads. This module finds
the copies (INPSNAP2_REFS_DIR, GPUSNAP_REFS_DIR, INPUTSNAP_REFS_DIR, then SNAPINTOSH_DIR/build/sp11-stick-log/refs, then this tree's build/sp11-inpsnap2/refs; each may hold several
directories separated by os.pathsep), checks every digest, and offers:

  LEDGER      every file:line range the documents may cite, with the text that range must hold in the pinned copy. The document test holds each citation of the documents to this
              list; tools/test-q1n1-sp11-payload-inpsnap2-refs.py holds each entry of it to the files.
  PINNED, UNVERIFIED, load()  the digests, the list of what no pinned file says, and the pinned text of a file.

VERIFIED in this module means: a pinned file says so. It never means that the unit does. Nothing here reads hardware."""
import hashlib
import os
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
LINUX_REVISION = '7475ea8b58616b33c04afb976cf0fbaad9dd63fb'

PINNED = {
    'hamoa.dtsi': 'd5bb1f7ce37c721d75fb5b4cffc8f58bed4d3ef9786a231a0deca05e917529e0',
    'gcc-x1e80100.c': 'f1c3779c7bc273dfe170ea2ff4d40f975083ee149e3b02a4f42d5939596eb775',
    'clk-branch.c': 'd29259eb77a5d1d6a07adf4aa835588f8e04d1fa3c14be2b7d4162cce737abfa',
    'clk-branch.h': 'bac7dcf51a0da5b27eaa0d4dc276f540fec80013bd4862cfbbc115a50161ef72',
    'common.c': 'ebefa181817ee8218b314218bbd94315ba239ff4f816a6565af3ec6aeed14226',
    'clk-rcg2.c': 'b173e0f4d0b962f777c668422f5b1ca22137334b62de766f01f3ef5faf5d93b6',
    'clk-alpha-pll.c': '9a93019436b59ce3020940e0b91615bcaddc233da37951dcf492b2f09a9de433',
    'qcom-geni-se.c': 'f8f7fc2a68e1ac8c927ac7d37c9d901c9aef75ef78f4ccc668ebe0a0ba71825e',
    'geni-se.h': '6aab274a8a269605887d426b71022ad018d5b9439f4e5fdfc980041a457c322d',
}
LINUX_PATH = {
    'hamoa.dtsi': 'arch/arm64/boot/dts/qcom/hamoa.dtsi', 'gcc-x1e80100.c': 'drivers/clk/qcom/gcc-x1e80100.c', 'clk-branch.c': 'drivers/clk/qcom/clk-branch.c',
    'clk-branch.h': 'drivers/clk/qcom/clk-branch.h', 'common.c': 'drivers/clk/qcom/common.c', 'clk-rcg2.c': 'drivers/clk/qcom/clk-rcg2.c',
    'clk-alpha-pll.c': 'drivers/clk/qcom/clk-alpha-pll.c', 'qcom-geni-se.c': 'drivers/soc/qcom/qcom-geni-se.c', 'geni-se.h': 'include/linux/soc/qcom/geni-se.h',
}
# The prefixes of the documents' citations (`gcc:4434-4450`), and the file each names.
PREFIX = {'dt': 'hamoa.dtsi', 'gcc': 'gcc-x1e80100.c', 'cbc': 'clk-branch.c', 'cbh': 'clk-branch.h', 'cmn': 'common.c', 'rcg': 'clk-rcg2.c', 'pll': 'clk-alpha-pll.c',
          'gse': 'qcom-geni-se.c', 'gsh': 'geni-se.h'}
CITATION = re.compile(r'\b(' + '|'.join(sorted(PREFIX, key=len, reverse=True)) + r'):(\d+)(?:-(\d+))?\b')

# (file, first line, last line, text that range must hold). Every citation of the documents lies inside one of these ranges.
LEDGER = [
    ('hamoa.dtsi', 758, 760, r'gcc: clock-controller@100000.*reg = <0 0x00100000 0 0x200000>'),
    ('hamoa.dtsi', 2141, 2148, r'qupv3_0: geniqup@bc0000.*reg = <0 0x00bc0000 0 0x2000>.*GCC_QUPV3_WRAP_0_M_AHB_CLK.*GCC_QUPV3_WRAP_0_S_AHB_CLK.*"m-ahb".*"s-ahb"'),
    ('hamoa.dtsi', 2337, 2343, r'uart2: serial@b88000.*reg = <0 0x00b88000 0 0x4000>.*GIC_SPI 584.*GCC_QUPV3_WRAP0_S2_CLK'),
    ('gcc-x1e80100.c', 113, 127, r'gcc_gpll0 = \{.*\.offset = 0x0.*CLK_ALPHA_PLL_TYPE_LUCID_OLE.*\.enable_reg = 0x52030.*BIT\(0\).*clk_alpha_pll_fixed_lucid_ole_ops'),
    ('gcc-x1e80100.c', 130, 150, r'post_div_table_gcc_gpll0_out_even.*\{ 0x1, 2 \}.*gcc_gpll0_out_even = \{.*\.post_div_shift = 10'),
    ('gcc-x1e80100.c', 1142, 1153, r'ftbl_gcc_qupv3_wrap0_s2_clk_src.*F\(64000000, P_GCC_GPLL0_OUT_EVEN, 1, 16, 75\).*F\(200000000, P_GCC_GPLL0_OUT_MAIN, 3, 0, 0\)'),
    ('gcc-x1e80100.c', 1165, 1172, r'gcc_qupv3_wrap0_s2_clk_src = \{.*\.cmd_rcgr = 0x42288.*\.mnd_width = 16.*\.hid_width = 5'),
    ('gcc-x1e80100.c', 2237, 2250, r'gcc_qupv3_wrap0_s2_div_clk_src = \{.*\.reg = 0x42284.*\.shift = 0.*\.width = 4.*clk_regmap_div_ro_ops'),
    ('gcc-x1e80100.c', 4336, 4358, r'gcc_qupv3_wrap0_core_2x_clk = \{.*\.halt_reg = 0x23018.*\.enable_reg = 0x52020.*BIT\(9\).*gcc_qupv3_wrap0_core_clk = \{.*\.halt_reg = 0x23008.*\.enable_reg = 0x52020.*BIT\(8\)'),
    ('gcc-x1e80100.c', 4434, 4450, r'gcc_qupv3_wrap0_s2_clk = \{.*\.halt_reg = 0x42274.*BRANCH_HALT_VOTED.*\.enable_reg = 0x52020.*BIT\(12\)'),
    ('gcc-x1e80100.c', 4954, 4982, r'gcc_qupv3_wrap_0_m_ahb_clk = \{.*\.halt_reg = 0x23000.*\.hwcg_reg = 0x23000.*\.hwcg_bit = 1.*BIT\(6\).*gcc_qupv3_wrap_0_s_ahb_clk = \{.*\.halt_reg = 0x23004.*\.hwcg_reg = 0x23004.*\.hwcg_bit = 1.*BIT\(7\)'),
    ('gcc-x1e80100.c', 7409, 7412, r'gcc_dfs_clocks\[\] = \{.*DEFINE_RCG_DFS\(gcc_qupv3_wrap0_s0_clk_src\).*DEFINE_RCG_DFS\(gcc_qupv3_wrap0_s2_clk_src\)'),
    ('gcc-x1e80100.c', 7468, 7469, r'\.dfs_rcgs = gcc_dfs_clocks.*\.num_dfs_rcgs = ARRAY_SIZE\(gcc_dfs_clocks\)'),
    ('common.c', 394, 400, r'desc->driver_data->dfs_rcgs.*qcom_cc_register_rcg_dfs'),
    ('clk-branch.c', 17, 27, r'clk_branch_in_hwcg_mode.*if \(!br->hwcg_reg\).*regmap_read\(br->clkr\.regmap, br->hwcg_reg, &val\).*BIT\(br->hwcg_bit\)'),
    ('clk-branch.c', 43, 60, r'clk_branch2_check_halt.*CBCR_NOC_FSM_STATUS.*CBCR_CLK_OFF.*regmap_read\(br->clkr\.regmap, br->halt_reg, &val\).*FIELD_GET\(CBCR_NOC_FSM_STATUS, val\) == FSM_STATUS_ON'),
    ('clk-branch.c', 62, 74, r'clk_branch_wait.*voted = br->halt_check & BRANCH_VOTED.*clk_branch_in_hwcg_mode\(br\)\) return 0'),
    ('clk-branch.h', 63, 65, r'CBCR_CLK_OFF\s+BIT\(31\).*CBCR_NOC_FSM_STATUS\s+GENMASK\(30, 28\).*FSM_STATUS_ON\s+BIT\(1\)'),
    ('clk-rcg2.c', 26, 47, r'CMD_REG\s+0x0.*CMD_ROOT_OFF\s+BIT\(31\).*CFG_REG\s+0x4.*CFG_SRC_SEL_MASK.*CFG_MODE_MASK.*M_REG\s+0x8.*N_REG\s+0xc.*D_REG\s+0x10'),
    ('clk-rcg2.c', 54, 60, r'Dynamic Frequency Scaling.*MAX_PERF_LEVEL\s+8.*SE_CMD_DFSR_OFFSET\s+0x14.*SE_CMD_DFS_EN\s+BIT\(0\).*SE_PERF_DFSR\(level\).*0x1c \+ 0x4.*SE_PERF_M_DFSR\(level\).*0x5c \+ 0x4.*SE_PERF_N_DFSR\(level\).*0x9c \+ 0x4'),
    ('clk-rcg2.c', 67, 77, r'clk_rcg2_is_enabled.*regmap_read\(rcg->clkr\.regmap, rcg->cmd_rcgr \+ CMD_REG, &cmd\).*\(cmd & CMD_ROOT_OFF\) == 0'),
    ('clk-rcg2.c', 193, 227, r'__clk_rcg2_recalc_rate.*RCG_M_OFFSET\(rcg\).*RCG_N_OFFSET\(rcg\).*n = ~n.*clk_rcg2_recalc_rate.*RCG_CFG_OFFSET\(rcg\)'),
    ('clk-rcg2.c', 1606, 1650, r'clk_rcg2_dfs_populate_freq.*rcg->cmd_rcgr \+ SE_PERF_DFSR\(l\).*SE_PERF_M_DFSR\(l\).*SE_PERF_N_DFSR\(l\).*val = ~val'),
    ('clk-rcg2.c', 1688, 1731, r'clk_rcg2_dfs_recalc_rate.*rcg->cmd_rcgr \+ SE_CMD_DFSR_OFFSET.*level &= GENMASK\(4, 1\).*level >>= 1.*SE_PERF_DFSR\(level\).*SE_PERF_M_DFSR\(level\).*SE_PERF_N_DFSR\(level\)'),
    ('clk-rcg2.c', 1743, 1766, r'clk_rcg2_enable_dfs.*regmap_read\(regmap, rcg->cmd_rcgr \+ SE_CMD_DFSR_OFFSET, &val\).*if \(!\(val & SE_CMD_DFS_EN\)\).*return 0.*clk_rcg2_dfs_ops'),
    ('clk-rcg2.c', 1770, 1781, r'qcom_cc_register_rcg_dfs.*clk_rcg2_enable_dfs\(&rcgs\[i\], regmap\)'),
    ('clk-alpha-pll.c', 16, 34, r'PLL_MODE\(p\).*PLL_OUTCTRL\s+BIT\(0\).*PLL_RESET_N\s+BIT\(2\).*PLL_VOTE_FSM_ENA\s+BIT\(20\).*PLL_ACTIVE_FLAG\s+BIT\(30\).*PLL_LOCK_DET\s+BIT\(31\)'),
    ('clk-alpha-pll.c', 36, 45, r'PLL_L_VAL\(p\).*PLL_ALPHA_VAL\(p\).*PLL_USER_CTL\(p\).*PLL_POST_DIV_SHIFT\s+8.*PLL_ALPHA_EN\s+BIT\(24\)'),
    ('clk-alpha-pll.c', 62, 63, r'PLL_STATUS\(p\).*PLL_OFF_STATUS.*PLL_OPMODE\(p\).*PLL_OFF_OPMODE'),
    ('clk-alpha-pll.c', 187, 202, r'CLK_ALPHA_PLL_TYPE_LUCID_OLE.*PLL_OFF_OPMODE\] = 0x04.*PLL_OFF_STATE\] = 0x08.*PLL_OFF_STATUS\] = 0x0c.*PLL_OFF_L_VAL\] = 0x10.*PLL_OFF_ALPHA_VAL\] = 0x14.*PLL_OFF_USER_CTL\] = 0x18'),
    ('clk-alpha-pll.c', 348, 349, r'PLL_STANDBY\s+0x0.*PLL_RUN\s+0x1'),
    ('clk-alpha-pll.c', 396, 412, r'wait_for_pll.*regmap_read\(pll->clkr\.regmap, PLL_MODE\(pll\), &val\)'),
    ('clk-alpha-pll.c', 428, 429, r'wait_for_pll_enable_lock.*PLL_LOCK_DET'),
    ('clk-alpha-pll.c', 719, 750, r'clk_alpha_pll_recalc_rate.*PLL_L_VAL\(pll\).*PLL_USER_CTL\(pll\).*ctl & PLL_ALPHA_EN.*PLL_ALPHA_VAL\(pll\).*alpha_pll_calc_rate\(prate, l, a, alpha_width\)'),
    ('clk-alpha-pll.c', 1078, 1089, r'trion_pll_is_enabled.*PLL_MODE\(pll\), &mode_val.*PLL_OPMODE\(pll\), &opmode_val.*\(opmode_val & PLL_RUN\) && \(mode_val & PLL_OUTCTRL\)'),
    ('qcom-geni-se.c', 188, 188, r'QUPV3_HW_VER_REG\s+0x4'),
    ('qcom-geni-se.c', 299, 310, r'geni_se_get_qup_hw_version.*readl_relaxed\(wrapper->base \+ QUPV3_HW_VER_REG\)'),
    ('geni-se.h', 336, 344, r'HW_VER_MAJOR_MASK\s+GENMASK\(31, 28\).*HW_VER_MINOR_MASK\s+GENMASK\(27, 16\).*HW_VER_STEP_MASK\s+GENMASK\(15, 0\).*GENI_SE_VERSION_MAJOR.*GENI_SE_VERSION_MINOR'),
]

# What no pinned file says. The documents' section "What could not be verified" lists these ids and no others.
UNVERIFIED = {
    'UV1': 'whether any word of QUP wrapper 0 (0x00bc0000, the version word at +4) can be read at EL2 on this unit: no word of any QUP wrapper has ever been read there (boot 29 found the '
           'engine clocks off and read none), so whether a read answers, aborts (the guard turns that into FAULT:6), hangs the bus or raises an SError (neither is caught) is UNKNOWN',
    'UV2': 'whether the first reads of the clock controller words this payload adds (the divider, the root clock generator\'s words and its DFS flag, the eight levels and GPLL0\'s own six words) '
           'answer: the window is the one boots 29 to 31 read other words of, which is the precedent and not the proof',
    'UV3': 'that a running wrapper 0 AHB and core clock (the three words of the wrapper gate) is enough for the wrapper\'s registers to answer: Linux turns the same clocks on before it touches '
           'the wrapper (hamoa.dtsi:2145-2148), which is INFERRED to be the condition, never observed on this unit',
    'UV4': 'that none of the words read has a side effect on the unit: no pinned file reads any of them as a FIFO, a clear-on-read or a read-to-acknowledge word (Linux reads every one as a '
           'plain status or configuration word), which is INFERRED for this unit, never observed',
    'UV5': 'what the unit\'s words hold: the DFS flag, the eight levels, the divider, the root clock generator\'s words, GPLL0, the votes and the wrapper version are all unread on this unit '
           'and nothing in this tree says what they are; the page shows them, the plan\'s decisions are made from the film later',
    'UV6': 'that the wrapper version word is at +4 on this unit\'s wrapper: Linux says so for the QUP wrapper in general (qcom-geni-se.c:188), INFERRED for the X1E80100\'s wrapper 0',
}


def refs_dirs():
    """The directories that may hold the pinned copies, in the order they are looked in."""
    dirs = []
    for name in ('INPSNAP2_REFS_DIR', 'GPUSNAP_REFS_DIR', 'INPUTSNAP_REFS_DIR'):
        dirs += [Path(p) for p in os.environ.get(name, '').split(os.pathsep) if p]
    if os.environ.get('SNAPINTOSH_DIR'):
        dirs.append(Path(os.environ['SNAPINTOSH_DIR']) / 'build' / 'sp11-stick-log' / 'refs')
    dirs.append(ROOT / 'build' / 'sp11-inpsnap2' / 'refs')
    return [d for d in dirs if d.is_dir()]


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def find(name):
    """The path of the pinned copy of `name` (the first copy in the search path whose digest is the pinned one), or None."""
    for directory in refs_dirs():
        path = directory / name
        if path.is_file() and digest(path) == PINNED[name]:
            return path
    return None


def load(name):
    """The lines of the pinned copy of `name` (tabs kept); None without a copy."""
    path = find(name)
    return None if path is None else path.read_text(encoding='utf-8').splitlines()


def covered(prefix, first, last):
    """Whether the citation `prefix:first-last` lies inside a ledger range of that prefix's file."""
    name = PREFIX[prefix]
    return any(f == name and a <= first and last <= b for f, a, b, _ in LEDGER)


def cited(text):
    """[(prefix, first, last)] of every citation in `text`."""
    return [(m.group(1), int(m.group(2)), int(m.group(3) or m.group(2))) for m in CITATION.finditer(text)]
