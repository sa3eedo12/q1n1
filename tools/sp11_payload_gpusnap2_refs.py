# SPDX-License-Identifier: MIT
"""The pinned reference copies behind docs/SP11-PAYLOAD-GPUSNAP2.md and the tables of payloads/gpusnap2-regs.h, and how to read them from a test.

Every Linux file this payload leans on is read at one revision (7475ea8b58616b33c04afb976cf0fbaad9dd63fb, from https://raw.githubusercontent.com/torvalds/linux/<revision>/<path>).
Nine of them are the ones the Snapintosh fork keeps in build/sp11-stick-log/refs/ and the tsnap and gpusnap tests read (git-ignored; docs/SP11-STICK-LOG.md section 10 pins the
SHA-256 of each); the tsens files are the tsnap test's; the rpmh, cmd-db, QFPROM and alpha-PLL files were fetched for this payload and their digests are recorded here and in
docs/SP11-PAYLOAD-GPUSNAP2-EVIDENCE.md. This module finds the copies (GPUSNAP2_REFS_DIR, GPUSNAP_REFS_DIR, TSNAP_REFS_DIR, then SNAPINTOSH_DIR/build/sp11-stick-log/refs, then this
tree's build/sp11-gpusnap2/refs; each may hold several directories separated by os.pathsep), checks every digest, and offers:

  LEDGER      every file:line range the document may cite, with the text that range must hold in the pinned copy. The document test holds each citation of the document to
              this list; tools/test-q1n1-sp11-payload-gpusnap2-refs.py holds each entry of it to the files.
  PINNED, UNVERIFIED, load()  the digests, the list of what no pinned file says, and the pinned text of a file.

VERIFIED in this module means: a pinned file says so. It never means that the unit does. Nothing here reads hardware."""
import hashlib
import os
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
LINUX_REVISION = '7475ea8b58616b33c04afb976cf0fbaad9dd63fb'

# file name -> (SHA-256 of the fetched bytes, where it is pinned). STICK = docs/SP11-STICK-LOG.md section 10, GPUSNAP = docs/SP11-PAYLOAD-GPUSNAP-EVIDENCE.md, TSNAP =
# docs/SP11-PAYLOAD-TSNAP.md section 8, THIS = recorded here and in docs/SP11-PAYLOAD-GPUSNAP2-EVIDENCE.md only.
PINNED = {
    'hamoa.dtsi': ('d5bb1f7ce37c721d75fb5b4cffc8f58bed4d3ef9786a231a0deca05e917529e0', 'STICK'),
    'gcc-x1e80100.c': ('f1c3779c7bc273dfe170ea2ff4d40f975083ee149e3b02a4f42d5939596eb775', 'STICK'),
    'clk-branch.h': ('bac7dcf51a0da5b27eaa0d4dc276f540fec80013bd4862cfbbc115a50161ef72', 'STICK'),
    'gdsc.c': ('a5a73fcc890f658b48a1e2dc015f3d47316d77b8c7853bbf999828f25a8c86b1', 'STICK'),
    'clk-branch.c': ('d29259eb77a5d1d6a07adf4aa835588f8e04d1fa3c14be2b7d4162cce737abfa', 'STICK'),
    'common.c': ('ebefa181817ee8218b314218bbd94315ba239ff4f816a6565af3ec6aeed14226', 'STICK'),
    'gpucc-x1e80100.c': ('c2914ffd395e82984c5c46e9d44239cc148c7fa7b6f72c2637ba58322fc6131b', 'GPUSNAP'),
    'a7xx_catalog.c': ('6941242f183b76143464237896f8b0b97f9a6533cb1efb6f834f2da4dcb6c799', 'GPUSNAP'),
    'a6xx_gmu.c': ('22bc34dafafff83827901221873c6aa770e20f9c17c60294593245324eee8272', 'GPUSNAP'),
    'clk-rcg2.c': ('b173e0f4d0b962f777c668422f5b1ca22137334b62de766f01f3ef5faf5d93b6', 'GPUSNAP'),
    'tsens-v2.c': ('0f0d41735b468d247f9d648980b31b30d91df4976d9f74c48767014c0ec74a12', 'TSNAP'),
    'rpmh-rsc.c': ('1efe0d45d2c8ab11a494bad594e3204582670f30087ee3d925b3f5c31a3982d6', 'THIS'),
    'rpmh-internal.h': ('39ad1ed46118821882e72f777378d5974bfaad984d19060ac22f892866b21674', 'THIS'),
    'cmd-db.c': ('8393e57616c2aa58f5779afab86b31cb252f4300351722a5eef5e639541267cf', 'THIS'),
    'cmd-db.h': ('5fbe09d09bd9e892079340672a61148b46b1d5319ac1665bce4c3b85beefee56', 'THIS'),
    'qfprom.c': ('db979c91348c0572f6689238d1e5c1ccf2984e2a8ceb21715fddf8c750522dfa', 'THIS'),
    'clk-alpha-pll.c': ('9a93019436b59ce3020940e0b91615bcaddc233da37951dcf492b2f09a9de433', 'THIS'),
    'qcom,rpmh-rsc.h': ('d57710164c227cf9d080d2885c44fe75a51cdc1b81ffd6aa27fc6ae0b70c1b73', 'THIS'),
}
# Linux path of every file (what a reader fetches the unpinned ones from).
LINUX_PATH = {
    'hamoa.dtsi': 'arch/arm64/boot/dts/qcom/hamoa.dtsi', 'gcc-x1e80100.c': 'drivers/clk/qcom/gcc-x1e80100.c', 'gpucc-x1e80100.c': 'drivers/clk/qcom/gpucc-x1e80100.c',
    'clk-branch.h': 'drivers/clk/qcom/clk-branch.h', 'clk-branch.c': 'drivers/clk/qcom/clk-branch.c', 'common.c': 'drivers/clk/qcom/common.c', 'gdsc.c': 'drivers/clk/qcom/gdsc.c',
    'clk-rcg2.c': 'drivers/clk/qcom/clk-rcg2.c', 'clk-alpha-pll.c': 'drivers/clk/qcom/clk-alpha-pll.c',
    'a7xx_catalog.c': 'drivers/gpu/drm/msm/adreno/a7xx_catalog.c', 'a6xx_gmu.c': 'drivers/gpu/drm/msm/adreno/a6xx_gmu.c', 'tsens-v2.c': 'drivers/thermal/qcom/tsens-v2.c',
    'rpmh-rsc.c': 'drivers/soc/qcom/rpmh-rsc.c', 'rpmh-internal.h': 'drivers/soc/qcom/rpmh-internal.h', 'cmd-db.c': 'drivers/soc/qcom/cmd-db.c',
    'cmd-db.h': 'include/soc/qcom/cmd-db.h', 'qfprom.c': 'drivers/nvmem/qfprom.c', 'qcom,rpmh-rsc.h': 'include/dt-bindings/soc/qcom,rpmh-rsc.h',
}
# The prefixes of the document's citations (`rsc:1094`), and the file each names.
PREFIX = {'dt': 'hamoa.dtsi', 'gcc': 'gcc-x1e80100.c', 'cc': 'gpucc-x1e80100.c', 'cb': 'clk-branch.h', 'cbc': 'clk-branch.c', 'cmn': 'common.c', 'gd': 'gdsc.c', 'rcg': 'clk-rcg2.c',
          'pll': 'clk-alpha-pll.c', 'cat': 'a7xx_catalog.c', 'gmu': 'a6xx_gmu.c', 'ts2': 'tsens-v2.c', 'rsc': 'rpmh-rsc.c', 'rin': 'rpmh-internal.h', 'cdb': 'cmd-db.c', 'cdh': 'cmd-db.h',
          'qf': 'qfprom.c', 'bnd': 'qcom,rpmh-rsc.h'}
CITATION = re.compile(r'\b(' + '|'.join(sorted(PREFIX, key=len, reverse=True)) + r'):(\d+)(?:-(\d+))?\b')

# (file, first line, last line, text that range must hold). Every citation of the document lies inside one of these ranges.
LEDGER = [
    ('hamoa.dtsi', 516, 520, r'aop_cmd_db_mem: aop-cmd-db@81c60000.*0x81c60000 0x0 0x20000'),
    ('hamoa.dtsi', 758, 762, r'gcc: clock-controller@100000.*0x00100000 0 0x200000'),
    ('hamoa.dtsi', 2804, 2814, r'tsens3: thermal-sensor@c274000.*0x0c274000.*0x0c225000.*qcom,sensors = <16>'),
    ('hamoa.dtsi', 4225, 4234, r'gpucc: clock-controller@3d90000.*0x03d90000 0 0xa000'),
    ('hamoa.dtsi', 8599, 8613, r'apps_rsc: rsc@17500000.*0x17520000.*"drv-2".*qcom,tcs-offset = <0xd00>.*qcom,drv-id = <2>.*ACTIVE_TCS    3.*SLEEP_TCS     2.*WAKE_TCS      2'),
    ('hamoa.dtsi', 8808, 8817, r'qfprom: efuse@221c8000.*0x221c8000.*gpu-speed-bin@119.*reg = <0x119 0x2>.*bits = <7 8>'),
    ('hamoa.dtsi', 9664, 9668, r'thermal_gpuss_0: gpuss-0-thermal.*tsens3 5'),
    ('hamoa.dtsi', 9664, 9856, r'thermal_gpuss_0: gpuss-0-thermal.*tsens3 5.*thermal_gpuss_7: gpuss-7-thermal.*tsens3 12'),
    ('hamoa.dtsi', 9853, 9856, r'thermal_gpuss_7: gpuss-7-thermal.*tsens3 12'),
    ('gcc-x1e80100.c', 7451, 7451, r'0x71004, /\* GCC_GPU_CFG_AHB_CLK \*/'),
    ('common.c', 310, 320, r'qcom_cc_clk_regs_configure.*qcom_branch_set_clk_en'),
    ('clk-branch.h', 63, 65, r'CBCR_CLK_OFF.*BIT\(31\).*CBCR_NOC_FSM_STATUS.*FSM_STATUS_ON'),
    ('clk-branch.c', 43, 58, r'clk_branch2_check_halt.*CBCR_NOC_FSM_STATUS.*FSM_STATUS_ON'),
    ('clk-rcg2.c', 33, 39, r'CMD_ROOT_OFF.*CFG_SRC_SEL_SHIFT\s+8'),
    ('gdsc.c', 21, 27, r'PWR_ON_MASK.*BIT\(31\).*HW_CONTROL_MASK.*BIT\(1\).*SW_COLLAPSE_MASK.*BIT\(0\)'),
    ('gpucc-x1e80100.c', 56, 60, r'gpu_cc_pll0.*\.offset = 0x0.*CLK_ALPHA_PLL_TYPE_ZONDA_OLE'),
    ('gpucc-x1e80100.c', 87, 91, r'gpu_cc_pll1.*\.offset = 0x1000.*CLK_ALPHA_PLL_TYPE_LUCID_OLE'),
    ('gpucc-x1e80100.c', 160, 160, r'\.cmd_rcgr = 0x9474'),
    ('gpucc-x1e80100.c', 227, 227, r'\.reg = 0x9054'),
    ('gpucc-x1e80100.c', 242, 242, r'\.reg = 0x9050'),
    ('gpucc-x1e80100.c', 256, 530, r'halt_reg = 0x911c.*halt_reg = 0x9120.*halt_reg = 0x914c.*halt_reg = 0x9008.*halt_reg = 0x9150.*halt_reg = 0x9134'),
    ('gpucc-x1e80100.c', 533, 534, r'\.gdscr = 0x9108.*\.gds_hw_ctrl = 0x953c'),
    ('gpucc-x1e80100.c', 604, 610, r'regmap_config.*\.max_register = 0x9988'),
    ('gpucc-x1e80100.c', 612, 614, r'gpu_cc_x1e80100_critical_cbcrs.*0x93a4, /\* GPU_CC_CB_CLK \*/'),
    ('gpucc-x1e80100.c', 638, 649, r'gpu_cc_x1e80100_probe.*clk_zonda_pll_configure\(&gpu_cc_pll0.*clk_lucid_evo_pll_configure\(&gpu_cc_pll1.*qcom_cc_really_probe'),
    ('clk-alpha-pll.c', 16, 34, r'PLL_MODE\(p\).*PLL_OUTCTRL.*BIT\(0\).*PLL_RESET_N.*PLL_ACTIVE_FLAG.*BIT\(30\).*PLL_LOCK_DET.*BIT\(31\)'),
    ('clk-alpha-pll.c', 187, 202, r'CLK_ALPHA_PLL_TYPE_LUCID_OLE.*PLL_OFF_OPMODE\] = 0x04.*PLL_OFF_L_VAL\] = 0x10.*PLL_OFF_ALPHA_VAL\] = 0x14'),
    ('clk-alpha-pll.c', 302, 316, r'CLK_ALPHA_PLL_TYPE_ZONDA_OLE.*PLL_OFF_L_VAL\] = 0x04.*PLL_OFF_ALPHA_VAL\] = 0x08.*PLL_OFF_OPMODE\] = 0x30.*PLL_OFF_STATUS\] = 0x3c'),
    ('clk-alpha-pll.c', 348, 349, r'PLL_STANDBY\s+0x0.*PLL_RUN\s+0x1'),
    ('clk-alpha-pll.c', 1078, 1090, r'trion_pll_is_enabled.*PLL_MODE.*PLL_OPMODE.*\(opmode_val & PLL_RUN\) && \(mode_val & PLL_OUTCTRL\)'),
    ('rpmh-rsc.c', 41, 46, r'RSC_DRV_ID\s+0.*MAJOR_VER_MASK\s+0xFF.*MAJOR_VER_SHIFT\s+16.*MINOR_VER_MASK\s+0xFF.*MINOR_VER_SHIFT\s+8'),
    ('rpmh-rsc.c', 72, 76, r'DRV_NUM_TCS_MASK\s+0x3F.*DRV_NUM_TCS_SHIFT\s+6.*DRV_NCPT_MASK\s+0x1F.*DRV_NCPT_SHIFT\s+27'),
    ('rpmh-rsc.c', 157, 194, r'rpmh_rsc_reg_offset_ver_2_7.*rpmh_rsc_reg_offset_ver_3_0'),
    ('rpmh-rsc.c', 157, 175, r'rpmh_rsc_reg_offset_ver_2_7.*= 672.*= 20.*DRV_SOLVER_CONFIG.*0x04.*DRV_PRNT_CHLD_CONFIG.*0x0C.*RSC_DRV_IRQ_ENABLE.*0x00.*RSC_DRV_IRQ_STATUS.*0x04.*RSC_DRV_CMD_ENABLE.*0x1C.*RSC_DRV_CMD_ADDR.*0x34.*RSC_DRV_CMD_DATA.*0x38'),
    ('rpmh-rsc.c', 176, 194, r'rpmh_rsc_reg_offset_ver_3_0.*= 672.*= 24.*RSC_DRV_CMD_ENABLE.*0x2C.*RSC_DRV_CMD_ADDR.*0x38.*RSC_DRV_CMD_DATA.*0x3C'),
    ('rpmh-rsc.c', 417, 428, r'enable_tcs_irq.*readl_relaxed\(drv->tcs_base \+ reg\).*writel_relaxed\(data, drv->tcs_base \+ reg\)'),
    ('rpmh-rsc.c', 440, 449, r'tcs_tx_done.*readl_relaxed\(drv->tcs_base \+ drv->regs\[RSC_DRV_IRQ_STATUS\]\)'),
    ('rpmh-rsc.c', 466, 470, r'RSC_DRV_CMD_ENABLE.*writel_relaxed\(BIT\(i\), drv->tcs_base \+ drv->regs\[RSC_DRV_IRQ_CLEAR\]\)'),
    ('rpmh-rsc.c', 457, 460, r'if \(req->is_read\).*reg = drv->regs\[RSC_DRV_CMD_RESP_DATA\].*read_tcs_reg\(drv, reg, i\)'),
    ('rpmh-rsc.c', 560, 568, r'read_tcs_reg\(drv, drv->regs\[RSC_DRV_CMD_ENABLE\], i\).*for_each_set_bit\(j, &curr_enabled, MAX_CMDS_PER_TCS\).*read_tcs_cmd\(drv, drv->regs\[RSC_DRV_CMD_ADDR\]'),
    ('rpmh-rsc.c', 996, 1010, r'config = readl_relaxed\(drv->base \+ drv->regs\[DRV_PRNT_CHLD_CONFIG\]\).*DRV_NUM_TCS_SHIFT \* drv->id.*DRV_NCPT_SHIFT'),
    ('rpmh-rsc.c', 1007, 1048, r'qcom,tcs-config.*tcs = &drv->tcs\[tcs_cfg\[i\]\.type\].*tcs->offset = st;.*st \+= tcs->num_tcs.*drv->num_tcs = st'),
    ('rpmh-rsc.c', 1122, 1122, r'solver_config = readl_relaxed\(drv->base \+ drv->regs\[DRV_SOLVER_CONFIG\]\)'),
    ('rpmh-rsc.c', 1088, 1097, r'rsc_id = readl_relaxed\(drv->base \+ RSC_DRV_ID\).*MAJOR_VER_SHIFT.*if \(drv->ver.major >= 3\).*rpmh_rsc_reg_offset_ver_3_0.*rpmh_rsc_reg_offset_ver_2_7'),
    ('rpmh-internal.h', 15, 15, r'MAX_CMDS_PER_TCS\s+16'),
    ('qcom,rpmh-rsc.h', 9, 12, r'SLEEP_TCS\s+0.*WAKE_TCS\s+1.*ACTIVE_TCS\s+2.*CONTROL_TCS\s+3'),
    ('cmd-db.c', 36, 80, r'struct entry_header.*u8 id\[8\].*priority.*addr.*len.*offset.*struct rsc_hdr.*slv_id.*header_offset.*data_offset.*cnt.*struct cmd_db_header.*version.*magic.*header\[MAX_SLV_ID\].*checksum'),
    ('cmd-db.c', 101, 108, r'CMD_DB_MAGIC\[\] = \{ 0xdb, 0x30, 0x03, 0x0c \}.*cmd_db_magic_matches'),
    ('cmd-db.c', 144, 176, r'cmd_db_get_header.*strtomem_pad\(query, id, 0\).*for \(i = 0; i < MAX_SLV_ID; i\+\+\).*if \(!rsc_hdr->slv_id\).*break.*memcmp\(ent->id, query, sizeof\(ent->id\)\)'),
    ('cmd-db.h', 12, 20, r'CMD_DB_HW_ARC\s+= CMD_DB_HW_MIN.*CMD_DB_HW_VRM\s+= 4.*CMD_DB_HW_BCM\s+= 5'),
    ('qfprom.c', 319, 335, r'qfprom_reg_read.*readl\(base \+ reg \+ i \* sizeof\(u32\)\)'),
    ('qfprom.c', 337, 347, r'cell->bit_offset \+= byte_offset \* BITS_PER_BYTE'),
    ('a7xx_catalog.c', 376, 376, r'ADRENO_CHIP_IDS\(0x43050c01\)'),
    ('a7xx_catalog.c', 398, 408, r'name = "SH0".*name = "MC0".*name = "ACV"'),
    ('a7xx_catalog.c', 411, 417, r'ADRENO_SPEEDBINS.*\{ 0,\s+0 \}.*\{ 59,\s+1 \}.*\{ 7,\s+2 \}.*\{ 232,\s+3 \}.*\{ 146,\s+4 \}'),
    ('a6xx_gmu.c', 1823, 1838, r'"mx\.lvl".*"gbx\.lvl".*"gfx\.lvl"'),
    ('a6xx_gmu.c', 1894, 1910, r'"gmxc\.lvl".*"gfx\.lvl".*"cx\.lvl", "mx\.lvl"'),
    ('tsens-v2.c', 126, 138, r'LAST_TEMP.*0,\s+11.*VALID.*21,\s+21.*MIN_STATUS.*16.*MAX_STATUS.*20'),
]

# What no pinned file says. The document's section 9 lists these ids and no others.
UNVERIFIED = {
    'UV1': 'whether the unit\'s EL2 stage-1 map reaches the command database (DRAM at 0x81c60000), the apps RSC drv-2 page (0x17520000) and the QFPROM (0x221c8000): none of the three has ever '
           'been read there, so whether a read faults (the guard turns that into FAULT:6), hangs the bus or raises an SError (neither is caught) is UNKNOWN',
    'UV2': 'whether the command database is intact after ExitBootServices (the UEFI map describes its region as reserved memory in the unit\'s own dumps, DERIVED, and the magic word is '
           'checked before anything is walked, but what the firmware keeps there at this point is not known)',
    'UV3': 'the version of the apps RSC on this SoC and what the firmware left in its wake TCSs: Linux picks the 3.0 layout for a major of 3 or more, this payload knows the majors 2 and 3 only, '
           'and an empty TCS (EN=0) is as likely as one with votes',
    'UV4': 'that reading the RSC words, the data words of the TCS commands (no Linux code reads them: the driver only writes them) and the QFPROM word has no side effect on the unit: '
           '"the interrupt status is cleared by a separate write to IRQ_CLEAR" (rpmh-rsc.c:446-470) is what Linux does, INFERRED to hold for the read',
    'UV5': 'the sensor-number field (bits 26:22) of a tsens3 status word: no pinned file defines it (tsens-v2.c:126-138 stops at bit 21); it is INFERRED from the words boot 29 showed',
    'UV6': 'whether the two GPUCC PLLs read their own state with the GPU\'s CX domain off: Linux writes their configuration at probe with nothing of the GPU powered (gpucc-x1e80100.c:638-649), '
           'and boot 30 read three other GPUCC words, but no PLL word has been read on the unit',
    'UV7': 'what each word means for the plan: a PLL that reads off, a rail whose level is not in the wake TCS, a speed bin: the page shows the words, the plan\'s decisions are made from them later',
}


def refs_dirs():
    """The directories that may hold the pinned copies, in the order they are looked in."""
    dirs = []
    for name in ('GPUSNAP2_REFS_DIR', 'GPUSNAP_REFS_DIR', 'TSNAP_REFS_DIR'):
        dirs += [Path(p) for p in os.environ.get(name, '').split(os.pathsep) if p]
    if os.environ.get('SNAPINTOSH_DIR'):
        dirs.append(Path(os.environ['SNAPINTOSH_DIR']) / 'build' / 'sp11-stick-log' / 'refs')
    dirs.append(ROOT / 'build' / 'sp11-gpusnap2' / 'refs')
    return [d for d in dirs if d.is_dir()]


def find(name):
    """The path of the pinned copy of `name`, or None."""
    for directory in refs_dirs():
        if (directory / name).is_file():
            return directory / name
    return None


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def load(name):
    """The lines of the pinned copy of `name` (tabs kept), after the digest was checked; None without a copy."""
    path = find(name)
    if path is None:
        return None
    if digest(path) != PINNED[name][0]:
        raise ValueError(f'{path} is not the pinned {name}: SHA-256 {digest(path)}')
    return path.read_text(encoding='utf-8').splitlines()


def covered(prefix, first, last):
    """Whether the citation `prefix:first-last` lies inside a ledger range of that prefix's file."""
    name = PREFIX[prefix]
    return any(f == name and a <= first and last <= b for f, a, b, _ in LEDGER)
