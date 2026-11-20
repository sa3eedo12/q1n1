# SPDX-License-Identifier: MIT
"""The pinned reference copies behind docs/SP11-PAYLOAD-GPUSNAP.md and the register table of payloads/gpusnap-regs.h, and how to read them from a test.

Six of the Linux files this payload leans on are the ones the Snapintosh fork keeps in build/sp11-stick-log/refs/ (git-ignored; docs/SP11-STICK-LOG.md
section 10 pins the revision and the SHA-256 of each). The others are fetched, read-only, at the same Linux revision (7475ea8b58616b33c04afb976cf0fbaad9dd63fb,
from https://raw.githubusercontent.com/torvalds/linux/<revision>/<path>) into build/sp11-gpusnap/refs/ of this tree, or into the directory GPUSNAP_REFS_DIR
names; their digests are the ones docs/SP11-GPU-PORT-PLAN.md Appendix B and docs/SP11-GPU-A7XX-STUDY.md Appendix B record (re-computed, and equal), except
common.c, which no table pins and whose digest is recorded here and in the payload's document. This module finds the copies (GPUSNAP_REFS_DIR, then
SNAPINTOSH_DIR/build/sp11-stick-log/refs, then this tree's build/sp11-gpusnap/refs), checks every digest, and offers:

  LEDGER      every file:line the document may cite, with what that line must show in the pinned copy. The document test holds each citation of the document
              to this list; tools/test-q1n1-sp11-payload-gpusnap-refs.py holds each entry of it to the files.
  extractors  the same registers read by NAME (the clock or GDSC struct of a Linux clock file, a register of an XML file, a #define of arm-smmu.h), so that a
              register table whose line numbers are right and whose offsets are not is still caught.
  parse_rows  the register table of payloads/gpusnap-regs.h.

VERIFIED in this module means: a pinned file says so. It never means that the unit does. Nothing here reads hardware."""
import hashlib
import os
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
LINUX_REVISION = '7475ea8b58616b33c04afb976cf0fbaad9dd63fb'

# file name -> SHA-256 of the fetched bytes. Where each is pinned: STICK = docs/SP11-STICK-LOG.md section 10, PLAN = docs/SP11-GPU-PORT-PLAN.md Appendix B,
# STUDY = docs/SP11-GPU-A7XX-STUDY.md Appendix B, NONE = in no table (recorded here, in the document and in the report only).
PINNED = {
    'hamoa.dtsi': ('d5bb1f7ce37c721d75fb5b4cffc8f58bed4d3ef9786a231a0deca05e917529e0', 'STICK'),
    'gcc-x1e80100.c': ('f1c3779c7bc273dfe170ea2ff4d40f975083ee149e3b02a4f42d5939596eb775', 'STICK'),
    'clk-branch.h': ('bac7dcf51a0da5b27eaa0d4dc276f540fec80013bd4862cfbbc115a50161ef72', 'STICK'),
    'gdsc.c': ('a5a73fcc890f658b48a1e2dc015f3d47316d77b8c7853bbf999828f25a8c86b1', 'STICK'),
    'arm-smmu.h': ('b7221ee9b767594ba79cfc139fca838236f81ba949fb5e0be81e31ef42b1911c', 'STICK'),
    'gpucc-x1e80100.c': ('c2914ffd395e82984c5c46e9d44239cc148c7fa7b6f72c2637ba58322fc6131b', 'PLAN'),
    'clk-rcg2.c': ('b173e0f4d0b962f777c668422f5b1ca22137334b62de766f01f3ef5faf5d93b6', 'PLAN'),
    'a6xx_gmu.c': ('22bc34dafafff83827901221873c6aa770e20f9c17c60294593245324eee8272', 'STUDY'),
    'a6xx_gmu.h': ('b9af7b6c0bdf0f4f3fabf70f59ba821bc783109b48cf7a8c04e6b7d07fef1b92', 'STUDY'),
    'a6xx_gmu.xml': ('f13f07aa3c975c1d671c1a7f5ba62ddaaf525aedb7a0e481186cbfffe461f88b', 'STUDY'),
    'a6xx_gpu.c': ('9b725c1c56a9b6b804de0daa899fa03f51ddb6c8253904c77814540d5142f4cd', 'STUDY'),
    'a6xx_gpu.h': ('3d11d36a6ec3f16876baaf6f8b76fcfcaa8e0b2991892e886fbe850682f87c70', 'STUDY'),
    'a6xx.xml': ('6e20d0347b06f26220f6b87d8600e94790331fec45363a167c5e63ea6ad8f9c2', 'STUDY'),
    'a7xx_catalog.c': ('6941242f183b76143464237896f8b0b97f9a6533cb1efb6f834f2da4dcb6c799', 'STUDY'),
    'adreno_gpu.h': ('c8fe321c6df3a4b2fc2f3f186cf6b3952fd0196f7e5c32b5d7b2740405dd3be6', 'STUDY'),
    'clk-branch.c': ('d29259eb77a5d1d6a07adf4aa835588f8e04d1fa3c14be2b7d4162cce737abfa', 'NONE'),
    'common.c': ('ebefa181817ee8218b314218bbd94315ba239ff4f816a6565af3ec6aeed14226', 'NONE'),
}
# Linux path of every file (what a reader fetches the unpinned ones from).
LINUX_PATH = {
    'hamoa.dtsi': 'arch/arm64/boot/dts/qcom/hamoa.dtsi', 'gcc-x1e80100.c': 'drivers/clk/qcom/gcc-x1e80100.c', 'clk-branch.h': 'drivers/clk/qcom/clk-branch.h',
    'gdsc.c': 'drivers/clk/qcom/gdsc.c', 'arm-smmu.h': 'drivers/iommu/arm/arm-smmu/arm-smmu.h', 'gpucc-x1e80100.c': 'drivers/clk/qcom/gpucc-x1e80100.c',
    'clk-rcg2.c': 'drivers/clk/qcom/clk-rcg2.c', 'clk-branch.c': 'drivers/clk/qcom/clk-branch.c', 'common.c': 'drivers/clk/qcom/common.c',
    'a6xx_gmu.c': 'drivers/gpu/drm/msm/adreno/a6xx_gmu.c', 'a6xx_gmu.h': 'drivers/gpu/drm/msm/adreno/a6xx_gmu.h',
    'a6xx_gmu.xml': 'drivers/gpu/drm/msm/registers/adreno/a6xx_gmu.xml', 'a6xx_gpu.c': 'drivers/gpu/drm/msm/adreno/a6xx_gpu.c',
    'a6xx_gpu.h': 'drivers/gpu/drm/msm/adreno/a6xx_gpu.h', 'a6xx.xml': 'drivers/gpu/drm/msm/registers/adreno/a6xx.xml',
    'a7xx_catalog.c': 'drivers/gpu/drm/msm/adreno/a7xx_catalog.c', 'adreno_gpu.h': 'drivers/gpu/drm/msm/adreno/adreno_gpu.h',
}
# The prefixes of the document's citations (`gcc:3095`), and the file each names.
PREFIX = {'gcc': 'gcc-x1e80100.c', 'gpucc': 'gpucc-x1e80100.c', 'gdsc': 'gdsc.c', 'cb': 'clk-branch.h', 'cbc': 'clk-branch.c', 'rcg': 'clk-rcg2.c', 'cmn': 'common.c',
          'dt': 'hamoa.dtsi', 'smmu': 'arm-smmu.h', 'xml': 'a6xx_gmu.xml', 'gmu': 'a6xx_gmu.c', 'gmuh': 'a6xx_gmu.h', 'gpuc': 'a6xx_gpu.c', 'gpuh': 'a6xx_gpu.h',
          'a6x': 'a6xx.xml', 'cat': 'a7xx_catalog.c', 'agh': 'adreno_gpu.h'}
CITATION = re.compile(r'\b(' + '|'.join(sorted(PREFIX, key=len, reverse=True)) + r'):(\d+)(?:-(\d+))?\b')

# What no pinned file says: the document's "What could not be verified" lists these ids and no others, and no register offset or bit position of the table
# or the code rests on an item of this list except where the item says so.
UNVERIFIED = {
    'UV1': 'what any GPU word holds on the unit: none has ever been read there, so whether a read aborts, hangs the bus or raises an SError is UNKNOWN',
    'UV2': 'that GPUCC answers while GCC_GPU_CFG_AHB runs: Linux keeps that clock enabled (gcc-x1e80100.c:7451, common.c:317-318) and reads GPUCC all the time, and the '
           'A16 notes of the plan say the same of that SoC; it is a premise for the unit, not a fact about it',
    'UV3': 'that bit 31 of GDS_HW_CTRL reads 1 when the CX domain is on on this unit: it is what Linux reads (gdsc.c:61-91), and the first reading of it is this run',
    'UV4': 'that CX_MISC, the GMU window and the RSC answer while the CX domain is on and the GMU is still held in reset: Linux reads and writes them in that state '
           '(a6xx_gmu.c:716-745, 964, 983-1010), the unit has not been asked',
    'UV5': 'what the size codes of ID2 (IAS, OAS, UBS) stand for in bits: the codes are defined in arm-smmu.c, which is not pinned; they are printed as codes',
    'UV6': 'which software owns these blocks at EL2 (the hypervisor, an XPU, the secure world): the plan lists it as open (R2); a refused read is the answer',
}


def refs_dirs():
    """The directories that may hold the pinned copies, in the order they are looked in."""
    dirs = []
    if os.environ.get('GPUSNAP_REFS_DIR'):
        dirs += [Path(p) for p in os.environ['GPUSNAP_REFS_DIR'].split(os.pathsep) if p]
    if os.environ.get('SNAPINTOSH_DIR'):
        dirs.append(Path(os.environ['SNAPINTOSH_DIR']) / 'build' / 'sp11-stick-log' / 'refs')
    dirs.append(ROOT / 'build' / 'sp11-gpusnap' / 'refs')
    return [d for d in dirs if d.is_dir()]


def locate(name):
    """The path of the pinned copy of `name`, or None."""
    for directory in refs_dirs():
        if (directory / name).is_file():
            return directory / name
    return None


def missing():
    return [name for name in PINNED if locate(name) is None]


def load():
    """{file name: [lines]} of the pinned copies, each checked against its digest (ValueError on a mismatch: a changed file is not a reference; FileNotFoundError
    for a missing one)."""
    files = {}
    for name, (digest, _) in PINNED.items():
        path = locate(name)
        if path is None:
            raise FileNotFoundError(name)
        data = path.read_bytes()
        if hashlib.sha256(data).hexdigest() != digest:
            raise ValueError(f'{name} is not the pinned copy')
        files[name] = data.decode('utf-8').splitlines()
    return files


def cited(text):
    """[(prefix, first line, last line)] of every file:line citation of `text`, in order."""
    return [(m.group(1), int(m.group(2)), int(m.group(3) or m.group(2))) for m in CITATION.finditer(text)]


# ---- The ledger ------------------------------------------------------------------------------------------------------------------------------------
# (prefix, first line, last line, pattern over the joined lines, what it shows). Every pattern was written from the line as read in the pinned copy.
def _halt(prefix, line, offset, what):
    return (prefix, line, line, rf'\.halt_reg = {offset},', what)


LEDGER = [
    # gcc-x1e80100.c
    ('gcc', 117, 118, r'\.enable_reg = 0x52030,\s*\.enable_mask = BIT\(0\),', 'gcc_gpll0 is voted at 0x52030 bit 0'),
    ('gcc', 2977, 2980, r'\.halt_reg = 0x7115c,\s*\.halt_check = BRANCH_HALT_SKIP,\s*\.hwcg_reg = 0x7115c,\s*\.hwcg_bit = 1,',
     'gcc_ddrss_gpu_axi_clk: halt check skipped, hardware gating bit 1'),
    ('gcc', 3063, 3064, r'\.enable_reg = 0x52000,\s*\.enable_mask = BIT\(15\),', 'gcc_gpu_gpll0_cph_clk_src is the vote bit 15 of 0x52000'),
    ('gcc', 3080, 3081, r'\.enable_reg = 0x52000,\s*\.enable_mask = BIT\(16\),', 'gcc_gpu_gpll0_div_cph_clk_src is the vote bit 16 of 0x52000'),
    ('gcc', 3095, 3098, r'\.halt_reg = 0x71010,\s*\.halt_check = BRANCH_HALT_VOTED,\s*\.hwcg_reg = 0x71010,\s*\.hwcg_bit = 1,', 'gcc_gpu_memnoc_gfx_clk'),
    ('gcc', 3110, 3111, r'\.halt_reg = 0x71018,\s*\.halt_check = BRANCH_HALT,', 'gcc_gpu_snoc_dvm_gfx_clk: a plain halt check, no hardware gating bit'),
    ('gcc', 4262, 4265, r'\.halt_reg = 0x71008,\s*\.halt_check = BRANCH_HALT_VOTED,\s*\.hwcg_reg = 0x71008,\s*\.hwcg_bit = 1,', 'gcc_qmip_gpu_ahb_clk'),
    ('gcc', 7284, 7284, r'\[GCC_GPU_BCR\] = \{ 0x71000 \},', 'the GPU block reset (not read)'),
    ('gcc', 7451, 7451, r'0x71004, /\* GCC_GPU_CFG_AHB_CLK \*/', 'the GPU CFG AHB clock is in the critical list'),
    ('gcc', 7466, 7467, r'\.clk_cbcrs = gcc_x1e80100_critical_cbcrs,\s*\.num_clk_cbcrs = ARRAY_SIZE\(gcc_x1e80100_critical_cbcrs\),', 'the critical list is handed to the common code'),
    # common.c
    ('cmn', 317, 318, r'for \(i = 0; i < data->num_clk_cbcrs; i\+\+\)\s*qcom_branch_set_clk_en\(regmap, data->clk_cbcrs\[i\]\);', 'every critical CBCR is enabled'),
    # gpucc-x1e80100.c
    ('gpucc', 104, 149, r'gpu_cc_parent_map_0.*\{ P_BI_TCXO, 0 \},.*\{ P_GPLL0_OUT_MAIN, 5 \},.*\{ P_GPLL0_OUT_MAIN_DIV, 6 \},.*gpu_cc_parent_map_1.*'
     r'\{ P_GPU_CC_PLL0_OUT_MAIN, 1 \},.*\{ P_GPU_CC_PLL1_OUT_MAIN, 3 \},', 'parent index 0 is XO, 1 PLL0, 3 PLL1, 5 GPLL0, 6 GPLL0_DIV'),
    ('gpucc', 182, 182, r'\.cmd_rcgr = 0x9318,', 'gpu_cc_gmu_clk_src'), ('gpucc', 197, 197, r'\.cmd_rcgr = 0x93ec,', 'gpu_cc_hub_clk_src'),
    ('gpucc', 212, 212, r'\.cmd_rcgr = 0x9010,', 'gpu_cc_xo_clk_src'),
    ('gpucc', 257, 258, r'\.halt_reg = 0x911c,\s*\.halt_check = BRANCH_HALT_VOTED,', 'gpu_cc_ahb_clk'),
    ('gpucc', 311, 312, r'\.halt_reg = 0x913c,\s*\.halt_check = BRANCH_HALT_VOTED,', 'gpu_cc_cx_gmu_clk'),
    ('gpucc', 323, 323, r'clk_branch2_aon_ops', 'gpu_cc_cx_gmu_clk is an always-on clock: Linux never disables it'),
    _halt('gpucc', 329, '0x9004', 'gpu_cc_cxo_aon_clk'), _halt('gpucc', 347, '0x9144', 'gpu_cc_cxo_clk'), _halt('gpucc', 365, '0x900c', 'gpu_cc_demet_clk'),
    ('gpucc', 377, 377, r'clk_branch2_aon_ops', 'gpu_cc_demet_clk is an always-on clock'),
    _halt('gpucc', 401, '0x7000', 'gpu_cc_hlos1_vote_gpu_smmu_clk'),
    ('gpucc', 414, 426, r'\.halt_reg = 0x90bc,\s*\.halt_check = BRANCH_HALT,.*\.ops = &clk_branch2_ops,', 'gpu_cc_gx_gmu_clk: a plain branch2 clock with a halt check, not an always-on one'),
    _halt('gpucc', 445, '0x93e8', 'gpu_cc_hub_aon_clk'),
    ('gpucc', 457, 457, r'clk_branch2_aon_ops', 'gpu_cc_hub_aon_clk is an always-on clock'),
    _halt('gpucc', 463, '0x9148', 'gpu_cc_hub_cx_int_clk'),
    ('gpucc', 475, 475, r'clk_branch2_aon_ops', 'gpu_cc_hub_cx_int_clk is an always-on clock'),
    ('gpucc', 532, 543, r'gpu_cx_gdsc = \{\s*\.gdscr = 0x9108,\s*\.gds_hw_ctrl = 0x953c,.*\.flags = VOTABLE \| RETAIN_FF_ENABLE,', 'the CX GDSC: GDSCR, status word, votable'),
    ('gpucc', 545, 557, r'gpu_gx_gdsc = \{\s*\.gdscr = 0x905c,.*\.flags = CLAMP_IO \| AON_RESET \| SW_RESET \| POLL_CFG_GDSCR,', 'the GX GDSC: GDSCR, polls CFG_GDSCR'),
    ('gpucc', 608, 608, r'\.max_register = 0x9988,', 'the last register of GPUCC, inside its 0xa000 window'),
    # gdsc.c, clk-branch.h/c, clk-rcg2.c
    ('gdsc', 21, 21, r'PWR_ON_MASK\s+BIT\(31\)', 'PWR_ON is bit 31'), ('gdsc', 26, 27, r'HW_CONTROL_MASK\s+BIT\(1\)\s*#define SW_COLLAPSE_MASK\s+BIT\(0\)', 'HW_CONTROL bit 1, SW_COLLAPSE bit 0'),
    ('gdsc', 32, 35, r'GDSC_POWER_UP_COMPLETE\s+BIT\(16\).*GDSC_POWER_DOWN_COMPLETE\s+BIT\(15\).*CFG_GDSCR_OFFSET\s+0x4', 'CFG_GDSCR, at +4, has the power up and power down complete bits'),
    ('gdsc', 61, 91, r'gdsc_check_status.*POLL_CFG_GDSCR\)\s*reg = sc->gdscr \+ CFG_GDSCR_OFFSET;\s*else if \(sc->gds_hw_ctrl\)\s*reg = sc->gds_hw_ctrl;.*'
     r'GDSC_POWER_UP_COMPLETE.*GDSC_POWER_DOWN_COMPLETE.*return !!\(val & PWR_ON_MASK\);', 'the status is read from gds_hw_ctrl (PWR_ON) for the CX GDSC, from CFG_GDSCR for the GX GDSC'),
    ('gdsc', 127, 141, r'gdsc_update_collapse_bit.*regmap_update_bits\(sc->regmap, reg, mask, val \? mask : 0\)', 'the collapse bit of a GDSCR is updated by a read-modify-write: Linux reads the register'),
    ('gdsc', 424, 424, r'regmap_read\(sc->regmap, sc->gdscr, &val\)', 'Linux reads a GDSCR'),
    ('cb', 63, 65, r'CBCR_CLK_OFF\s+BIT\(31\)\s*#define CBCR_NOC_FSM_STATUS\s+GENMASK\(30, 28\)\s*#define FSM_STATUS_ON\s+BIT\(1\)', 'CLK_OFF is bit 31, the NoC FSM status bits 30:28'),
    ('cb', 71, 71, r'CBCR_CLOCK_ENABLE\s+BIT\(0\)', 'CLK_ENABLE is bit 0'),
    ('cb', 106, 109, r'qcom_branch_set_clk_en.*regmap_update_bits\(regmap, cbcr, CBCR_CLOCK_ENABLE, CBCR_CLOCK_ENABLE\)', 'a critical CBCR is enabled by a read-modify-write: Linux reads it'),
    ('cbc', 17, 27, r'clk_branch_in_hwcg_mode.*hwcg_reg.*BIT\(br->hwcg_bit\)', 'a clock is in hardware gated mode when its hwcg bit is set'),
    ('cbc', 52, 52, r'regmap_read\(br->clkr\.regmap, br->halt_reg, &val\)', 'the halt check reads the CBCR'),
    ('cbc', 54, 58, r'CBCR_CLK_OFF.*CBCR_NOC_FSM_STATUS, val\) == FSM_STATUS_ON', 'Linux counts the NoC FSM status ON as the clock being on'),
    ('cbc', 72, 72, r'BRANCH_HALT_SKIP \|\| clk_branch_in_hwcg_mode\(br\)', 'Linux does not check the halt bit of a skipped or hardware gated clock'),
    ('cbc', 175, 179, r'clk_branch2_ops = \{\s*\.enable = clk_branch2_enable,\s*\.disable = clk_branch2_disable,\s*\.is_enabled = clk_is_enabled_regmap,', 'a branch clock of the plain kind has an enable, a disable and the generic is_enabled (clk-regmap.c, not pinned here)'),
    ('cbc', 182, 186, r'clk_branch2_aon_ops = \{\s*\.enable = clk_branch2_enable,\s*\.is_enabled', 'an always-on clock has an enable and no disable'),
    ('rcg', 33, 39, r'CMD_ROOT_OFF\s+BIT\(31\).*CFG_REG\s+0x4.*CFG_SRC_SEL_SHIFT\s+8\s.*CFG_SRC_SEL_MASK\s+\(0x7 << CFG_SRC_SEL_SHIFT\)', 'RCG: ROOT_OFF bit 31, CFG at +4, source select bits 10:8'),
    # hamoa.dtsi
    ('dt', 758, 760, r'gcc: clock-controller@100000.*reg = <0 0x00100000 0 0x200000>;', 'the GCC window'),
    ('dt', 4016, 4018, r'reg = <0x0 0x03d00000 0x0 0x40000>,\s*<0x0 0x03d9e000 0x0 0x1000>,\s*<0x0 0x03d61000 0x0 0x800>;', 'the GPU window (GX), cx_mem and cx_dbgc'),
    ('dt', 4175, 4177, r'reg = <0x0 0x03d6a000 0x0 0x35000>,\s*<0x0 0x03d50000 0x0 0x10000>,\s*<0x0 0x0b280000 0x0 0x10000>;', 'the GMU, RSCC and PDC windows'),
    ('dt', 4184, 4197, r'GPU_CC_AHB_CLK.*GPU_CC_CX_GMU_CLK.*GPU_CC_CXO_CLK.*GCC_DDRSS_GPU_AXI_CLK.*GCC_GPU_MEMNOC_GFX_CLK.*GPU_CC_HUB_CX_INT_CLK.*GPU_CC_DEMET_CLK.*'
     r'"ahb".*"gmu".*"cxo".*"axi".*"memnoc".*"hub".*"demet"', 'the seven clocks of the GMU node, in order'),
    ('dt', 4199, 4199, r'power-domains = <&gpucc GPU_CX_GDSC>,', 'the GMU node power domain'),
    ('dt', 4227, 4227, r'reg = <0 0x03d90000 0 0xa000>;', 'the GPUCC window'),
    ('dt', 4239, 4239, r'reg = <0x0 0x03da0000 0x0 0x40000>;', 'the GPU SMMU window'),
    ('dt', 4268, 4276, r'GPU_CC_HLOS1_VOTE_GPU_SMMU_CLK.*GCC_GPU_MEMNOC_GFX_CLK.*GCC_GPU_SNOC_DVM_GFX_CLK.*GPU_CC_AHB_CLK.*"hlos".*"bus".*"iface".*"ahb".*'
     r'power-domains = <&gpucc GPU_CX_GDSC>;', 'the four clocks of the GPU SMMU node, in order, and its power domain'),
    # arm-smmu.h
    ('smmu', 27, 27, r'ARM_SMMU_GR0_sCR0\s+0x0$', 'sCR0'), ('smmu', 45, 45, r'ARM_SMMU_GR0_ID0\s+0x20$', 'ID0'), ('smmu', 57, 57, r'ARM_SMMU_ID0_NUMSMRG\s+GENMASK\(7, 0\)', 'NUMSMRG is bits 7:0'),
    ('smmu', 59, 63, r'ARM_SMMU_GR0_ID1\s+0x24.*ARM_SMMU_ID1_PAGESIZE\s+BIT\(31\).*ARM_SMMU_ID1_NUMPAGENDXB\s+GENMASK\(30, 28\).*ARM_SMMU_ID1_NUMCB\s+GENMASK\(7, 0\)',
     'ID1: PAGESIZE bit 31, NUMPAGENDXB bits 30:28, NUMCB bits 7:0'),
    ('smmu', 65, 72, r'ARM_SMMU_GR0_ID2\s+0x28.*PTFS_64K\s+BIT\(14\).*PTFS_16K\s+BIT\(13\).*PTFS_4K\s+BIT\(12\).*UBS\s+GENMASK\(11, 8\).*OAS\s+GENMASK\(7, 4\).*IAS\s+GENMASK\(3, 0\)',
     'ID2: page table formats bits 14:12, UBS, OAS, IAS'),
    ('smmu', 79, 79, r'ARM_SMMU_GR0_ID7\s+0x3c$', 'ID7'), ('smmu', 83, 83, r'ARM_SMMU_GR0_sGFSR\s+0x48$', 'sGFSR'),
    # a6xx_gmu.xml
    ('xml', 64, 64, r'offset="0x1f800" name="GMU_CM3_SYSRESET"', 'GMU_CM3_SYSRESET'), ('xml', 66, 68, r'offset="0x1f81a" name="GMU_CM3_FW_BUSY".*offset="0x1f81c" name="GMU_CM3_FW_INIT_RESULT".*'
     r'offset="0x1f82d" name="GMU_CM3_CFG"', 'FW_BUSY, FW_INIT_RESULT, CM3_CFG'),
    ('xml', 108, 111, r'offset="0x1f8d0" name="GMU_SPTPRAC_PWR_CLK_STATUS" variants="A7XX".*GX_HM_GDSC_POWER_OFF" pos="0".*GX_HM_CLK_OFF" pos="1"', 'the A7XX GX status word and its two bits'),
    ('xml', 231, 231, r'offset="0x23b13" name="GMU_AHB_FENCE_STATUS"', 'GMU_AHB_FENCE_STATUS'),
    ('xml', 244, 245, r'offset="0x0004" name="GPU_RSCC_RSC_STATUS0_DRV0".*offset="0x0008" name="RSCC_PDC_SEQ_START_ADDR"', 'RSC_STATUS0_DRV0 and PDC_SEQ_START_ADDR'),
    ('xml', 256, 256, r'offset="0x0101" name="RSCC_SEQ_BUSY_DRV0"', 'SEQ_BUSY_DRV0'),
    ('xml', 259, 268, r'RSCC_TCS0_DRV0_STATUS.*RSCC_TCS1_DRV0_STATUS.*RSCC_TCS2_DRV0_STATUS.*RSCC_TCS3_DRV0_STATUS.*RSCC_TCS4_DRV0_STATUS.*RSCC_TCS5_DRV0_STATUS.*'
     r'RSCC_TCS6_DRV0_STATUS.*RSCC_TCS7_DRV0_STATUS.*RSCC_TCS8_DRV0_STATUS.*RSCC_TCS9_DRV0_STATUS', 'the ten TCS status words'),
    ('a6x', 5130, 5133, r'A6XX_CX_MISC.*offset="0x0039" name="CX_MISC_TCM_RET_CNTL" variants="A7XX-"', 'CX_MISC_TCM_RET_CNTL, dword 0x39'),
    # a6xx_gmu.c, a6xx_gmu.h, a6xx_gpu.[ch], the catalog
    ('gmu', 121, 136, r'bool a7xx_gmu_gx_is_on.*return !\(val &\s*\(A7XX_GMU_SPTPRAC_PWR_CLK_STATUS_GX_HM_GDSC_POWER_OFF \|\s*A7XX_GMU_SPTPRAC_PWR_CLK_STATUS_GX_HM_CLK_OFF\)\);',
     'GX is on when neither of the two bits is set'),
    ('gmu', 320, 333, r'REG_A6XX_GMU_CM3_SYSRESET, 1\).*REG_A6XX_GMU_CM3_SYSRESET, 0\)', 'GMU_CM3_SYSRESET is held at 1 and released at 0, written and never read'),
    ('gmu', 335, 335, r'gmu_poll_timeout\(gmu, REG_A6XX_GMU_CM3_FW_INIT_RESULT', 'GMU_CM3_FW_INIT_RESULT is polled'),
    ('gmu', 637, 637, r'gmu_poll_timeout_rscc\(gmu, REG_A6XX_RSCC_SEQ_BUSY_DRV0', 'RSCC_SEQ_BUSY_DRV0 is polled'),
    ('gmu', 666, 666, r'gmu_poll_timeout_rscc\(gmu, REG_A6XX_GPU_RSCC_RSC_STATUS0_DRV0', 'GPU_RSCC_RSC_STATUS0_DRV0 is polled'),
    ('gmu', 730, 730, r'REG_A6XX_RSCC_PDC_SEQ_START_ADDR, 0x4520\)', 'Linux programs PDC_SEQ_START_ADDR to 0x4520 and never reads it'),
    ('gmu', 964, 964, r'a6xx_cx_misc_write\(a6xx_gpu, REG_A7XX_CX_MISC_TCM_RET_CNTL, 1\)', 'Linux writes TCM_RET_CNTL = 1'),
    ('gmu', 1010, 1010, r'gmu_write\(gmu, REG_A6XX_GMU_CM3_CFG, 0x4052\)', 'GMU_CM3_CFG is written and never read'),
    ('gmu', 1364, 1364, r'a6xx_cx_misc_read\(a6xx_gpu, REG_A7XX_CX_MISC_TCM_RET_CNTL\) == 1', 'Linux reads TCM_RET_CNTL to tell a warm boot from a cold one'),
    ('gmu', 1105, 1108, r'adreno_is_a740_family\(adreno_gpu\) \|\| adreno_is_a722\(adreno_gpu\) \|\|\s*adreno_is_a8xx\(adreno_gpu\)\)\s*seqmem_off = 4;', 'the TCS status words sit 4 dwords up on the a740 family'),
    ('gmu', 1111, 1135, r'REG_A6XX_RSCC_TCS0_DRV0_STATUS \+ seqmem_off.*REG_A7XX_RSCC_TCS9_DRV0_STATUS \+ seqmem_off', 'TCS0..9 are polled with that offset, for a bit 0 that means idle'),
    ('gmu', 2446, 2446, r'gmu->mmio_offset = \(u32\)\(start - res->start\);', 'the GMU window offset from the GPU base'),
    ('gmu', 2450, 2450, r'gmu->rscc = devm_platform_ioremap_resource_byname\(pdev, "rscc"\);', 'the RSC has its own window on the a7xx'),
    ('gmuh', 139, 139, r'GMU_BYTE_OFFSET\(gmu, offset\) \(\(\(offset\) << 2\) - \(gmu\)->mmio_offset\)', 'a GMU register is dword << 2 less the window offset'),
    ('gpuh', 275, 278, r'a6xx_cx_misc_read.*return readl\(a6xx_gpu->cx_misc_mmio \+ \(reg << 2\)\);', 'a CX_MISC register is dword << 2 from its window'),
    ('gpuc', 76, 76, r'gmu_poll_timeout\(gmu, REG_A6XX_GMU_AHB_FENCE_STATUS', 'GMU_AHB_FENCE_STATUS is polled'),
    ('gpuc', 2739, 2739, r'cx_misc_mmio = msm_ioremap\(pdev, "cx_mem"\);', 'the CX_MISC window is cx_mem'),
    ('cat', 376, 377, r'ADRENO_CHIP_IDS\(0x43050c01\).*\.family = ADRENO_7XX_GEN2,', 'the X1-85 is a gen2 a7xx'),
    ('agh', 572, 577, r'adreno_is_a740_family.*family == ADRENO_7XX_GEN2 \|\|\s*gpu->info->family == ADRENO_7XX_GEN3', 'gen2 is the a740 family'),
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


# ---- By name ---------------------------------------------------------------------------------------------------------------------------------------
def struct_field(lines, struct, field):
    """The value of `.field = value,` in `static struct <type> <struct> = {` of a Linux clock file (as text), or None."""
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
    """An integer macro expression of the pinned files: hex numbers, BIT(n), GENMASK(h, l), |, +, <<, >>, & and the names of other #defines."""
    expression = re.sub(r'BIT\((\d+)\)', r'(1<<\1)', expression)
    expression = re.sub(r'GENMASK\((\d+),\s*(\d+)\)', lambda m: f'(((1<<({int(m.group(1)) - int(m.group(2)) + 1}))-1)<<{m.group(2)})', expression)
    for name in set(re.findall(r'\b[A-Za-z_]\w*\b', expression)):
        if re.fullmatch(r'0x[0-9a-fA-F]+|\d+', name):
            continue
        body = define(lines, name)
        if body is None:
            raise ValueError(f'{name} is not a #define of the file')
        expression = re.sub(rf'\b{name}\b', f'({evaluate(lines, body)})', expression)
    if not re.fullmatch(r'[0-9a-fA-Fx()<>|+&\s-]+', expression):
        raise ValueError(f'not an integer expression: {expression!r}')
    return eval(expression, {'__builtins__': {}}, {})  # noqa: S307 (the text is one of the pinned files', checked above)


def bit_of(lines, name):
    """The bit number of a `#define name BIT(n)` of a pinned file."""
    value = evaluate(lines, define(lines, name))
    if value & (value - 1):
        raise ValueError(f'{name} is not one bit')
    return value.bit_length() - 1


def field_of(lines, name):
    """(shift, mask after the shift) of a `#define name GENMASK(h, l)` (or one bit) of a pinned file."""
    value = evaluate(lines, define(lines, name))
    shift = (value & -value).bit_length() - 1
    return shift, value >> shift


def dt_node_regs(lines, label):
    """[(address, size)] of the `reg = <...>` groups of the node that starts `<label>: ...{` at two tabs (two address and two size cells), or None."""
    for index, line in enumerate(lines):
        if re.match(rf'\t\t{re.escape(label)}: \S+ \{{$', line):
            end = next(i for i in range(index + 1, len(lines)) if lines[i] == '\t\t};')
            found = re.search(r'^\t\t\treg = ((?:<[^>]*>,?\s*)+);', '\n'.join(lines[index:end]), re.M)
            if not found:
                return None
            groups = []
            for group in re.findall(r'<([^>]*)>', found.group(1)):
                cells = [int(c, 0) for c in group.split()]
                groups += [(cells[k] << 32 | cells[k + 1], cells[k + 2] << 32 | cells[k + 3]) for k in range(0, len(cells), 4)]
            return groups
    return None


def xml_registers(lines):
    """{name: [(dword, variants or '')]} of the `<reg32 offset=... name=...>` entries of a Linux register XML file."""
    found = {}
    for line in lines:
        m = re.match(r'\s*<reg32 offset="(0x[0-9a-f]+)" name="(\w+)"(?: variants="([^"]*)")?', line)
        if m:
            found.setdefault(m.group(2), []).append((int(m.group(1), 16), m.group(3) or ''))
    return found


def xml_bitfields(lines, register, variants=None):
    """{field: pos} of the `<bitfield name=... pos=...>` entries of the (variant of the) register `register`."""
    out, inside = {}, False
    for line in lines:
        m = re.match(r'\s*<reg32 offset="0x[0-9a-f]+" name="(\w+)"(?: variants="([^"]*)")?(/?)>', line)
        if m:
            inside = m.group(1) == register and (variants is None or m.group(2) == variants) and not m.group(3)
            continue
        if inside:
            f = re.match(r'\s*<bitfield name="(\w+)" pos="(\d+)"', line)
            if f:
                out[f.group(1)] = int(f.group(2))
            elif '</reg32>' in line:
                inside = False
    return out


# ---- The table of payloads/gpusnap-regs.h ----------------------------------------------------------------------------------------------------------
def parse_windows(text):
    """[(base, size)] of the window table of gpusnap-regs.h, in table order (GCC, GPUCC, CXMISC, GMU, RSCC, SMMU)."""
    body = re.search(r'windows\[WINDOWS\] = \{(.*?)\};', text, re.S).group(1)
    return [(int(b, 16), int(s, 16)) for b, s in re.findall(r'\{(0x[0-9a-f]+)u, (0x[0-9a-f]+)u, 0\}', body)]


def _call_arguments(text, name):
    """[(argument text)] of every `name(...)` call of `text` (the arguments split at the top level, parentheses balanced)."""
    calls = []
    for m in re.finditer(rf'(?<![\w])({name})\(', text):
        depth, start, parts = 1, m.end(), []
        for i in range(m.end(), len(text)):
            ch = text[i]
            depth += ch == '('
            depth -= ch == ')'
            if depth == 0:
                parts.append(text[start:i].strip())
                break
            if ch == ',' and depth == 1:
                parts.append(text[start:i].strip())
                start = i + 1
        calls.append(parts)
    return calls


def parse_rows(text):
    """[(key, window name, offset expression, decode, flags)] of the register table of gpusnap-regs.h, in table order; a TCS row is expanded as its macro does."""
    rows = []
    start = text.index('static const struct reg regs[R_COUNT] = {')
    body = text[start:text.index('\n};', start)]
    seqmem = int(re.search(r'#define RSC_TCS_SEQMEM_DWORDS (\d+)u', text).group(1))
    for m in re.finditer(r'(?<![\w])(TCS_ROW|ROW)\(', body):
        parts = next(p for p in _call_arguments(body[m.start():], m.group(1)))
        if m.group(1) == 'ROW':
            rows.append((parts[4].strip('"'), parts[0].removeprefix('WIN_'), parts[1], parts[2], parts[3]))
        else:
            rows.append((parts[0].strip('"'), 'RSCC', f'RSC({parts[1]} + {seqmem})', 'D_NONE', 'F_QUIET'))
    return rows


def macro_offset(text, window, expression):
    """The byte offset in its window that the table's offset expression stands for (CXM, RSC and GMU as gpusnap-regs.h defines them)."""
    gmu_base = int(re.search(r'#define GMU_WINDOW_FROM_GPU_BASE (0x[0-9a-f]+)u', text).group(1), 16)
    expression = re.sub(r'\bCXM\(([^)]*)\)', r'(4*(\1))', expression)
    expression = re.sub(r'\bRSC\(([^)]*)\)', r'(4*(\1))', expression)
    expression = re.sub(r'\bGMU\(([^)]*)\)', rf'(4*(\1)-{gmu_base})', expression)
    if not re.fullmatch(r'[0-9a-fx()+*\- ]+', expression):
        raise ValueError(f'not an offset expression: {expression!r}')
    return eval(expression, {'__builtins__': {}}, {})  # noqa: S307 (checked above)
