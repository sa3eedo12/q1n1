# SPDX-License-Identifier: MIT
"""Adreno X1-85 (a7xx, gen70500, chip 0x43050c01) register table for the Surface Pro 11 GPU bring-up (gate X8a).

HOST MODEL ONLY. Nothing here has run on a Surface Pro 11, no GPU register has been read on any machine through this
module, and nothing in it authorises a run: it is the table tools/sp11_gpu_x8a.py checks every access against, and
tools/test-sp11-gpu-x8a.py drives against a fake device. The counterpart for the A16 is tools/adreno_x2.py.

Where an address comes from. Every register is a (block, offset) pair. The blocks' base addresses are the board
descriptor's (BOARD_PUBLIC below holds the ones the public Linux device tree for the X1E80100 gives); a register whose offset
no cited public source gives has offset None, and the tool refuses to touch it. Nothing is typed from memory.

Evidence tags (all VERIFIED means read in the cited file at the pin; never a hardware result):
  LNX  Linux 7475ea8b58616b33c04afb976cf0fbaad9dd63fb (drivers/clk/qcom/{gcc,gpucc}-x1e80100.c, gdsc.[ch], clk-branch.h,
       clk-rcg2.c, drivers/gpu/drm/msm/adreno/a6xx_gmu.c, registers/adreno/a6xx_gmu.xml, arch/arm64/boot/dts/qcom/hamoa.dtsi,
       drivers/iommu/arm/arm-smmu/arm-smmu.h), GPL-2.0-only files read for facts; nothing is copied.
  MESA Mesa bbeb2dca9feed6ac88d71234a9dc5ae8aeed4275 (src/freedreno/registers/adreno/a6xx.xml).
  STUDY docs/SP11-GPU-A7XX-STUDY.md of the Snapintosh tree, by section.
  GMU XML dword offsets count from the GPU base (STUDY 2.3, row "MMIO base"), so GMU registers are (block 'gpu', 4 * dword).

Domains: AO always on while the SoC runs (GCC); CX the GPU's CX side (GPUCC, and behind the CX GDSC the GMU, RSCC, CX_MISC,
GBIF, the SMMU); GX the GPU core and what the GMU powers.  Gates, what must be proven before a register is touched:
  always    nothing.
  gcc_ahb   GCC_GPU_CFG_AHB_CBCR runs: the GPUCC register file is reachable (the A16 stage-1 finding; Linux keeps 0x71004 on).
  cx_on     the Linux precedent for touching the GMU: CX GDSC on (status from GDS_HW_CTRL), not under SW collapse or HW control,
            and every clock the hamoa GMU node lists running (ahb, gmu, cxo, axi, memnoc, hub, demet).
  cx_smmu   cx_on and the four clocks of the hamoa adreno_smmu node running (hlos vote, memnoc, snoc dvm, ahb).
  gmu_up    the GMU answered (firmware init result seen).
  gx_on     the GMU reports GX on. No GX register is touched before this, and never by the survey.
  never     listed for the record; a reset or a register no stage may touch.
"""
from __future__ import annotations

from dataclasses import dataclass

DOMAINS = ('AO', 'CX', 'GX')
GATES = ('always', 'gcc_ahb', 'cx_on', 'cx_smmu', 'gmu_up', 'gx_on', 'never')

# --- bit definitions (LNX drivers/clk/qcom/gdsc.c:21-35, clk-branch.h:63, clk-rcg2.c:26-39) ---------------------------------
GDSC_PWR_ON = 1 << 31               # gdsc_check_status reads it from GDS_HW_CTRL for the CX GDSC (gds_hw_ctrl set, gdsc.c:60-82)
GDSC_HW_CONTROL = 1 << 1
GDSC_SW_OVERRIDE = 1 << 2
GDSC_SW_COLLAPSE = 1 << 0
GDSC_RETAIN_FF = 1 << 11            # RETAIN_FF_ENABLE_MASK: CX has the flag in gpucc-x1e80100.c
GDSC_EN_REST_WAIT, GDSC_EN_FEW_WAIT, GDSC_CLK_DIS_WAIT = 0xf << 20, 0xf << 16, 0xf << 12
GDSC_WAITS_MASK = GDSC_EN_REST_WAIT | GDSC_EN_FEW_WAIT | GDSC_CLK_DIS_WAIT
CX_GDSC_WAITS = 2 << 20 | 2 << 16 | 0xf << 12       # gpu_cx_gdsc en_rest 2, en_few 2, clk_dis 0xf (gpucc-x1e80100.c:536-538)
GDSC_POWER_UP_COMPLETE = 1 << 16    # CFG_GDSCR (gdscr + 4), only for gdsc flag POLL_CFG_GDSCR (the GX GDSC here)
GDSC_POWER_DOWN_COMPLETE = 1 << 15
CBCR_ENABLE = 1 << 0
CBCR_HW_CTL = 1 << 1
CBCR_CLK_OFF = 1 << 31
RCG_UPDATE = 1 << 0
RCG_ROOT_EN = 1 << 1
RCG_ROOT_OFF = 1 << 31
RCG_SRC_SEL_MASK = 0x7 << 8
RCG_SRC_XO = 0                      # parent index 0 is BI_TCXO in every gpucc parent map (gpucc-x1e80100.c:104-149)
RCG_SRC_GPLL0, RCG_SRC_GPLL0_DIV = 5, 6      # the hub RCG's GCC parents (gpu_cc_parent_map_2); GCC_PROC_VOTE_ENA bits 15 and 16
GCC_VOTE_GPLL0, GCC_VOTE_GPLL0_DIV = 1 << 15, 1 << 16

# --- the public part of the board descriptor (LNX hamoa.dtsi, X1E80100; reg windows) ----------------------------------------
BOARD_PUBLIC = {
    'gcc': (0x00100000, 0x200000, 'hamoa.dtsi:758-760'),
    'gpu': (0x03d00000, 0x40000, 'hamoa.dtsi:4014-4018'),
    'gmu': (0x03d6a000, 0x35000, 'hamoa.dtsi:4173-4177'),
    'rscc': (0x03d50000, 0x10000, 'hamoa.dtsi:4173-4177 (gmu node, rscc window)'),
    'pdc': (0x0b280000, 0x10000, 'hamoa.dtsi:4173-4177 (gmu node, gmu_pdc window)'),
    'gpucc': (0x03d90000, 0xa000, 'hamoa.dtsi:4225-4234'),
    'cx_misc': (0x03d9e000, 0x1000, 'hamoa.dtsi:4014-4018 (cx_mem window)'),
    'smmu': (0x03da0000, 0x40000, 'hamoa.dtsi:4236'),
}
# Block window -> (domain, gate that must hold before ANY access inside it).
BLOCK_RULES = {
    'gcc': ('AO', 'always'),
    'gpucc': ('CX', 'gcc_ahb'),
    'gpu': ('GX', 'gx_on'),          # the GPU window holds RBBM and CP (GX); the GMU registers inside it are named 'gmu'
    'gmu': ('CX', 'cx_on'),
    'rscc': ('CX', 'cx_on'),
    'cx_misc': ('CX', 'cx_on'),
    'smmu': ('CX', 'cx_smmu'),
    'pdc': ('CX', 'cx_on'),
}


@dataclass(frozen=True)
class Reg:
    name: str
    block: str                 # key of BLOCK_RULES; the base comes from the board
    off: int | None            # byte offset inside the block; None = no cited source: the tool refuses
    domain: str
    gate: str
    access: str                # '' (listed only), 'r', 'rw'
    evidence: str
    notes: str = ''
    halt: str = ''             # branch clocks: HALT, HALT_VOTED, HALT_DELAY, HALT_SKIP (LNX clk_branch.halt_check)
    count: int = 1
    stride: int = 4
    window: str = ''           # the block whose window the register lies in, when it differs from `block` (GMU registers)

    def at(self, base: int, index: int = 0) -> int:
        if self.off is None:
            raise IndexError(f'{self.name} has no cited offset')
        if not 0 <= index < self.count:
            raise IndexError(f'{self.name}[{index}] outside 0..{self.count - 1}')
        return base + self.off + self.stride * index


REGS: dict[str, Reg] = {}


def _add(name, block, off, access, evidence, notes='', halt='', count=1, stride=4, gate=None, domain=None):
    d, g = BLOCK_RULES[block]
    REGS[name] = Reg(name, block, off, domain or d, gate or g, access, evidence, notes, halt, count, stride)


def _gmu(name, dword, access, evidence, notes='', gate='cx_on', count=1):
    """A GMU register: its address is the GPU base plus 4 * the XML dword (Linux mmio_offset), inside the GMU's own window."""
    REGS[name] = Reg(name, 'gpu', None if dword is None else 4 * dword, 'CX', gate, access, evidence, notes, '', count,
                     window='gmu')


# GCC (always on). LNX gcc-x1e80100.c: gcc_ddrss_gpu_axi_clk 2975-2988, gpu_gpll0 votes 3060-3092, memnoc/snoc_dvm 3094-3123,
# qmip_gpu_ahb 4260-4272, GCC_GPU_BCR 7284, the critical CBCR list (0x71004 among them) 7444-7453.
_add('GCC_GPU_BCR', 'gcc', 0x71000, '', 'LNX gcc-x1e80100.c:7284', 'reset: never touched', gate='never')
_add('GCC_GPU_CFG_AHB_CBCR', 'gcc', 0x71004, 'r', 'LNX gcc-x1e80100.c:7451', 'critical CBCR: Linux keeps it enabled', halt='HALT')
_add('GCC_QMIP_GPU_AHB_CBCR', 'gcc', 0x71008, 'r', 'LNX gcc-x1e80100.c:4260-4272', halt='HALT_VOTED')
_add('GCC_GPU_MEMNOC_GFX_CBCR', 'gcc', 0x71010, 'rw', 'LNX gcc-x1e80100.c:3094-3107', 'the hamoa gmu "memnoc" and adreno_smmu "bus" clock',
     halt='HALT_VOTED')
_add('GCC_GPU_SNOC_DVM_GFX_CBCR', 'gcc', 0x71018, 'r', 'LNX gcc-x1e80100.c:3109-3121', 'the adreno_smmu "iface" clock: read only here',
     halt='HALT')
_add('GCC_DDRSS_GPU_AXI_CBCR', 'gcc', 0x7115c, 'rw', 'LNX gcc-x1e80100.c:2975-2988', 'the hamoa gmu "axi" clock', halt='HALT_SKIP')
_add('GCC_PROC_VOTE_ENA', 'gcc', 0x52000, 'r', 'LNX gcc-x1e80100.c:3060-3092',
     'bit 15 gcc_gpu_gpll0_cph_clk_src, bit 16 its div (both HALT_DELAY): the shared vote register, read only here')

# GPUCC. LNX gpucc-x1e80100.c: AHB 257, CX_GMU 311, CXO_AON 329, CXO 347, GX_GMU 414, HUB_AON 445, HUB_CX_INT 463,
# MEMNOC_GFX 481, SLEEP 520, GMU RCG 182, HUB RCG 197, XO RCG 212, CX GDSC 533-543, GX GDSC 546-557; CFG word = gdscr + 4
# (gdsc.c:35).
_add('GPU_CC_CX_GDSCR', 'gpucc', 0x9108, 'rw', 'LNX gpucc-x1e80100.c:533-543', 'flags VOTABLE | RETAIN_FF_ENABLE; waits en_rest 2, en_few 2, clk_dis f')
_add('GPU_CC_CX_CFG_GDSCR', 'gpucc', 0x910c, 'r', 'LNX gdsc.c:35 + gpucc-x1e80100.c:533')
_add('GPU_CC_CX_GDS_HW_CTRL', 'gpucc', 0x953c, 'r', 'LNX gpucc-x1e80100.c:534; gdsc.c:60-82', 'bit 31 is the CX GDSC power status (gds_hw_ctrl is set, POLL_CFG_GDSCR is not)')
_add('GPU_CC_GX_GDSCR', 'gpucc', 0x905c, 'r', 'LNX gpucc-x1e80100.c:546-557',
     'flags CLAMP_IO | AON_RESET | SW_RESET | POLL_CFG_GDSCR: the GMU owns it; no stage writes it')
_add('GPU_CC_GX_CFG_GDSCR', 'gpucc', 0x9060, 'r', 'LNX gdsc.c:35 + gpucc-x1e80100.c:546')
_add('GPU_CC_GX_CLAMP_IO_CTRL', 'gpucc', 0x9504, 'r', 'LNX gpucc-x1e80100.c:547')
for _n, _o, _l, _h in (('AHB', 0x911c, 257, 'HALT_VOTED'), ('CX_GMU', 0x913c, 311, 'HALT_VOTED'),
                       ('CXO_AON', 0x9004, 329, 'HALT_VOTED'), ('CXO', 0x9144, 347, 'HALT'),
                       ('DEMET', 0x900c, 364, 'HALT'), ('HLOS1_VOTE_GPU_SMMU', 0x7000, 400, 'HALT_VOTED'),
                       ('GX_GMU', 0x90bc, 414, 'HALT'), ('HUB_AON', 0x93e8, 445, 'HALT'),
                       ('HUB_CX_INT', 0x9148, 463, 'HALT_VOTED'), ('MEMNOC_GFX', 0x9150, 481, 'HALT_VOTED'),
                       ('SLEEP', 0x9134, 520, 'HALT_VOTED')):
    _add(f'GPU_CC_{_n}_CBCR', 'gpucc', _o, 'rw' if _n in ('AHB', 'CX_GMU', 'CXO', 'HUB_CX_INT', 'DEMET') else 'r',
         f'LNX gpucc-x1e80100.c:{_l}', halt=_h)
for _n, _o, _l in (('GMU', 0x9318, 182), ('HUB', 0x93ec, 197), ('XO', 0x9010, 212)):
    _add(f'GPU_CC_{_n}_RCG_CMD', 'gpucc', _o, 'rw' if _n != 'XO' else 'r', f'LNX gpucc-x1e80100.c:{_l} + clk-rcg2.c:26-39')
    _add(f'GPU_CC_{_n}_RCG_CFG', 'gpucc', _o + 4, 'rw' if _n != 'XO' else 'r', f'LNX gpucc-x1e80100.c:{_l} + clk-rcg2.c:35-39')

# CX_MISC (behind the CX GDSC). MESA a6xx.xml:5128: CX_MISC_TCM_RET_CNTL dword 0x39 (A7XX and later); a6xx_gmu.c:964, 1364.
_add('CX_MISC_TCM_RET_CNTL', 'cx_misc', 0x39 * 4, 'rw', 'MESA a6xx.xml:5128; LNX a6xx_gmu.c:964,1364',
     'a7xx writes 1 to keep the GMU TCM (S3); a cold boot reads it as not 1 (the warm-boot test)')

# GMU window (LNX registers/adreno/a6xx_gmu.xml, offsets in dwords from the GPU base).
_gmu('GMU_CM3_SYSRESET', 0x1f800, 'rw', 'LNX a6xx_gmu.xml:64', 'bit 0: the GMU core held in reset')
_gmu('GMU_CM3_BOOT_CONFIG', 0x1f801, 'rw', 'LNX a6xx_gmu.xml:65; a6xx_gmu.c:984', 'written 2 before the start')
_gmu('GMU_CM3_FW_BUSY', 0x1f81a, 'r', 'LNX a6xx_gmu.xml:66')
_gmu('GMU_CM3_FW_INIT_RESULT', 0x1f81c, 'rw', 'LNX a6xx_gmu.xml:67; a6xx_gmu.c:983', 'cleared before the start, then polled (a6xx_gmu.c:304-340)')
_gmu('GMU_CM3_CFG', 0x1f82d, 'rw', 'LNX a6xx_gmu.xml:68; a6xx_gmu.c:1006-1010')
_gmu('GMU_CM3_ITCM_START', 0x1b400, 'rw', 'LNX a6xx_gmu.xml:45', 'firmware load window; the image comes from the descriptor', count=1)
_gmu('GMU_CM3_DTCM_START', 0x1c400, 'rw', 'LNX a6xx_gmu.xml:46')
_gmu('GMU_ICACHE_CONFIG', 0x1f400, 'rw', 'LNX a6xx_gmu.xml:60; a6xx_gmu.c:821-823', 'written 1 (a7xx stops after these three, a6xx_gmu.c:826-827)')
_gmu('GMU_DCACHE_CONFIG', 0x1f401, 'rw', 'LNX a6xx_gmu.xml:61; a6xx_gmu.c:821-823')
_gmu('GMU_SYS_BUS_CONFIG', 0x1f40f, 'rw', 'LNX a6xx_gmu.xml:62; a6xx_gmu.c:821-823')
_gmu('GMU_SPTPRAC_PWR_CLK_STATUS', 0x1f8d0, 'r', 'LNX a6xx_gmu.xml:108 (A7XX)', 'the a7xx GX-on test (STUDY 2.3, a6xx_gmu.c:121)')
_gmu('GPU_GMU_CX_GMU_CX_FAL_INTF', 0x1f8f0, 'rw', 'LNX a6xx_gmu.xml:135; a6xx_gmu.c:953-960', 'FAL10 veto, written 1')
_gmu('GPU_GMU_CX_GMU_CX_FALNEXT_INTF', 0x1f8f1, 'rw', 'LNX a6xx_gmu.xml:137; a6xx_gmu.c:953-960', 'FAL10 veto, written 1')
_gmu('GMU_AHB_FENCE_RANGE_0', 0x23b11, 'rw', 'LNX a6xx_gmu.xml:237; a6xx_gmu.c:990-1003', 'a7xx: bit 31, upper 0x32 << 18, lower 0x8a0')
_gmu('GMU_AHB_FENCE_STATUS', 0x23b13, 'r', 'LNX a6xx_gmu.xml:231')
_gmu('GMU_GENERAL_8', 0x1f9cd, 'rw', 'LNX a6xx_gmu.xml:183 (A7XX)', 'log buffer address and size word, a6xx_gmu.c:1032-1036')
_gmu('GMU_GENERAL_9', 0x1f9ce, 'rw', 'LNX a6xx_gmu.xml:184 (A7XX)', 'log write index, zeroed while the core is in reset (a6xx_gmu.c:325-329)')
_gmu('GMU_GENERAL_10', 0x1f9cf, 'rw', 'LNX a6xx_gmu.xml:185 (A7XX)', 'GMU chip-id word, expected 0x7050001 (STUDY 1.1)')
_gmu('GMU_HFI_QTBL_INFO', 0x1f984, 'rw', 'LNX a6xx_gmu.xml:158; a6xx_gmu.c:987-988', 'written before the start')
_gmu('GMU_HFI_QTBL_ADDR', 0x1f985, 'rw', 'LNX a6xx_gmu.xml:159; a6xx_gmu.c:987-988', 'written before the start')
_gmu('GMU_HFI_CTRL_STATUS', 0x1f980, 'r', 'LNX a6xx_gmu.xml:154', gate='gmu_up')
_gmu('GMU_HFI_CTRL_INIT', 0x1f986, 'rw', 'LNX a6xx_gmu.xml:160; a6xx_gmu.c:346-358', gate='gmu_up')
_gmu('GMU_GMU2HOST_INTR_INFO', 0x1f992, 'r', 'LNX a6xx_gmu.xml:163', gate='gmu_up')
_gmu('GMU_GMU2HOST_INTR_CLR', 0x1f991, 'rw', 'LNX a6xx_gmu.xml:162', gate='gmu_up')
_gmu('GMU_HOST2GMU_INTR_SET', 0x1f994, 'rw', 'LNX a6xx_gmu.xml:168', gate='gmu_up')
_gmu('GMU_RSCC_CONTROL_REQ', 0x23b07, 'rw', 'LNX a6xx_gmu.xml:235', 'out-of-band requests (GX power) go through the GMU, never through GPUCC', gate='gmu_up')
_gmu('GMU_RSCC_CONTROL_ACK', 0x23b08, 'r', 'LNX a6xx_gmu.xml:236', gate='gmu_up')

# RSCC (rscc window, dword offsets from its base, LNX a6xx_gmu.xml:244-268). The a7xx second spin adds 4 dwords
# (a6xx_gmu.c:1128-1134, seqmem_off).
_add('RSCC_RSC_STATUS0_DRV0', 'rscc', 0x0004 * 4, 'r', 'LNX a6xx_gmu.xml:244')
_add('RSCC_SEQ_BUSY_DRV0', 'rscc', 0x0101 * 4, 'r', 'LNX a6xx_gmu.xml:256')
_add('RSCC_PDC_SEQ_START_ADDR', 'rscc', 0x0008 * 4, 'r', 'LNX a6xx_gmu.xml:245', 'read-back of what the boot firmware left; S2 only if the descriptor lists every word')
_TCS = (0x0346, 0x03ee, 0x0496, 0x053e, 0x05e6, 0x068e, 0x0736, 0x07de, 0x0886, 0x092e)
for _i, _o in enumerate(_TCS):
    _add(f'RSCC_TCS{_i}_DRV0_STATUS', 'rscc', (_o + 4) * 4, 'r', f'LNX a6xx_gmu.xml:{259 + _i}; a6xx_gmu.c:1128-1134',
         'bit 0 set when no RPMh vote is outstanding; +4 dwords on the a7xx second spin')

# SMMU (ARM SMMU global space; LNX arm-smmu.h:27-86). The GPU SMMU is an arm,mmu-500-compatible node (STUDY 2.4).
for _n, _o, _l in (('SCR0', 0x0, 27), ('ID0', 0x20, 45), ('ID1', 0x24, 59), ('ID2', 0x28, 65), ('ID7', 0x3c, 79), ('SGFSR', 0x48, 83)):
    _add(f'SMMU_{_n}', 'smmu', _o, 'r', f'LNX arm-smmu.h:{_l}')

# GX (RBBM, CP): a7xx dword offsets from the GPU base, read in the pinned Mesa a6xx.xml (variants A6XX-A7XX; the CP_RB_* and
# SECVID ones carry no variant). Only after gx_on.
for _n, _d, _l in (('RBBM_STATUS', 0x210, 553), ('RBBM_INT_0_STATUS', 0x201, 551), ('CP_SQE_CNTL', 0x808, 162),
                   ('CP_INTERRUPT_STATUS', 0x823, 175), ('CP_HW_FAULT', 0x821, 174), ('RBBM_GBIF_HALT', 0x016, 783),
                   ('RBBM_GBIF_HALT_ACK', 0x017, 785)):
    _add(f'GPU_{_n}', 'gpu', _d * 4, 'rw' if _n in ('CP_SQE_CNTL', 'RBBM_GBIF_HALT') else 'r', f'MESA a6xx.xml:{_l}; STUDY 2.1',
         gate='gx_on', domain='GX')
for _n, _d, _l in (('CP_RB_CNTL', 0x802, 148), ('CP_RB_RPTR', 0x806, 151), ('CP_RB_WPTR', 0x807, 152)):
    _add(f'GPU_{_n}', 'gpu', _d * 4, 'rw', f'MESA a6xx.xml:{_l}; STUDY 2.1', gate='gx_on', domain='GX')
# RBBM_SECVID_TRUST_CNTL 0xf400 is the same in both generations (STUDY 2.1). A refused write must stop the sequence.
_add('GPU_RBBM_SECVID_TRUST_CNTL', 'gpu', 0xf400 * 4, 'rw', 'MESA a6xx.xml:774; STUDY 2.1, 2.7', gate='gx_on', domain='GX')


def check_table() -> None:
    """Self-consistency of the table itself (the test runs it)."""
    seen = {}
    for reg in REGS.values():
        assert reg.domain in DOMAINS and reg.gate in GATES, reg.name
        assert reg.block in BLOCK_RULES, reg.name
        assert set(reg.access) <= {'r', 'w'} or reg.access == 'rw', reg.name
        assert reg.evidence, f'{reg.name}: every register carries its source'
        if reg.off is not None:
            assert reg.off % 4 == 0 and reg.off >= 0, reg.name
            window = reg.window or reg.block
            lo = BOARD_PUBLIC[window][0] - BOARD_PUBLIC[reg.block][0]
            assert lo <= reg.off and reg.off + reg.stride * reg.count <= lo + BOARD_PUBLIC[window][1], \
                f'{reg.name} outside its {window} window'
            key = (reg.block, reg.off)
            assert key not in seen, f'{reg.name} and {seen[key]} share an address'
            seen[key] = reg.name
        if reg.domain == 'GX':
            assert reg.gate == 'gx_on', f'{reg.name}: a GX register is gated by gx_on'
        if reg.gate == 'gx_on':
            assert reg.domain == 'GX', f'{reg.name}: only GX registers use gx_on'
