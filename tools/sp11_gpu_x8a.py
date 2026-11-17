#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Adreno X1-85, gate X8a (and the first step of X8b): host model of the Surface Pro 11 GPU power-up through q1n1.

  python3 tools/sp11_gpu_x8a.py plan [--board board.json]     # the stages, registers, sources and stop rules; touches nothing
  python3 tools/sp11_gpu_x8a.py board [--board board.json]     # the resolved board descriptor and what is still null

HOST MODEL ONLY, DEFAULT OFF. Nothing in this module has run on a Surface Pro 11, nothing here authorises a run, and no
other q1n1 tool imports it. It reads and writes no GPU register on any machine unless `run` is given a proxy, and the only
caller that does is tools/test-sp11-gpu-x8a.py with the fake device of tools/sp11_gpu_fake.py; there is deliberately no
command line that connects to hardware. Counterpart of tools/a16gpu.py and tools/a16gpu_stage3.py for the A16. The checked
access path (Session, Board, exit codes) is tools/sp11_gpu_session.py; the register table is tools/sp11_gpu_regs.py.

Stages. Each is one function with its register list, its source and its stop rule; STAGE_PLAN below is the same table as
data, and the test checks the two against each other.

  S0 survey    READ-ONLY. GCC, then GPUCC, then the gate that says whether the CX side is powered, then (only then) the blocks
               behind it. No GX register is read and nothing is written.
  S1 cx-power  GMU RCG parked on XO, CX GDSC on (gdsc_init values, SW_COLLAPSE clear, status poll, RETAIN_FF), then the seven
               clocks of the hamoa GMU node in device-tree order.
  S2 rsc       RPMh quiet check: every RSC TCS idle. It never programs the RSC or the PDC (no cited register list for that yet).
  S3 gmu-start The Linux cold-boot order of a6xx_gmu_fw_start for a7xx: FAL veto, TCM retention, image load, init result clear,
               HFI table in DRAM and its registers, fence range, M3 config, chip-id and log words, bus and cache config, reset
               release, firmware init result. Needs a descriptor with the image and every value below.
  S4 hfi       HFI start, then the descriptor's messages (the first is the lowest-level performance vote), each acknowledged.
  S5 gx-oob    GX power through the GMU's out-of-band request only, then the GMU's own status says GX on.
  S6 ring      (X8b) descriptor-supplied SECVID, SQE and ring steps and bounded copies of at most 1 MiB. Refuses without every value.
  S7 quiesce   Reverse order, and never ahead of the GMU's own status saying GX is off; stops at its first failure.

NOT MODELLED, and each is a reason the first S1 or S3 may stop on the unit (STUDY 2.3, UNIMPLEMENTED unless stated):
  the GMU RCG rate (Linux sets 200 MHz, which the table rounds to 220 MHz from GPU_CC_PLL1; S1 leaves it parked on XO),
  GPU_CC_PLL1 and the GCC GPLL0 votes (S1 refuses a hub RCG whose parent is not ready), the RSC wake handshake and the RSC/PDC
  programming (a6xx_rpmh_start, a6xx_gmu_rpmh_init), the GMU-stream SMMU context, the a7xx GBIF CX table (a descriptor list that
  must be empty), the GMU interrupt masks, the HFI messages beyond the descriptor's list, thermal sensing (the cycle.py guard).

A value no cited source gives is null in the board descriptor and the stage that needs it refuses before it writes anything.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
import sp11_gpu_regs as R  # noqa: E402
from sp11_gpu_session import (BOARD_SCHEMA, POLL_BUDGET_S, POLL_LIMITS, AbortStop, Arena, Board, GuardMissing, LinkLost,  # noqa: E402,F401
                              PollTimeout, Refused, SErrorStop, Session, Stop, as_int, hx, load_board, q1n1proxy, serror_json)

MAX_COPY_BYTES = 1 << 20                         # AGENTS.md rule 5: a 4 MiB CP_MEMCPY hung the A16 GPU
GMU_CHIPID_WORD = 0x07050001                     # STUDY 1.1: the X1-85 entry's gmu_chipid (LNX a7xx_catalog.c:396)
GMU_CM3_CFG_VALUE = 0x4052                       # LNX a6xx_gmu.c:1010
GMU_BOOT_CONFIG_VALUE = 0x2                      # LNX a6xx_gmu.c:984
GMU_FENCE_RANGE_0_VALUE = 1 << 31 | 0x32 << 18 | 0x8a0      # LNX a6xx_gmu.c:990-1003 (a7xx)
GMU_DTCM_VERSION_DWORD = 0xff8                   # LNX a6xx_gmu.c:311
GMU_FW_START_RULES = ((0x20010004, 0xffffffff, 0xbabeface), (None, 0x1ff, 0x100))   # LNX a6xx_gmu.c:311-318, 335-336
HFI_QTBL_INFO_VALUE = 1                          # LNX a6xx_gmu.c:988
HFI_QUEUES, HFI_TABLE_DWORDS, HFI_QHDR_DWORDS, HFI_QUEUE_BYTES = 3, 6, 12, 4096    # LNX a6xx_hfi.h:7-30, a6xx_hfi.c:1155-1198
HFI_F2H_MSG_ACK = 126                            # LNX a6xx_hfi.h:70
HFI_PAD = 0xfafafafa                             # LNX a6xx_hfi.c:92-96
OOB_GPU_SET_REQUEST_BIT, OOB_GPU_SET_ACK_BIT, OOB_GPU_SET_CLEAR_BIT = 30, 31, 31   # LNX a6xx_gmu.c:372-377 (non-legacy GMU)
GMU2HOST_MSGQ = 1                                # LNX a6xx_gmu.xml:164 (MSGQ, bit 0)

# The clocks of the hamoa GMU node, in device-tree order (hamoa.dtsi:4184-4197): ahb, gmu, cxo, axi, memnoc, hub, demet.
GMU_CLOCKS = ('GPU_CC_AHB_CBCR', 'GPU_CC_CX_GMU_CBCR', 'GPU_CC_CXO_CBCR', 'GCC_DDRSS_GPU_AXI_CBCR', 'GCC_GPU_MEMNOC_GFX_CBCR',
              'GPU_CC_HUB_CX_INT_CBCR', 'GPU_CC_DEMET_CBCR')
# The clocks of the hamoa adreno_smmu node (hamoa.dtsi:4268-4276): hlos, bus, iface, ahb.
SMMU_CLOCKS = ('GPU_CC_HLOS1_VOTE_GPU_SMMU_CBCR', 'GCC_GPU_MEMNOC_GFX_CBCR', 'GCC_GPU_SNOC_DVM_GFX_CBCR', 'GPU_CC_AHB_CBCR')
GATE_INPUTS = ('GPU_CC_CX_GDSCR', 'GPU_CC_CX_GDS_HW_CTRL') + GMU_CLOCKS
GCC_SURVEY = ('GCC_GPU_CFG_AHB_CBCR', 'GCC_QMIP_GPU_AHB_CBCR', 'GCC_GPU_MEMNOC_GFX_CBCR', 'GCC_GPU_SNOC_DVM_GFX_CBCR',
              'GCC_DDRSS_GPU_AXI_CBCR', 'GCC_PROC_VOTE_ENA')
GPUCC_SURVEY = ('GPU_CC_CX_GDSCR', 'GPU_CC_CX_CFG_GDSCR', 'GPU_CC_CX_GDS_HW_CTRL', 'GPU_CC_GX_GDSCR', 'GPU_CC_GX_CFG_GDSCR',
                'GPU_CC_GX_CLAMP_IO_CTRL', 'GPU_CC_AHB_CBCR', 'GPU_CC_CX_GMU_CBCR', 'GPU_CC_CXO_AON_CBCR', 'GPU_CC_CXO_CBCR',
                'GPU_CC_DEMET_CBCR', 'GPU_CC_HLOS1_VOTE_GPU_SMMU_CBCR', 'GPU_CC_GX_GMU_CBCR', 'GPU_CC_HUB_AON_CBCR',
                'GPU_CC_HUB_CX_INT_CBCR', 'GPU_CC_MEMNOC_GFX_CBCR', 'GPU_CC_SLEEP_CBCR', 'GPU_CC_GMU_RCG_CMD',
                'GPU_CC_GMU_RCG_CFG', 'GPU_CC_HUB_RCG_CMD', 'GPU_CC_HUB_RCG_CFG', 'GPU_CC_XO_RCG_CMD')
TCS_STATUS = tuple(f'RSCC_TCS{i}_DRV0_STATUS' for i in range(10))
CX_SURVEY = ('CX_MISC_TCM_RET_CNTL', 'GMU_CM3_SYSRESET', 'GMU_CM3_FW_INIT_RESULT', 'GMU_CM3_FW_BUSY', 'GMU_CM3_CFG',
             'GMU_SPTPRAC_PWR_CLK_STATUS', 'GMU_AHB_FENCE_STATUS', 'RSCC_RSC_STATUS0_DRV0', 'RSCC_SEQ_BUSY_DRV0',
             'RSCC_PDC_SEQ_START_ADDR') + TCS_STATUS
SMMU_SURVEY = ('SMMU_SCR0', 'SMMU_ID0', 'SMMU_ID1', 'SMMU_ID2', 'SMMU_ID7', 'SMMU_SGFSR')


# --- pure helpers ----------------------------------------------------------------------------------------------------------
def running(reg, value):
    """clk_branch state. HALT and HALT_VOTED branches run when enabled with CLK_OFF clear; HALT_DELAY and HALT_SKIP have no
    status bit, so enabled is all that can be said; a GCC branch in hardware-gated mode is not judged by CLK_OFF (A16 rule)."""
    if reg.block == 'gcc' and value & R.CBCR_HW_CTL:
        return True
    if not value & R.CBCR_ENABLE:
        return False
    return not value & R.CBCR_CLK_OFF if reg.halt in ('HALT', 'HALT_VOTED') else True


def gx_state(status):
    """LNX a6xx_gmu.c:95-118 for A7XX: GX is on when neither GX_HM_GDSC_POWER_OFF (bit 0) nor GX_HM_CLK_OFF (bit 1) is set."""
    return 'off' if status & 0x3 else 'on'


def cx_gate(values):
    """The CX gate from the reads: on, off, partial (GDSC on, a GMU clock not running) or hw_control (the GMU or RSC may
    collapse the GDSC at any time: no CX reads). The CX GDSC status is bit 31 of GDS_HW_CTRL (LNX gdsc.c:61-91)."""
    gdscr = values['GPU_CC_CX_GDSCR']
    if gdscr & R.GDSC_HW_CONTROL:
        return 'hw_control'
    if gdscr & R.GDSC_SW_COLLAPSE or not values['GPU_CC_CX_GDS_HW_CTRL'] & R.GDSC_PWR_ON:
        return 'off'
    return 'on' if all(running(R.REGS[n], values[n]) for n in GMU_CLOCKS) else 'partial'


def smmu_gate(values):
    return cx_gate(values) == 'on' and all(running(R.REGS[n], values[n]) for n in SMMU_CLOCKS)


def hub_source_ready(source, gcc_vote):
    """The hub RCG's parent must be running before its branches are enabled: XO always, GPLL0 only when its GCC vote is set.
    GPU_CC_PLL1 (source 3) is never assumed ready."""
    return (source == R.RCG_SRC_XO or (source == R.RCG_SRC_GPLL0 and bool(gcc_vote & R.GCC_VOTE_GPLL0))
            or (source == R.RCG_SRC_GPLL0_DIV and bool(gcc_vote & R.GCC_VOTE_GPLL0_DIV)))


def fw_start_rule(version_word):
    """(mask, value) the GMU init result must show: LNX a6xx_gmu.c:311-318, chosen by the firmware version word at DTCM+0xff8."""
    for limit, mask, value in GMU_FW_START_RULES:
        if limit is None or version_word <= limit:
            return mask, value


def gdsc_report(gdscr, status, cfg=None):
    report = {'sw_collapse': bool(gdscr & R.GDSC_SW_COLLAPSE), 'hw_control': bool(gdscr & R.GDSC_HW_CONTROL),
              'retain_ff': bool(gdscr & R.GDSC_RETAIN_FF)}
    if cfg is None:
        report['on'] = bool(status & R.GDSC_PWR_ON)
    else:                                           # the GX GDSC polls CFG_GDSCR (POLL_CFG_GDSCR)
        report['on'], report['off'] = bool(cfg & R.GDSC_POWER_UP_COMPLETE), bool(cfg & R.GDSC_POWER_DOWN_COMPLETE)
    return report


def hfi_addresses(arena):
    """iova of the table, the two queue headers and the two data areas (LNX a6xx_hfi.c:1155-1198: data at 4 KiB steps)."""
    qhdr = lambda i: arena.iova + 4 * (HFI_TABLE_DWORDS + HFI_QHDR_DWORDS * i)
    return {'table': arena.iova, 'cmd_header': qhdr(0), 'rsp_header': qhdr(1),
            'cmd_data': arena.iova + HFI_QUEUE_BYTES, 'rsp_data': arena.iova + 2 * HFI_QUEUE_BYTES}


def hfi_table_words(arena):
    """The table header and the three queue headers as Linux's a6xx_hfi_init writes them (non-legacy ids 0, 1, 2).
    The table's size field holds a byte count, as the code stores it (the struct comment says dwords)."""
    words = [0, 4 * (HFI_TABLE_DWORDS + HFI_QUEUES * HFI_QHDR_DWORDS), HFI_TABLE_DWORDS, HFI_QHDR_DWORDS, HFI_QUEUES, HFI_QUEUES]
    for i in range(HFI_QUEUES):
        words += [1, arena.iova + HFI_QUEUE_BYTES * (i + 1), 10 << 8 | i, HFI_QUEUE_BYTES >> 2, 0, 0, 1, 1, 1, 0, 0, 0]
    return words


# --- stages ----------------------------------------------------------------------------------------------------------------
def stage_survey(s, out):
    """S0. Source: the A16 stage-1 pattern (docs/A16-ADRENO-STAGE1.md) with the X1E80100 registers of sp11_gpu_regs.
    Stop rule: GCC_GPU_CFG_AHB off ends the survey before any GPUCC read; a CX gate that is not `on` ends it before any read
    behind the GDSC; the SMMU is read only when its own four clocks run; a fault stops it. Writes nothing; no GX register."""
    s.step = 'S0.R2'
    values = {n: s.rd(n) for n in GCC_SURVEY}
    s.survey = values
    out['gcc'] = {n: hx(v) for n, v in values.items()}
    if not running(R.REGS['GCC_GPU_CFG_AHB_CBCR'], values['GCC_GPU_CFG_AHB_CBCR']):
        raise Stop('S0.R2', 'GCC_GPU_CFG_AHB is off: GPUCC is not reachable, nothing behind it is read', gcc=out['gcc'])
    s.prove('gcc_ahb', 'GCC_GPU_CFG_AHB_CBCR running')
    s.step = 'S0.R3'
    values.update({n: s.rd(n) for n in GPUCC_SURVEY})
    out['gpucc'] = {n: hx(values[n]) for n in GPUCC_SURVEY}
    out['cx_gdsc'] = gdsc_report(values['GPU_CC_CX_GDSCR'], values['GPU_CC_CX_GDS_HW_CTRL'])
    out['gx_gdsc'] = gdsc_report(values['GPU_CC_GX_GDSCR'], 0, values['GPU_CC_GX_CFG_GDSCR'])
    s.step = 'S0.R4'
    out['cx_gate'] = cx_gate(values)
    if out['cx_gate'] != 'on':
        out['note'] = f'CX gate {out["cx_gate"]}: nothing behind the CX GDSC was read'
        return out
    s.prove('cx_on', 'CX GDSC status on, not under HW control, the seven GMU-node clocks running')
    s.step = 'S0.R5'
    cx = {n: s.rd(n) for n in CX_SURVEY}
    values.update(cx)
    out['cx'] = {n: hx(v) for n, v in cx.items()}
    out['gx_by_gmu'] = gx_state(cx['GMU_SPTPRAC_PWR_CLK_STATUS'])
    out['tcm_retained'] = cx['CX_MISC_TCM_RET_CNTL'] == 1
    if smmu_gate(values):
        s.prove('cx_smmu', 'cx_on and the four adreno_smmu clocks running')
        out['smmu'] = {n: hx(s.rd(n)) for n in SMMU_SURVEY}
    else:
        out['smmu'] = 'skipped: the adreno_smmu clocks are not all running; the survey enables nothing'
    return out


def park_rcg(s, base):
    """clk_rcg2_shared_disable (LNX clk-rcg2.c:1453-1479): force the root on, CFG = safe source (XO), UPDATE, release. The old
    parent is still running for the switch. Returns what it did. A poll timeout releases the force-enable and re-raises."""
    cmd, cfg = f'GPU_CC_{base}_RCG_CMD', f'GPU_CC_{base}_RCG_CFG'
    old = s.rd(cfg)
    if old & R.RCG_SRC_SEL_MASK == R.RCG_SRC_XO << 8 and old & 0xff in (0, 1):     # the A16 is_xo rule: divider 0 or 1
        return 'already on XO'
    s.update(cmd, R.RCG_ROOT_EN, R.RCG_ROOT_EN)
    try:
        s.poll(cmd, R.RCG_ROOT_OFF, 0, 'rcg')              # clk_rcg2_set_force_enable waits for the root to turn on
        s.wr(cfg, R.RCG_SRC_XO << 8)
        s.update(cmd, R.RCG_UPDATE, R.RCG_UPDATE)
        s.poll(cmd, R.RCG_UPDATE, 0, 'rcg')                # update_config waits for UPDATE to clear
    except PollTimeout as timeout:
        try:
            s.update(cmd, R.RCG_ROOT_EN, 0)
            timeout.detail['root_en_released'] = True
        except Stop as release:
            timeout.detail['root_en_released'] = f'failed: {release.reason}'
        raise
    s.update(cmd, R.RCG_ROOT_EN, 0)
    return f'parked on XO from CFG {hx(old)}'


def branch_on(s, name):
    """clk_branch enable: set the enable bit, then wait as halt_check says (INFERRED from clk-branch.h:30-36, clk-branch.c is
    not in the pinned set): HALT and HALT_VOTED poll CLK_OFF clear, HALT_DELAY waits 10 us, HALT_SKIP and GCC hardware-gated
    branches wait for nothing."""
    reg = R.REGS[name]
    old = s.rd(name)
    if not old & R.CBCR_ENABLE:
        s.wr(name, old | R.CBCR_ENABLE)
        s.owned.append(name)
    if reg.block == 'gcc' and old & R.CBCR_HW_CTL:
        return
    if reg.halt in ('HALT', 'HALT_VOTED'):
        s.poll(name, R.CBCR_CLK_OFF, 0, 'branch')
    elif reg.halt == 'HALT_DELAY':
        s.udelay(10)


def branch_off(s, name):
    """The reverse: clear the enable bit; a plain HALT branch is then polled for CLK_OFF, a voted or delay branch waits 10 us."""
    reg = R.REGS[name]
    value = s.update(name, R.CBCR_ENABLE, 0)
    if reg.block == 'gcc' and value & R.CBCR_HW_CTL:
        return
    if reg.halt == 'HALT':
        s.poll(name, R.CBCR_CLK_OFF, R.CBCR_CLK_OFF, 'branch')
    else:
        s.udelay(10)


def stage_cx_power(s, out):
    """S1. Source: LNX clk-rcg2.c:1453-1479 and 1519-1546 (the shared GMU RCG is parked before its GDSC can be enabled, or the
    GDSC can wedge), gdsc.c:429-471 (gdsc_init: HW control and SW override off, the wait values of gpucc-x1e80100.c:536-538),
    gdsc.c:147-195 and 285-341 (clear SW_COLLAPSE, 1 us, poll the status, 1 us, RETAIN_FF), hamoa.dtsi:4184-4197 (the clocks
    in device-tree order). Stop rule: HW control is never taken; a hub RCG whose parent is not ready, a poll past its bound, or
    a CX gate that is not `on` afterwards stops the run (S7 reverses what S1 turned on)."""
    s.step = 'S1'
    if 'gcc_ahb' not in s.proven or 'cx_gate' not in out:
        raise Refused('S1 needs the survey of this session first (gate gcc_ahb)')
    gate = out['cx_gate']
    if gate == 'on':
        out['s1'] = 'CX already on: nothing written'
        return out
    if gate == 'hw_control':
        raise Stop('S1', 'CX GDSC is under HW control (GDSCR bit 1): someone else may own it; S1 never takes HW control')
    source = (s.survey['GPU_CC_HUB_RCG_CFG'] & R.RCG_SRC_SEL_MASK) >> 8
    if not hub_source_ready(source, s.survey['GCC_PROC_VOTE_ENA']):
        raise Stop('S1', f'the hub RCG is sourced from parent {source} and that parent is not known to run (no GCC vote, or a '
                         'GPU_CC PLL): enabling its branches could wedge the GDSC; the vote and PLL sequences are not modelled')
    s.owned_gdsc = gate == 'off'                 # a GDSC that was already on (clocks missing) is not ours to collapse
    out['rcg_park'] = park_rcg(s, 'GMU')
    s.update('GPU_CC_CX_GDSCR', R.GDSC_HW_CONTROL | R.GDSC_SW_OVERRIDE | R.GDSC_WAITS_MASK, R.CX_GDSC_WAITS)
    s.update('GPU_CC_CX_GDSCR', R.GDSC_SW_COLLAPSE, 0)
    s.udelay(1)
    s.poll('GPU_CC_CX_GDS_HW_CTRL', R.GDSC_PWR_ON, R.GDSC_PWR_ON, 'gdsc')
    s.udelay(1)
    s.update('GPU_CC_CX_GDSCR', R.GDSC_RETAIN_FF, R.GDSC_RETAIN_FF)
    for name in GMU_CLOCKS:
        branch_on(s, name)
    after = {n: s.rd(n) for n in GATE_INPUTS}
    state = cx_gate(after)
    out['cx_gate'] = state
    if state != 'on':
        raise Stop('S1', f'CX gate is {state} after the power-up: not proceeding', cx_gdscr=hx(after['GPU_CC_CX_GDSCR']),
                   cx_status=hx(after['GPU_CC_CX_GDS_HW_CTRL']))
    s.survey.update(after)
    s.prove('cx_on', 'S1: CX GDSC on, the seven GMU-node clocks running')
    out['s1'] = {'enabled': list(s.owned)}
    return out


def stage_rsc(s, out):
    """S2. Source: LNX a6xx_gmu.c:1099-1134 (no RPMh vote outstanding: every TCS status bit 0 set). Reads only: the RSC and PDC
    programming of STUDY 2.3 has no cited register list here, so this stage never writes. Stop rule: a TCS that stays busy, or
    a state the operator has not reviewed (descriptor rsc.reviewed), stops the run."""
    s.step = 'S2'
    if 'cx_on' not in s.proven:
        raise Refused('S2 needs the CX gate (cx_on)')
    out['rsc'] = {n: hx(s.rd(n)) for n in ('RSCC_RSC_STATUS0_DRV0', 'RSCC_SEQ_BUSY_DRV0', 'RSCC_PDC_SEQ_START_ADDR')}
    for name in TCS_STATUS:
        s.poll(name, 1, 1, 'rsc')
    if s.board.data.get('rsc', {}).get('reviewed') is not True:
        raise Stop('S2', 'the RSC and PDC state has not been reviewed (descriptor rsc.reviewed is not true); programming is not part of this tool')
    out['rsc_quiet'] = True
    return out


def verify_image(s, name):
    """The image the descriptor names: size and SHA-256 are checked on the host before any write (a wrong GMU image is a hung GMU)."""
    spec = s.board.need(f'firmware.{name}')
    path, want, size = spec.get('path'), spec.get('sha256'), spec.get('size')
    if not path or not want or not size:
        raise Refused(f'board descriptor: firmware.{name} needs path, sha256 and size')
    data = Path(path).read_bytes()
    if len(data) != size or hashlib.sha256(data).hexdigest() != want:
        raise Refused(f'firmware.{name}: {Path(path).name} does not match the descriptor size and SHA-256; nothing is written')
    return data


def plan_segments(s, image):
    """The GMU image's segments as the descriptor lists them (no format is assumed; Linux's a6xx_gmu_fw_load block headers are
    for the operator's tool to turn into this list), checked against the image and the TCM windows before any write."""
    plan = []
    itcm = as_int(s.board.need('firmware.gmu.itcm_size'), 'itcm_size')
    dtcm = as_int(s.board.need('firmware.gmu.dtcm_size'), 'dtcm_size')
    for seg in s.board.need('firmware.gmu.segments'):
        if not isinstance(seg, dict):
            raise Refused('firmware.gmu.segments: every segment is an object')
        window = {'itcm': ('GMU_CM3_ITCM_START', itcm), 'dtcm': ('GMU_CM3_DTCM_START', dtcm)}.get(seg.get('window'))
        if window is None:
            raise Refused(f'firmware.gmu.segments: window {seg.get("window")!r} is neither itcm nor dtcm')
        offset, size, source = (as_int(seg.get(k), f'segment.{k}') for k in ('offset', 'size', 'file_offset'))
        if None in (offset, size, source) or offset % 4 or size % 4 or offset + size > window[1] or source + size > len(image):
            raise Refused('firmware.gmu.segments: a segment is null, unaligned, outside its TCM window or past the end of the image')
        plan.append((window[0], offset, image[source:source + size]))
    if not plan:
        raise Refused('firmware.gmu.segments is empty')
    return plan


def stage_gmu_start(s, out):
    """S3. Source: LNX a6xx_gmu.c:953-1058 (a6xx_gmu_fw_start, cold boot), 815-827 (a6xx_gmu_power_config: a7xx stops after the
    three bus and cache words), 304-340 (a6xx_gmu_start), a6xx_hfi.c:1155-1198 (the HFI table). The core is held in reset first
    (not in Linux's order: a deliberate hold). Not done: a6xx_rpmh_start (the RSC wake, only after a sleep), the GBIF CX table.
    Stop rule: a warm GMU (TCM retained), a null value (every one is resolved before the first write), no init result within
    the bound (the core goes back in reset in S7)."""
    s.step = 'S3'
    if not s.allow_writes:
        raise Refused('S3 writes')
    if 'cx_on' not in s.proven:
        raise Refused('S3 needs gate cx_on')
    if out.get('tcm_retained'):
        raise Stop('S3', 'CX_MISC_TCM_RET_CNTL reads 1: Linux would take the warm-boot path (no image load); it is not modelled')
    image = verify_image(s, 'gmu')
    segments = plan_segments(s, image)
    log, table = s.board.arena('dram.gmu_log'), s.board.arena('hfi.arena')
    if table.size < HFI_QUEUE_BYTES * (HFI_QUEUES + 1):
        raise Refused('hfi.arena is smaller than the table plus three 4 KiB queues')
    gbif = s.board.need('gmu.gbif_cx')
    if not isinstance(gbif, list) or gbif:
        raise Refused('gmu.gbif_cx must be an empty list: the X1-85 GBIF CX writes (LNX a6xx_gmu.c:1045-1046) are not in the register '
                      'table; [] states that the operator checked the catalog entry')
    s.allow_dram(table)
    s.wr('GMU_CM3_SYSRESET', 1)
    s.wr('GPU_GMU_CX_GMU_CX_FALNEXT_INTF', 1)
    s.wr('GPU_GMU_CX_GMU_CX_FAL_INTF', 1)
    s.wr('CX_MISC_TCM_RET_CNTL', 1)
    for window, offset, data in segments:
        for i in range(0, len(data), 4):
            s.wr_at_window(window, offset + i, int.from_bytes(data[i:i + 4], 'little'))
    s.wr('GMU_CM3_FW_INIT_RESULT', 0)
    s.wr('GMU_CM3_BOOT_CONFIG', GMU_BOOT_CONFIG_VALUE)
    s.dram_write(table.phys, hfi_table_words(table))
    s.wr('GMU_HFI_QTBL_ADDR', table.iova)
    s.wr('GMU_HFI_QTBL_INFO', HFI_QTBL_INFO_VALUE)
    s.wr('GMU_AHB_FENCE_RANGE_0', GMU_FENCE_RANGE_0_VALUE)
    s.wr('GMU_CM3_CFG', GMU_CM3_CFG_VALUE)
    s.wr('GMU_GENERAL_10', GMU_CHIPID_WORD)
    s.wr('GMU_GENERAL_8', (log.iova & 0xfffff000) | ((log.size // 4096 - 1) & 0xff))
    for name in ('GMU_SYS_BUS_CONFIG', 'GMU_ICACHE_CONFIG', 'GMU_DCACHE_CONFIG'):
        s.wr(name, 1)
    mask, value = fw_start_rule(s.rd_at_window('GMU_CM3_DTCM_START', 4 * GMU_DTCM_VERSION_DWORD))
    s.wr('GMU_CM3_SYSRESET', 1)
    s.wr('GMU_GENERAL_9', 0)
    s.wr('GMU_CM3_SYSRESET', 0)
    s.poll('GMU_CM3_FW_INIT_RESULT', mask, value, 'gmu')
    s.prove('gmu_up', 'GMU firmware init result seen')
    out['gmu_up'] = True
    return out


def queue_write(s, arena, words):
    """a6xx_hfi_queue_write (LNX a6xx_hfi.c:72-110): copy at write_index, pad to a multiple of 4 dwords with 0xfafafafa, publish
    write_index, then ring the doorbell (HOST2GMU_INTR_SET = 1)."""
    addr = hfi_addresses(arena)
    header = arena.phys_of(addr['cmd_header'])
    h = s.dram_read(header, HFI_QHDR_DWORDS)
    size, rd, wr = h[3], h[10], h[11]
    if size == 0 or (rd - wr - 1) % size < len(words):
        raise Stop('S4', 'the HFI command queue is full', dropped=h[5])
    data = arena.phys_of(addr['cmd_data'])
    for i, word in enumerate(words):
        s.dram_write(data + 4 * ((wr + i) % size), [word])
    index = (wr + len(words)) % size
    while index % 4:
        s.dram_write(data + 4 * index, [HFI_PAD])
        index = (index + 1) % size
    s.dram_write(header + 4 * 11, [index])
    s.wr('GMU_HOST2GMU_INTR_SET', 1)


def queue_read(s, arena):
    """One message from the response queue (its size is in its header word), or None when the queue is empty."""
    addr = hfi_addresses(arena)
    header = arena.phys_of(addr['rsp_header'])
    h = s.dram_read(header, HFI_QHDR_DWORDS)
    size, rd, wr = h[3], h[10], h[11]
    if rd == wr:
        return None
    data = arena.phys_of(addr['rsp_data'])
    first = s.dram_read(data + 4 * rd, 1)[0]
    dwords = first >> 8 & 0xff
    if dwords == 0 or dwords > size or dwords > 19:
        raise Stop('S4', f'a response with an impossible size ({dwords} dwords)', header=hx(first))
    words = [s.dram_read(data + 4 * ((rd + i) % size), 1)[0] for i in range(dwords)]
    index = (rd + dwords) % size
    s.dram_write(header + 4 * 10, [(index + (-index % 4)) % size])
    return words


def send_and_wait(s, arena, header, words):
    """Send one message and wait for its acknowledgement. Stricter than Linux (a6xx_hfi.c:150-210 skips unexpected responses and
    keeps waiting): anything but an ACK of exactly this header with error word 0 stops the run."""
    queue_write(s, arena, words)
    for _ in range(POLL_LIMITS['hfi']):
        s.poll('GMU_GMU2HOST_INTR_INFO', GMU2HOST_MSGQ, GMU2HOST_MSGQ, 'hfi')
        s.wr('GMU_GMU2HOST_INTR_CLR', GMU2HOST_MSGQ)
        response = queue_read(s, arena)
        if response is None:
            continue
        if response[0] & 0xff != HFI_F2H_MSG_ACK or len(response) < 3 or response[1] != header:
            raise Stop('S4', f'unexpected response to message {hx(header)}', response=[hx(w) for w in response])
        if response[2] != 0:
            raise Stop('S4', f'message {hx(header)} was refused (error word {hx(response[2])})', response=[hx(w) for w in response])
        return response
    raise PollTimeout('S4', f'no response to message {hx(header)}', header=hx(header))


def stage_hfi(s, out):
    """S4. Source: LNX a6xx_gmu.c:346-358 (a6xx_gmu_hfi_start: CTRL_INIT = 1, poll CTRL_STATUS bit 0), a6xx_hfi.c:213-232 (the
    message header: sequence << 20 | type << 16 | dwords << 8 | id), a6xx_hfi.h:288-296 and a6xx_hfi.c:1000-1012 (the
    GX_BW_PERF_VOTE message: ack type, frequency index, bandwidth index). The messages come from the descriptor
    (hfi.messages: [{id, payload}], the first being the lowest-level vote): Linux's own list (init, version, perf and bandwidth
    tables, test, start) is unit-specific and not reproduced. Stop rule: no acknowledgement, or one that is not an ACK of the
    message with error word 0, stops the run before GX is requested."""
    s.step = 'S4'
    if 'gmu_up' not in s.proven:
        raise Refused('S4 needs the GMU up (gate gmu_up)')
    arena = s.board.arena('hfi.arena')
    messages = s.board.need('hfi.messages')
    if not isinstance(messages, list) or not messages:
        raise Refused('hfi.messages must be a non-empty list')
    plan = []
    for seq, message in enumerate(messages, 1):
        ident, payload = as_int(message.get('id'), 'message.id'), [as_int(w, 'message.payload') for w in message.get('payload') or []]
        if ident is None or ident > 0xff or None in payload or len(payload) + 1 > 0xff:
            raise Refused('hfi.messages: a message needs an id below 256 and an integer payload')
        plan.append(((seq << 20) | ((1 + len(payload)) << 8) | ident, payload))
    s.allow_dram(arena)
    s.wr('GMU_HFI_CTRL_INIT', 1)
    s.poll('GMU_HFI_CTRL_STATUS', 1, 1, 'hfi')
    out['hfi_acks'] = []
    for header, payload in plan:
        response = send_and_wait(s, arena, header, [header] + payload)
        out['hfi_acks'].append({'header': hx(header), 'error': response[2]})
    s.prove('hfi', 'every descriptor message acknowledged')
    out['hfi_ready'] = True
    return out


def stage_gx_oob(s, out):
    """S5. Source: LNX a6xx_gmu.c:372-377 and 406-465 (GPU_SET: request bit 30 in GMU_HOST2GMU_INTR_SET, acknowledge bit 31 in
    GMU_GMU2HOST_INTR_INFO, then clear it) and a6xx_gmu.c:95-118 (the GMU's own GX status). GX is requested only this way, never
    through GPUCC. Stop rule: no acknowledgement, or a GMU status that still says GX off, stops the run; the GX gate is proven
    from the GMU's status word, not from the acknowledgement."""
    s.step = 'S5'
    for gate in ('gmu_up', 'cx_on', 'hfi'):
        if gate not in s.proven:
            raise Refused(f'S5 needs gate {gate}')
    if not s.board.has('thermal.sensor') or not s.board.has('thermal.stop_c'):
        raise Refused('S5 needs the thermal sensor and stop temperature in the descriptor (read by the cycle.py guard, which stays on; '
                      'both UNKNOWN until read)')
    s.oob_requested = True                       # set first: a write that fails may still have started GX
    s.wr('GMU_HOST2GMU_INTR_SET', 1 << OOB_GPU_SET_REQUEST_BIT)
    s.poll('GMU_GMU2HOST_INTR_INFO', 1 << OOB_GPU_SET_ACK_BIT, 1 << OOB_GPU_SET_ACK_BIT, 'oob')
    s.wr('GMU_GMU2HOST_INTR_CLR', 1 << OOB_GPU_SET_ACK_BIT)
    try:
        status = s.poll('GMU_SPTPRAC_PWR_CLK_STATUS', 0x3, 0, 'oob')
    except PollTimeout as timeout:
        raise Stop('S5', f'the GMU acknowledged GPU_SET but still reports GX off ({timeout.detail["value"]})') from None
    s.prove('gx_on', f'GMU_SPTPRAC_PWR_CLK_STATUS {hx(status)}: GX on')
    out['gx_on'] = True
    return out


def plan_copy(size):
    """The bounded-submit rule: a copy is at most 1 MiB and dword aligned, or it is refused before a word is written."""
    if size <= 0 or size % 4 or size > MAX_COPY_BYTES:
        raise Refused(f'CP_MEMCPY of {size} bytes: at most {MAX_COPY_BYTES} (1 MiB), dword aligned, never more (a 4 MiB copy hung the A16)')
    return size


def run_steps(s, steps, flag, out):
    """Descriptor steps: {reg, value, verify?} writes and {expect: {reg, mask, value}} bounded polls. Every register must be in
    the table, so its gate applies; a step with neither key is refused."""
    for step in steps:
        if 'reg' in step:
            value = as_int(step.get('value'), 'step.value')
            if value is None:
                raise Refused(f'step on {step["reg"]} has a null value')
            s.wr(step['reg'], value)
            out[flag] = True
            if step.get('verify') and s.rd(step['reg']) != value:
                raise Stop(s.step, f'{step["reg"]} did not read back as written')
        elif 'expect' in step:
            e = step['expect']
            s.poll(e['reg'], as_int(e['mask'], 'mask'), as_int(e['value'], 'value'), 'ring')
        else:
            raise Refused('a step needs reg or expect')


def stage_ring(s, out):
    """S6 (X8b). Source: STUDY 2.2, 2.6, 2.7 and Linux a6xx_gpu.c hw_init; the SQE start, ring base, CP init packet and protect
    table have no cited encodings in this tool, so every one comes from the descriptor (ring.steps) and a null refuses.
    ring.halt_steps is what S7 runs to halt the CP and the GBIF before GX is dropped. Stop rule: SECVID not reading back as
    written, a ring that does not advance inside the bound, or a copy above 1 MiB stops the run; a timeout is recovery, never
    success."""
    s.step = 'S6'
    if 'gx_on' not in s.proven:
        raise Refused('S6 needs GX on by the GMU (gate gx_on)')
    steps = s.board.need('ring.steps')
    s.board.need('ring.halt_steps')
    for size in s.board.need('ring.copy_sizes'):
        plan_copy(as_int(size, 'ring.copy_sizes'))
    run_steps(s, steps, 's6_wrote', out)
    out['ring_ok'] = True
    return out


def stage_quiesce(s, out):
    """S7. Source: STUDY 2.1 (GBIF halt pair), LNX a6xx_gmu.c:1427-1520 (shutdown), gdsc.c:343-390 (disable: a VOTABLE GDSC is
    not polled), clk-rcg2.c. Reverse order of what this run turned on, and a safety rule of this tool (EXPERIMENTAL, no
    hardware evidence): the GMU is never held in reset, and CX never collapsed, while GX may still be on. So: halt the CP
    and the GBIF (descriptor ring.halt_steps) if S6 wrote, clear the GPU_SET request and wait for the GMU's own status to
    show the GX GDSC off, then hold the GMU in reset, then disable what S1 enabled and collapse the CX GDSC. The first
    failure stops the quiesce where it is and is recorded; it is never raised. Not run after an SError or a lost link."""
    s.step = 'S7'
    done, left = out.setdefault('quiesce', []), None
    try:
        if 'S6' in s.wrote and 'gx_on' in s.proven:
            halt = s.board.data.get('ring', {}).get('halt_steps')
            if not isinstance(halt, list):
                left = 'S6 ran but ring.halt_steps is null: the CP is not halted, GX is left on and the GMU running'
                return out
            run_steps(s, halt, 's7_wrote', out)
            done.append('CP and GBIF halted by the descriptor steps')
        if s.oob_requested:
            s.wr('GMU_HOST2GMU_INTR_SET', 1 << OOB_GPU_SET_CLEAR_BIT)
            status = s.poll('GMU_SPTPRAC_PWR_CLK_STATUS', 0x1, 0x1, 'oob')
            s.withdraw('gx_on')
            done.append(f'GX GDSC off by the GMU status ({hx(status)})')
        if 'S3' in s.wrote and 'cx_on' in s.proven:
            s.wr('GMU_CM3_SYSRESET', 1)
            s.withdraw('gmu_up')
            done.append('GMU held in reset')
        if 'S1' in s.wrote and 'gcc_ahb' in s.proven:
            s.withdraw('cx_on')
            s.withdraw('cx_smmu')
            for name in reversed(s.owned):
                branch_off(s, name)
            if s.owned:
                done.append('branches disabled: ' + ', '.join(reversed(s.owned)))
            if s.owned_gdsc:
                s.update('GPU_CC_CX_GDSCR', R.GDSC_SW_COLLAPSE, R.GDSC_SW_COLLAPSE)
                s.udelay(500)                                # a VOTABLE GDSC is not polled when it is disabled (gdsc.c:170-181)
                status = s.rd('GPU_CC_CX_GDS_HW_CTRL')
                out['cx_gdsc_after'] = hx(status)
                if status & R.GDSC_PWR_ON:
                    left = 'CX GDSC still reads on after SW_COLLAPSE: another vote holds it'
                else:
                    done.append('CX GDSC collapsed')
    except (Stop, Refused) as problem:
        left = f'{problem}'
    finally:
        out['quiesce_left'] = left
    return out


# --- the plan as data (checked against the code by the test) ---------------------------------------------------------------
STAGE_PLAN = (
    {'id': 'S0', 'name': 'survey', 'writes': False, 'registers': GCC_SURVEY + GPUCC_SURVEY + CX_SURVEY + SMMU_SURVEY,
     'source': 'A16 stage 1; LNX gcc-x1e80100.c, gpucc-x1e80100.c, gdsc.c, a6xx_gmu.xml, arm-smmu.h',
     'stop': 'GCC_GPU_CFG_AHB off, a CX gate that is not on, any SError or abort'},
    {'id': 'S1', 'name': 'cx-power', 'writes': True,
     'registers': ('GPU_CC_GMU_RCG_CMD', 'GPU_CC_GMU_RCG_CFG', 'GPU_CC_CX_GDSCR', 'GPU_CC_CX_GDS_HW_CTRL') + GMU_CLOCKS,
     'source': 'LNX clk-rcg2.c, gdsc.c, gpucc-x1e80100.c; hamoa.dtsi:4184-4197',
     'stop': 'HW control, a hub RCG parent not ready, a poll past its bound, CX gate not on'},
    {'id': 'S2', 'name': 'rsc', 'writes': False, 'registers': ('RSCC_RSC_STATUS0_DRV0', 'RSCC_SEQ_BUSY_DRV0', 'RSCC_PDC_SEQ_START_ADDR') + TCS_STATUS,
     'source': 'LNX a6xx_gmu.c:1099-1134', 'stop': 'a TCS that stays busy, a state the operator has not reviewed'},
    {'id': 'S3', 'name': 'gmu-start', 'writes': True,
     'registers': ('GMU_CM3_SYSRESET', 'GPU_GMU_CX_GMU_CX_FALNEXT_INTF', 'GPU_GMU_CX_GMU_CX_FAL_INTF', 'CX_MISC_TCM_RET_CNTL',
                   'GMU_CM3_ITCM_START', 'GMU_CM3_DTCM_START', 'GMU_CM3_FW_INIT_RESULT', 'GMU_CM3_BOOT_CONFIG', 'GMU_HFI_QTBL_ADDR',
                   'GMU_HFI_QTBL_INFO', 'GMU_AHB_FENCE_RANGE_0', 'GMU_CM3_CFG', 'GMU_GENERAL_10', 'GMU_GENERAL_8',
                   'GMU_SYS_BUS_CONFIG', 'GMU_ICACHE_CONFIG', 'GMU_DCACHE_CONFIG', 'GMU_GENERAL_9'),
     'source': 'LNX a6xx_gmu.c:304-340, 815-827, 953-1058; a6xx_hfi.c:1155-1198',
     'stop': 'a warm GMU, a null value, no firmware init result within the bound'},
    {'id': 'S4', 'name': 'hfi', 'writes': True,
     'registers': ('GMU_HFI_CTRL_INIT', 'GMU_HFI_CTRL_STATUS', 'GMU_HOST2GMU_INTR_SET', 'GMU_GMU2HOST_INTR_INFO',
                   'GMU_GMU2HOST_INTR_CLR'),
     'source': 'LNX a6xx_gmu.c:346-358, a6xx_hfi.c:72-110, 213-232, a6xx_hfi.h', 'stop': 'no acknowledgement, or one that is not an ACK of the message with error word 0'},
    {'id': 'S5', 'name': 'gx-oob', 'writes': True,
     'registers': ('GMU_HOST2GMU_INTR_SET', 'GMU_GMU2HOST_INTR_INFO', 'GMU_GMU2HOST_INTR_CLR', 'GMU_SPTPRAC_PWR_CLK_STATUS'),
     'source': 'LNX a6xx_gmu.c:372-377, 406-465, 95-118', 'stop': 'no acknowledgement, GMU status still GX off, no thermal limits'},
    {'id': 'S6', 'name': 'ring', 'writes': True,
     'registers': ('GPU_RBBM_SECVID_TRUST_CNTL', 'GPU_CP_SQE_CNTL', 'GPU_CP_RB_CNTL', 'GPU_CP_RB_RPTR', 'GPU_CP_RB_WPTR',
                   'GPU_RBBM_STATUS', 'GPU_RBBM_INT_0_STATUS', 'GPU_CP_INTERRUPT_STATUS', 'GPU_CP_HW_FAULT', 'GPU_RBBM_GBIF_HALT',
                   'GPU_RBBM_GBIF_HALT_ACK'),
     'source': 'STUDY 2.2, 2.6, 2.7; MESA a6xx.xml', 'stop': 'SECVID not as written, a ring that does not advance, a copy above 1 MiB'},
    {'id': 'S7', 'name': 'quiesce', 'writes': True,
     'registers': ('GMU_HOST2GMU_INTR_SET', 'GMU_SPTPRAC_PWR_CLK_STATUS', 'GMU_CM3_SYSRESET', 'GPU_CC_CX_GDSCR',
                   'GPU_CC_CX_GDS_HW_CTRL', 'GPU_RBBM_GBIF_HALT', 'GPU_RBBM_GBIF_HALT_ACK') + GMU_CLOCKS,
     'source': 'STUDY 2.1; LNX a6xx_gmu.c:1427-1520, gdsc.c:343-390',
     'stop': 'the first failure, recorded and never raised; GX must read off before the GMU is reset; not run after an SError or a lost link'},
)
STAGES = {'S0': stage_survey, 'S1': stage_cx_power, 'S2': stage_rsc, 'S3': stage_gmu_start, 'S4': stage_hfi, 'S5': stage_gx_oob,
          'S6': stage_ring}
STAGE_IDS = tuple(STAGES)


def arm_guard(proxy, out, allow_unguarded):
    """R1: read the SError record, then reset it and go strict (as tools/a16gpu.py arm_guard). Returns the record before arming."""
    try:
        state = proxy.serror_state()
    except q1n1proxy.ProxyRemoteError:
        out['serror_guard'] = {'present': False}
        if allow_unguarded:
            return None
        raise GuardMissing('S0.R1', 'the running q1n1 has no SError guard (P_Q1N1_SERROR rejected): chainload a stage built with it')
    if state['mechanism'] == 0 and not allow_unguarded:
        raise GuardMissing('S0.R1', 'the SError guard reports no mechanism on this core')
    out['serror_guard'] = {'present': True, 'before_reset': serror_json(state)}
    proxy.serror_reset()
    proxy.serror_strict(True)
    return state


def finish_guard(proxy, out, previous, status, silent):
    """After a clean run one more bracketed access polls for a late SError (the A16 REVIEW-2 rule), then the record is read and
    the previous strict mode restored. Nothing is sent when the link was lost. Returns the (possibly raised) exit status."""
    if previous is None or silent:
        return status
    try:
        if status == 0:
            try:
                proxy.read64(previous['address'])
            except q1n1proxy.ProxyRemoteError:
                pass
        out['serror_guard']['after'] = serror_json(proxy.serror_state())
        proxy.serror_strict(bool(previous['flags'] & q1n1proxy.SERROR_STRICT))
    except (q1n1proxy.ProxyError, OSError) as problem:
        out['serror_guard']['after_error'] = str(problem)
    after = out['serror_guard'].get('after', {})
    if status == 0 and (after.get('before') or after.get('during') or after.get('unconsumed')):
        out['stopped'] = {'step': 'end', 'reason': 'SError counters are not zero after the run'}
        return SErrorStop.exit_code
    return status


def run(proxy, board, until='S0', allow_writes=False, allow_unguarded=False, quiesce=True, clock=time.monotonic):
    """Run the stages up to `until` in order against `proxy`, then S7 if anything was written (unless quiesce is False, for a
    caller that continues in the same session). Returns (exit_code, out, session). The only caller that gives a real proxy is a
    future, separately authorised command line; tests give a fake device."""
    out = {'tool': 'sp11_gpu_x8a', 'format': 1, 'board_sha256': board.sha256(), 'until': until, 'allow_writes': allow_writes,
           'order': [], 'stopped': None}
    s, previous, code = None, None, 0
    try:
        if until not in STAGES:
            raise Refused(f'unknown stage {until!r}')
        previous = arm_guard(proxy, out, allow_unguarded)
        s = Session(proxy, board, allow_writes=allow_writes, guarded=previous is not None, clock=clock)
        for index, name in enumerate(STAGE_IDS):
            if name > until:
                break
            if STAGE_PLAN[index]['writes'] and not allow_writes:
                s.step = name
                raise Refused(f'{name} writes: pass allow_writes (and the operator authorisation) to run it')
            out['order'].append(name)
            STAGES[name](s, out)
    except Refused as refusal:
        code, out['stopped'] = refusal.exit_code, {'step': s.step if s else 'setup', 'reason': f'refused: {refusal}'}
    except Stop as stop:
        code, out['stopped'] = stop.exit_code, {'step': stop.step, 'reason': stop.reason, **stop.detail}
    except (q1n1proxy.ProxyError, OSError) as problem:
        code = LinkLost.exit_code
        out['stopped'] = {'step': s.step if s else 'setup', 'reason': f'proxy link failed: {problem} (possible bus hang)'}
        if s is not None:
            s.dead = s.silent = True
    if s is not None and not s.dead and quiesce and s.wrote - {'S7'}:
        try:
            stage_quiesce(s, out)
        except (Stop, Refused) as problem:
            out['quiesce_left'] = str(problem)
        except (q1n1proxy.ProxyError, OSError) as problem:
            out['quiesce_left'] = f'proxy link failed during the quiesce: {problem}'
            s.dead = s.silent = True
        if out.get('quiesce_left') and code == 0:
            code = Stop.exit_code
            out['stopped'] = {'step': 'S7', 'reason': f'the quiesce did not complete: {out["quiesce_left"]}'}
    code = finish_guard(proxy, out, previous, code, s is not None and s.silent or code == LinkLost.exit_code)
    if s is not None:
        out.update(proven=s.proven, polls=s.polls, log=s.log, accesses=len(s.log))
    return code, out, s


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    parser.add_argument('command', choices=('plan', 'board'))
    parser.add_argument('--board', help='board descriptor JSON (schema sp11-gpu-board/1)')
    args = parser.parse_args(argv)
    board = load_board(args.board)
    if args.command == 'plan':
        for st in STAGE_PLAN:
            print(f'{st["id"]} {st["name"]:<10} {"WRITES" if st["writes"] else "reads "}  stop: {st["stop"]}')
            print(f'    source: {st["source"]}')
            print(f'    registers: {", ".join(st["registers"])}')
    else:
        print(json.dumps({'blocks': {k: None if v is None else hx(v) for k, v in board.blocks.items()},
                          'overrides': board.overrides, 'sha256': board.sha256()}, indent=1))
    return 0


if __name__ == '__main__':
    sys.exit(main())
