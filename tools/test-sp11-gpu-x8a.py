#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Offline fake-device test for tools/sp11_gpu_x8a.py, sp11_gpu_session.py and sp11_gpu_regs.py (Adreno X1-85, Surface Pro 11).

HOST ONLY. Nothing here has run on a Surface Pro 11; the device is tools/sp11_gpu_fake.py, the author's reading of the cited
Linux files, and a pass proves only that the tool obeys its own rules against that model. No hardware, no proxy, no network.

Every stage is run against FakeSP11: the positive path (S0 to S7, the quiesce restoring the cold power state) and deliberately
faulty devices the stage must stop on (a GDSC that does not come up, a GMU that never answers, an RPMh vote refused, an SError,
a lost link, a GX that stays on). The last group are faulty tools (mutants) the model must catch.

  python3 tools/test-sp11-gpu-x8a.py
"""
from __future__ import annotations

import contextlib
import hashlib
import io
from pathlib import Path
import shutil
import sys
import tempfile

TOOLS = Path(__file__).resolve().parent
sys.path.insert(0, str(TOOLS))
import sp11_gpu_regs as R  # noqa: E402
import sp11_gpu_x8a as X  # noqa: E402
from sp11_gpu_fake import (A, GMU_CLOCKS_DT, HFI_ARENA, HFI_VOTE_ID, LOG_ARENA, EXPECTED_CHIPID, NEW_RULE_VERSION,  # noqa: E402
                           OLD_RULE_VERSION, SMMU_CLOCKS_DT, FakeHang, FakeSP11)

Q = X.q1n1proxy
BUILD = TOOLS.parent / 'build'            # ignored by git; the test never writes outside the repository
checks = 0


def check(condition, label):
    global checks
    if not condition:
        raise SystemExit(f'FAIL: {label}')
    checks += 1


# --- the standard descriptor, image and runner -----------------------------------------------------------------------------
IMAGE = bytes(range(64)) + (OLD_RULE_VERSION).to_bytes(4, 'little')
IMAGE_WORDS = {i: int.from_bytes(IMAGE[4 * i:4 * i + 4], 'little') for i in range(16)}
WORK = {}


def board_data():
    return {
        'schema': X.BOARD_SCHEMA,
        'firmware': {'gmu': {'path': str(WORK['image']), 'sha256': hashlib.sha256(IMAGE).hexdigest(), 'size': len(IMAGE),
                             'itcm_size': 0x4000, 'dtcm_size': 0x4000,
                             'segments': [{'window': 'itcm', 'offset': 0, 'size': 64, 'file_offset': 0},
                                          {'window': 'dtcm', 'offset': 4 * X.GMU_DTCM_VERSION_DWORD, 'size': 4, 'file_offset': 64}]}},
        'dram': {'gmu_log': dict(LOG_ARENA)},
        'hfi': {'arena': dict(HFI_ARENA), 'messages': [{'id': HFI_VOTE_ID, 'payload': [1, 0, 0]}]},
        'gmu': {'gbif_cx': []},
        'rsc': {'reviewed': True},
        'thermal': {'sensor': 'gpu-sensor', 'stop_c': 95},
        'ring': {'steps': [{'reg': 'GPU_RBBM_SECVID_TRUST_CNTL', 'value': 1, 'verify': True},
                           {'reg': 'GPU_CP_SQE_CNTL', 'value': 1},
                           {'reg': 'GPU_CP_RB_WPTR', 'value': 4},
                           {'expect': {'reg': 'GPU_CP_RB_RPTR', 'mask': 0xffffffff, 'value': 4}}],
                 'halt_steps': [{'reg': 'GPU_RBBM_GBIF_HALT', 'value': 1},
                                {'expect': {'reg': 'GPU_RBBM_GBIF_HALT_ACK', 'mask': 1, 'value': 1}}],
                 'copy_sizes': [4096, 65536, 262144, 1048576]},
    }


def set_path(data, path, value):
    node = data
    parts = path.split('.')
    for part in parts[:-1]:
        node = node[part]
    node[parts[-1]] = value


def go(until='S5', allow_writes=True, over=None, **scenario):
    data = board_data()
    for path, value in (over or {}).items():
        set_path(data, path, value)
    board = X.Board(data)
    fake = FakeSP11(X.Board(board_data()), IMAGE_WORDS, **scenario)       # the device is what it is, whatever the descriptor says
    code, out, session = X.run(fake, board, until=until, allow_writes=allow_writes)
    return code, out, session, fake


def stage_of(entry_step):
    return entry_step[:2]


def gx_accesses(fake):
    return [e for e in fake.log if e[3] and R.REGS[e[3]].domain == 'GX']


def set_oob(fake):
    return [e for e in fake.log if e[3] == 'GMU_HOST2GMU_INTR_SET' and e[2] >> 30 & 1]


# --- tests -----------------------------------------------------------------------------------------------------------------
def test_registry():
    R.check_table()
    names = [n for st in X.STAGE_PLAN for n in st['registers']]
    check(all(n in R.REGS for n in names), 'every register in the plan is in the table')
    check([st['id'] for st in X.STAGE_PLAN] == ['S0', 'S1', 'S2', 'S3', 'S4', 'S5', 'S6', 'S7'], 'stage ids S0..S7 in order')
    check(not any(R.REGS[n].domain == 'GX' for n in X.STAGE_PLAN[0]['registers']), 'the survey names no GX register')
    check(not any(R.REGS[n].domain == 'GX' for st in X.STAGE_PLAN[:6] for n in st['registers']), 'no GX register before S6 (S7 only halts)')
    check(all(R.REGS[n].gate == 'gx_on' for n in R.REGS if R.REGS[n].domain == 'GX'), 'every GX register is gated by gx_on')
    check(all(R.REGS[n].evidence for n in R.REGS), 'every register carries a source')
    check(R.REGS['GMU_CM3_SYSRESET'].at(0x03d00000) == 0x03d7e000 and R.REGS['GPU_CC_CX_GDS_HW_CTRL'].at(0x03d90000) == 0x03d9953c,
          'absolute addresses from the public device tree')
    check(R.REGS['SMMU_ID0'].gate == 'cx_smmu', 'the SMMU has its own gate')
    check(X.GMU_CLOCKS == GMU_CLOCKS_DT and X.SMMU_CLOCKS == SMMU_CLOCKS_DT, 'the clock lists match the device-tree transcription of the model')
    check(X.plan_copy(1 << 20) == 1 << 20 and X.plan_copy(4096) == 4096, 'copies up to 1 MiB are planned')
    for bad in (0, 3, (1 << 20) + 4, 4 << 20):
        try:
            X.plan_copy(bad)
            check(False, f'a copy of {bad} bytes must be refused')
        except X.Refused:
            check(True, 'copy refused')
    check(X.fw_start_rule(OLD_RULE_VERSION) == (0xffffffff, 0xbabeface) and X.fw_start_rule(NEW_RULE_VERSION) == (0x1ff, 0x100),
          'both firmware start rules')
    check(X.hub_source_ready(0, 0) and not X.hub_source_ready(5, 0) and X.hub_source_ready(5, R.GCC_VOTE_GPLL0)
          and not X.hub_source_ready(3, R.GCC_VOTE_GPLL0) and X.hub_source_ready(6, R.GCC_VOTE_GPLL0_DIV), 'hub parent readiness')
    words = X.hfi_table_words(X.Arena(0x60010000, 0x960010000, 0x4000))
    check(words[:6] == [0, 168, 6, 12, 3, 3] and len(words) == 42 and words[7] == 0x60011000 and words[6 + 12 + 1] == 0x60012000,
          'the HFI table words as a6xx_hfi_init writes them')


def test_session_refusals():
    board = X.Board(board_data())
    fake = FakeSP11(board, IMAGE_WORDS)
    s = X.Session(fake, board, allow_writes=False)
    for what, call in (('an unlisted register', lambda: s.rd('GPU_CC_NOT_A_REGISTER')),
                       ('a register behind a gate that is not proven', lambda: s.rd('GMU_CM3_SYSRESET')),
                       ('a GX register', lambda: s.rd('GPU_RBBM_STATUS')),
                       ('a never register', lambda: s.rd('GCC_GPU_BCR')),
                       ('a write with writes off', lambda: s.wr('GCC_GPU_MEMNOC_GFX_CBCR', 1)),
                       ('DRAM outside every arena', lambda: s.dram_read(0x1000, 1)),
                       ('a DRAM write with writes off', lambda: s.dram_write(HFI_ARENA['phys'], [1]))):
        before = len(fake.log)
        try:
            call()
            check(False, f'{what} must be refused')
        except X.Refused:
            check(len(fake.log) == before, f'{what}: refused with nothing sent')
    check(not fake.violations, 'refusals left no violation')
    s2 = X.Session(fake, board, allow_writes=True)
    s2.prove('cx_on', 'test')
    for what, call in (('a write to a read-only register', lambda: s2.wr('GMU_CM3_FW_BUSY', 1)),
                       ('DRAM before a stage registers its arena', lambda: s2.dram_write(HFI_ARENA['phys'], [1]))):
        try:
            call()
            check(False, f'{what} must be refused')
        except X.Refused:
            check(True, f'{what} is refused')
    try:
        X.Session(fake, X.Board(dict(board_data(), blocks={'gpucc': None}))).rd('GPU_CC_CX_GDSCR')
        check(False, 'a null block base must refuse')
    except X.Refused:
        check(True, 'a null block base refuses')
    try:
        X.Board({'schema': 'other/1'})
        check(False, 'a wrong schema must refuse')
    except X.Refused:
        check(True, 'a wrong schema refuses')


def test_survey():
    code, out, s, fake = go(until='S0', allow_writes=False)
    check(code == 0 and out['cx_gate'] == 'off' and out['order'] == ['S0'], 'cold survey ends with the CX gate off')
    check(not any(k in ('w', 'wm') for k, *_ in fake.log) and not fake.violations, 'the survey writes nothing and breaks no rule')
    check(not fake.accesses(blocks=('gmu', 'rscc', 'cx_misc', 'smmu', 'gpu')), 'a cold survey reads nothing behind the CX GDSC')
    check(out['gcc']['GCC_GPU_CFG_AHB_CBCR'] and out['cx_gdsc']['on'] is False and out['gx_gdsc']['off'] is True, 'GDSC states reported')
    check('serror_guard' in out and out['serror_guard']['after']['before'] == 0 and not fake.strict, 'guard armed, then restored')
    code, out, s, fake = go(until='S0', allow_writes=False, cx_on=True)
    check(code == 0 and out['cx_gate'] == 'on' and out['gx_by_gmu'] == 'off' and out['tcm_retained'] is False, 'warm survey')
    check(out['smmu'].startswith('skipped') and not fake.accesses(blocks=('smmu',)), 'the SMMU is not read without its clocks')
    check(not any(R.REGS[n].domain == 'GX' for _, _, n, _ in fake.accesses()), 'no GX register read by the survey')
    code, out, s, fake = go(until='S0', allow_writes=False, cx_on=True, smmu_clocks_on=True)
    check(code == 0 and isinstance(out['smmu'], dict) and out['smmu']['SMMU_ID0'] == '0x00000a20', 'the SMMU is read with its clocks on')
    check({n for _, _, n, _ in fake.accesses()} == set(X.STAGE_PLAN[0]['registers']), 'a full survey reads exactly the registers the plan lists')
    code, out, s, fake = go(until='S0', allow_writes=False, cx_on=True, off_clock='GPU_CC_DEMET_CBCR')
    check(out['cx_gate'] == 'partial' and not fake.accesses(blocks=('gmu', 'rscc', 'cx_misc')), 'a missing GMU clock keeps the gate shut')


def test_survey_stops():
    code, out, s, fake = go(until='S0', allow_writes=False, gcc_cfg_ahb_on=False)
    check(code == 2 and out['stopped']['step'] == 'S0.R2', 'GCC_GPU_CFG_AHB off stops the survey')
    check(not fake.accesses(blocks=('gpucc', 'gmu', 'rscc', 'cx_misc', 'smmu', 'gpu')) and not fake.violations, 'no GPUCC read when its AHB is off')
    code, out, s, fake = go(until='S0', allow_writes=False, cx_on=True, hw_control=True)
    check(code == 0 and out['cx_gate'] == 'hw_control' and not fake.accesses(blocks=('gmu', 'rscc', 'cx_misc', 'smmu')) and not fake.violations,
          'HW control: no CX read (the model would hang on one)')
    code, out, s, fake = go(until='S1', cx_on=True, hw_control=True)
    check(code == 2 and out['stopped']['step'] == 'S1' and not [e for e in fake.log if e[0] == 'w'], 'S1 never takes HW control and writes nothing')
    code, out, s, fake = go(until='S1', hub_rcg_src=5, gcc_vote=0)
    check(code == 2 and 'hub RCG' in out['stopped']['reason'] and not [e for e in fake.log if e[0] == 'w'], 'a hub RCG on an unvoted GPLL0 stops S1 before any write')
    code, out, s, fake = go(until='S1', hub_rcg_src=5, gcc_vote=R.GCC_VOTE_GPLL0)
    check(code == 0 and out['cx_gate'] == 'on', 'the same hub RCG with its vote set is accepted')


def test_guard_and_faults():
    code, out, s, fake = go(until='S0', allow_writes=False, guard=False)
    check(code == 4 and not fake.log and out['stopped']['step'] == 'S0.R1', 'no SError guard: exit 4, nothing sent')
    code, out, s, fake = go(until='S0', allow_writes=False, mechanism=0)
    check(code == 4 and not fake.log, 'a guard without a mechanism: exit 4')
    addr = A('GPU_CC_CX_GDSCR')
    code, out, s, fake = go(until='S0', allow_writes=False, serror_at=(addr, 'r'))
    check(code == 3 and fake.log[-1][1] == addr and s.dead and out['stopped']['serror']['during'] == 1, 'an SError stops the run at the faulting access')
    check(s.log[-1].get('failed') and 'quiesce' not in out and not [e for e in fake.log if e[0] == 'w'], 'nothing is sent after the SError, and nothing was written')
    before = len(fake.log)
    try:
        s.rd('GCC_GPU_CFG_AHB_CBCR')
        check(False, 'a dead session must refuse every access')
    except X.Refused:
        check(len(fake.log) == before, 'a session that saw an SError refuses further accesses, even to an always-on block')
    code, out, s, fake = go(until='S0', allow_writes=False, sync_abort_at=A('GCC_PROC_VOTE_ENA'))
    check(code == 3 and 'synchronous abort' in out['stopped']['reason'], 'a synchronous abort (guard marker) stops the run')
    code, out, s, fake = go(until='S0', allow_writes=False, hang_at=(addr, 'r'))
    check(code == 5 and fake.log[-1][1] != addr and fake.state_calls == 1 and s.silent, 'a lost link: exit 5, and no record read after it')
    code, out, s, fake = go(until='S0', allow_writes=False, late_serror_at=(addr, 'r'))
    check(code == 3 and out['stopped']['serror']['before'] == 1, 'an SError found before the next access stops the run')
    code, out, s, fake = go(until='S1', serror_at=(addr, 'w'))
    check(code == 3 and s.dead and fake.log[-1][1] == addr and fake.log[-1][0] == 'w', 'an SError on a write stops it, with no quiesce traffic')
    check('quiesce' not in out, 'no quiesce after an SError')
    code, out, s, fake = go(until='S1', write_abort_at=addr)
    check(code == 3 and s.dead and 'synchronous abort' in out['stopped']['reason'] and 'quiesce' not in out, 'a synchronous abort on a write stops it the same way')
    code, out, s, fake = go(until='S1', end_serror=True)
    check(code == 3 and out['stopped']['reason'].startswith('SError counters'), 'a late SError at the end of an otherwise clean run is exit 3')


def test_cx_power():
    code, out, s, fake = go(until='S1')
    writes = [e for e in fake.log if e[0] == 'w' and e[3]]
    check(code == 0 and out['cx_gate'] == 'on' and not fake.violations, 'cold S1 powers the CX side')
    check(set(out['s1']['enabled']) == set(X.GMU_CLOCKS) and fake.power_state()['cx_gdsc_on'] is False and 'CX GDSC collapsed' in out['quiesce'],
          'S1 enabled the seven clocks, and the end-of-run quiesce collapsed the GDSC')
    first_gdsc = next(i for i, e in enumerate(fake.log) if e[0] == 'w' and e[3] == 'GPU_CC_CX_GDSCR')
    enable_order = [e[3] for e in fake.log if e[0] == 'w' and e[3] in X.GMU_CLOCKS and e[2] & R.CBCR_ENABLE]
    check(enable_order == list(X.GMU_CLOCKS), 'the seven clocks are enabled in the device-tree order of the GMU node')
    first_branch = next(i for i, e in enumerate(fake.log) if e[0] == 'w' and e[3].endswith('_CBCR') and e[3].startswith('GPU_CC_'))
    check(first_gdsc < first_branch, 'the GDSC comes up before the GPUCC branches')
    gdscr = [e[2] for e in writes if e[3] == 'GPU_CC_CX_GDSCR']
    check(gdscr[0] & R.GDSC_WAITS_MASK == R.CX_GDSC_WAITS and not gdscr[0] & (R.GDSC_HW_CONTROL | R.GDSC_SW_OVERRIDE)
          and not gdscr[1] & R.GDSC_SW_COLLAPSE and gdscr[2] & R.GDSC_RETAIN_FF, 'gdsc_init values, then collapse clear, then RETAIN_FF')
    gdscr_at = [i for i, e in enumerate(fake.log) if e[0] == 'w' and e[3] == 'GPU_CC_CX_GDSCR']
    between = [e for e in fake.log[gdscr_at[1]:gdscr_at[2]] if e[0] == 'r' and e[3] == 'GPU_CC_CX_GDS_HW_CTRL']
    check(len(between) >= 2 and any(p['reg'] == 'GPU_CC_CX_GDS_HW_CTRL' and p['ok'] for p in s.polls),
          'between the collapse clear and RETAIN_FF the status is polled from GDS_HW_CTRL (bit 31)')
    # a shared RCG on a running parent is parked first; on a dead parent the park fails before the GDSC is touched
    code, out, s, fake = go(until='S1', gmu_rcg_src=5, gcc_vote=R.GCC_VOTE_GPLL0)
    idx = {name: [i for i, e in enumerate(fake.log) if e[0] == 'w' and e[3] == name] for name in ('GPU_CC_GMU_RCG_CMD', 'GPU_CC_GMU_RCG_CFG', 'GPU_CC_CX_GDSCR')}
    check(code == 0 and 'parked on XO' in out['rcg_park'] and idx['GPU_CC_GMU_RCG_CFG'][0] < idx['GPU_CC_CX_GDSCR'][0] and not fake.violations,
          'the GMU RCG is parked on XO before the GDSC is enabled')
    check(fake.log[idx['GPU_CC_GMU_RCG_CFG'][0]][2] == 0, 'the parked CFG is written 0 (XO, divider 0)')
    code, out, s, fake = go(until='S1', gmu_rcg_src=1)
    check(code == 2 and out['stopped']['step'] == 'S1' and out['stopped'].get('root_en_released') is True
          and not [e for e in fake.log if e[0] == 'w' and e[3] == 'GPU_CC_CX_GDSCR'] and not fake.violations,
          'a dead RCG parent: the park times out, ROOT_EN is released and the GDSC is never touched')
    # the GDSC never comes up: bounded, then reversed
    code, out, s, fake = go(until='S1', gdsc_stuck=True)
    polls = [p for p in s.polls if p['reg'] == 'GPU_CC_CX_GDS_HW_CTRL']
    check(code == 2 and out['stopped']['step'] == 'S1' and polls[-1]['ok'] is False and polls[-1]['reads'] <= X.POLL_LIMITS['gdsc'],
          'a GDSC that never comes up: a bounded poll, exit 2')
    check(not [e for e in fake.log if e[0] == 'w' and e[3] in X.GMU_CLOCKS] and fake.power_state()['sw_collapse'] and not fake.violations,
          'no clock was enabled and the collapse request was put back')
    code, out, s, fake = go(until='S1', branch_delay=99)
    check(code == 2 and 'GPU_CC_AHB_CBCR' in out['stopped']['reason'], 'a branch that never leaves CLK_OFF stops S1')
    code, out, s, fake = go(until='S1', cx_on=True)
    check(code == 0 and out['s1'] == 'CX already on: nothing written' and not [e for e in fake.log if e[0] == 'w'] and not s.wrote,
          'S1 on a powered CX side writes nothing')
    code, out, s, fake = go(until='S1', cx_on=True, off_clock='GPU_CC_DEMET_CBCR')
    check(code == 0 and out['s1']['enabled'] == ['GPU_CC_DEMET_CBCR'], 'a partial CX side: only the missing clock is enabled')
    check(fake.power_state()['cx_gdsc_on'] is True and 'GPU_CC_DEMET_CBCR' not in fake.enabled,
          'the quiesce disables only what S1 enabled and leaves a GDSC it did not power')


def test_rsc_and_gmu():
    code, out, s, fake = go(until='S2', tcs_busy=True)
    check(code == 2 and out['stopped']['step'] == 'S2' and 'S3' not in s.wrote, 'a busy TCS stops S2 before the GMU is touched')
    check([p for p in s.polls if p['reg'] == 'RSCC_TCS3_DRV0_STATUS'][-1]['reads'] <= X.POLL_LIMITS['rsc'], 'the TCS poll is bounded')
    code, out, s, fake = go(until='S2', over={'rsc.reviewed': False})
    check(code == 2 and 'reviewed' in out['stopped']['reason'], 'an unreviewed RSC state stops S2')
    code, out, s, fake = go(until='S3')
    check(code == 0 and out['gmu_up'] and not fake.violations, 'S3 brings the GMU up')
    resets = [e[2] for e in fake.log if e[0] == 'w' and e[3] == 'GMU_CM3_SYSRESET']
    check(resets[:3] == [1, 1, 0] and resets[-1] == 1, 'reset held, held again, then released (the quiesce holds it at the end)')
    s3 = [(e[3], e[2]) for e in fake.log if e[0] == 'w' and e[3] and not e[3].startswith('GPU_CC_')]
    order = [n for n, _ in s3]
    check(order.index('GPU_GMU_CX_GMU_CX_FALNEXT_INTF') < order.index('CX_MISC_TCM_RET_CNTL') < order.index('GMU_CM3_ITCM_START')
          < order.index('GMU_CM3_FW_INIT_RESULT') < order.index('GMU_HFI_QTBL_ADDR') < order.index('GMU_CM3_CFG') < order.index('GMU_GENERAL_10'),
          'the Linux cold-boot order of a6xx_gmu_fw_start')
    check(dict(s3)['GMU_GENERAL_10'] == EXPECTED_CHIPID and dict(s3)['GMU_AHB_FENCE_RANGE_0'] == (1 << 31 | 0x32 << 18 | 0x8a0), 'chip-id and fence-range words')
    check(dict(s3)['GMU_GENERAL_8'] == 0x60000000 | 3, 'the log word: iova and (size / 4 KiB - 1)')
    check(fake.dram[HFI_ARENA['phys']] == 0 and fake.dram[HFI_ARENA['phys'] + 4] == 168, 'the HFI table was written to the physical address, not the iova')
    code, out, s, fake = go(until='S3', over={'firmware.gmu.sha256': None})
    check(code == 6 and 'S3' not in s.wrote, 'a null image hash refuses before any S3 write')
    # firmware with the other start rule (version above 0x20010004) and junk above the mask
    global IMAGE, IMAGE_WORDS
    saved = IMAGE, IMAGE_WORDS
    try:
        IMAGE = bytes(range(64)) + NEW_RULE_VERSION.to_bytes(4, 'little')
        IMAGE_WORDS = {i: int.from_bytes(IMAGE[4 * i:4 * i + 4], 'little') for i in range(16)}
        WORK['image'].write_bytes(IMAGE)
        code, out, s, fake = go(until='S3')
        check(code == 0 and fake.g['GMU_CM3_FW_INIT_RESULT'] == 0x12345100, 'the newer firmware start rule (mask 0x1ff) is honoured')
    finally:
        IMAGE, IMAGE_WORDS = saved
        WORK['image'].write_bytes(IMAGE)
    code, out, s, fake = go(until='S3', fw_stall=True)
    check(code == 2 and out['stopped']['step'] == 'S3' and 'gmu_up' not in s.proven, 'a GMU that never answers: exit 2')
    check([p for p in s.polls if p['reg'] == 'GMU_CM3_FW_INIT_RESULT'][-1]['reads'] <= X.POLL_LIMITS['gmu'], 'the init-result poll is bounded')
    last_reset = [e for e in fake.log if e[0] == 'w' and e[3] == 'GMU_CM3_SYSRESET'][-1]
    check(last_reset[2] == 1 and fake.power_state()['gmu_in_reset'] and not fake.power_state()['cx_gdsc_on'] and not fake.violations,
          'after a silent GMU the core is back in reset and CX is collapsed')
    code, out, s, fake = go(until='S3', tcm_ret=1, cx_on=True)
    check(code == 2 and 'warm' in out['stopped']['reason'] and 'S3' not in s.wrote, 'a warm GMU (TCM retained) stops S3 before any write')
    for path, value in (('firmware.gmu', None), ('dram.gmu_log', None), ('hfi.arena', None), ('firmware.gmu.segments', []),
                        ('firmware.gmu.itcm_size', None), ('gmu.gbif_cx', None), ('gmu.gbif_cx', [{'reg': 'X', 'value': 1}]),
                        ('firmware.gmu.segments', [{'window': 'itcm', 'offset': 0x3ffc, 'size': 8, 'file_offset': 0}]),
                        ('firmware.gmu.sha256', '00' * 32), ('hfi.arena', dict(HFI_ARENA, iova=0xffffe000)),
                        ('hfi.arena', dict(HFI_ARENA, size=0x2000))):
        code, out, s, fake = go(until='S3', over={path: value})
        check(code == 6 and 'S3' not in s.wrote and not fake.violations, f'S3 refuses a bad descriptor ({path}) before its first write')
    code, out, s, fake = go(until='S3', allow_writes=False)
    check(code == 6 and not [e for e in fake.log if e[0] in ('w', 'wm')], 'writes off: refused, nothing written')


def test_stage_preconditions():
    board = X.Board(board_data())
    for name in ('S1', 'S2', 'S3', 'S4', 'S5', 'S6'):
        fake = FakeSP11(board, IMAGE_WORDS)
        s = X.Session(fake, board, allow_writes=True)
        try:
            X.STAGES[name](s, {'cx_gate': 'off'} if name == 'S1' else {})
            check(False, f'{name} without its gates must be refused')
        except X.Refused:
            check(not fake.log, f'{name} without its gates: refused, nothing sent')
    fake = FakeSP11(board, IMAGE_WORDS)
    s = X.Session(fake, board, allow_writes=True)
    s.prove('gmu_up', 'test')
    s.prove('cx_on', 'test')
    try:
        X.stage_gx_oob(s, {})
        check(False, 'S5 needs the HFI to have been started')
    except X.Refused as refusal:
        check('hfi' in str(refusal) and not fake.log, 'S5 refuses without the HFI gate and sends nothing')
    fake = FakeSP11(board, IMAGE_WORDS)
    s = X.Session(fake, board, allow_writes=False)
    s.prove('cx_on', 'test')
    try:
        X.stage_gmu_start(s, {})
        check(False, 'S3 with writes off must be refused')
    except X.Refused:
        check(not fake.log, 'S3 with writes off: refused, nothing sent')


def test_hfi_and_gx():
    code, out, s, fake = go(until='S4')
    check(code == 0 and out['hfi_acks'] == [{'header': '0x0010041e', 'error': 0}] and not fake.violations, 'S4: the first vote is acknowledged')
    cmd_data, rsp_header = HFI_ARENA['phys'] + 4096, HFI_ARENA['phys'] + 24 + 48
    check([fake.dram[cmd_data + 4 * i] for i in range(4)] == [0x0010041e, 1, 0, 0], 'the vote message in the command queue: seq 1, 4 dwords, id 30')
    check(fake.dram[rsp_header + 40] == fake.dram[rsp_header + 44] == 4, 'the response was consumed and the read index published, aligned to 4')
    check(not set_oob(fake), 'S4 never requests GX')
    two = [{'id': HFI_VOTE_ID, 'payload': [1, 0, 0]}, {'id': 40, 'payload': [7]}]
    code, out, s, fake = go(until='S4', over={'hfi.messages': two})
    check(code == 0 and len(out['hfi_acks']) == 2 and [fake.dram[cmd_data + 16 + 4 * i] for i in range(4)] == [0x00200228, 7, 0xfafafafa, 0xfafafafa],
          'a 2-dword message is padded to 4 dwords with 0xfafafafa and the sequence number advances')
    code, out, s, fake = go(until='S4', vote_refused=True)
    check(code == 2 and 'refused' in out['stopped']['reason'] and not s.oob_requested and not fake.gx_on, 'a refused vote stops the run before GX is requested')
    check(not set_oob(fake) and fake.power_state()['gmu_in_reset'], 'and the quiesce holds the GMU in reset')
    code, out, s, fake = go(until='S4', ack_wrong_header=True)
    check(code == 2 and 'unexpected response' in out['stopped']['reason'], 'an acknowledgement of another message stops the run')
    code, out, s, fake = go(until='S4', ack_never=True)
    check(code == 2 and out['stopped']['step'] == 'S4' and [p for p in s.polls if p['reg'] == 'GMU_GMU2HOST_INTR_INFO'][-1]['reads'] <= X.POLL_LIMITS['hfi'],
          'no acknowledgement: a bounded wait, exit 2')
    code, out, s, fake = go(until='S4', hfi_never=True)
    check(code == 2 and out['stopped']['step'] == 'S4' and [p for p in s.polls if p['reg'] == 'GMU_HFI_CTRL_STATUS'][-1]['ok'] is False,
          'an HFI that never starts: exit 2')
    code, out, s, fake = go(until='S4', over={'hfi.messages': []})
    check(code == 6 and not fake.gx_on, 'no messages in the descriptor: refused')
    code, out, s, fake = go(until='S5')
    check(code == 0 and out['gx_on'] and not fake.violations, 'S5: GX on through the GMU, then wound down in order')
    check(fake.power_state()['gx_on'] is False and out['quiesce_left'] is None, 'the end-of-run quiesce dropped GX through the GMU, then reset it, then collapsed CX')
    check(not gx_accesses(fake), 'no GX register was touched in S0..S5')
    check(out['quiesce'][0].startswith('GX GDSC off') and 'GMU held in reset' in out['quiesce'] and out['quiesce'][-1] == 'CX GDSC collapsed', 'quiesce order: GX, GMU, CX')
    code, out, s, fake = go(until='S5', over={'thermal.stop_c': None})
    check(code == 6 and not s.oob_requested and not set_oob(fake), 'no thermal limit: S5 refuses before the GX request')
    code, out, s, fake = go(until='S5', oob_ack_never=True)
    check(code == 2 and out['stopped']['step'] == 'S5' and not fake.gx_on and out['quiesce_left'] is None, 'no OOB acknowledgement: exit 2 and a clean quiesce')
    code, out, s, fake = go(until='S5', gx_never=True)
    check(code == 2 and 'still reports GX off' in out['stopped']['reason'] and 'gx_on' not in s.proven, 'GX never comes up: exit 2, the GX gate is not proven')
    check(not fake.violations and out['quiesce_left'] is None and fake.power_state()['gmu_in_reset'], 'and nothing GX-side was touched; the quiesce completed')


def test_quiesce_rules():
    # GX stuck on: the GMU is never reset and CX never collapsed while GX may be on
    code, out, s, fake = go(until='S5', gx_stuck_on=True)
    state = fake.power_state()
    check(code == 2 and out['stopped']['step'] == 'S7' and out['gx_on'], 'GX stuck on: the run ends as exit 2 at S7')
    check(state['gx_on'] and not state['gmu_in_reset'] and state['cx_gdsc_on'], 'the quiesce stopped: the GMU keeps running and CX stays on')
    check('GMU_SPTPRAC_PWR_CLK_STATUS' in out['quiesce_left'] and not fake.violations, 'the quiesce records where and why it stopped, and breaks no rule of the model')
    # the descriptor halts the CP before GX is dropped
    code, out, s, fake = go(until='S6')
    check(code == 0 and out['ring_ok'] and out['s6_wrote'] and 'CP and GBIF halted by the descriptor steps' in out['quiesce'] and not fake.violations,
          'S6: ring steps, then a quiesce that halts the CP first')
    check(out['quiesce'][0] == 'CP and GBIF halted by the descriptor steps' and out['quiesce'][1].startswith('GX GDSC off'), 'quiesce order: CP halt, GX off, GMU, CX')
    gx_first = next(i for i, e in enumerate(fake.log) if e[3] and R.REGS[e[3]].domain == 'GX')
    check(fake.log.index(set_oob(fake)[0]) < gx_first, 'the first GX register access follows the GX request')
    code, out, s, fake = go(until='S6', secvid_refuse=True)
    check(code == 2 and 'did not read back' in out['stopped']['reason'], 'a refused SECVID write stops S6')
    check(fake.power_state()['gx_on'] is False and out['quiesce_left'] is None, 'and the run is wound down in order')
    code, out, s, fake = go(until='S6', ring_stall=True)
    check(code == 2 and out['stopped']['step'] == 'S6' and [p for p in s.polls if p['reg'] == 'GPU_CP_RB_RPTR'][-1]['reads'] <= X.POLL_LIMITS['ring'],
          'a ring that does not advance: a bounded poll, exit 2')
    code, out, s, fake = go(until='S6', halt_ack_never=True)
    check(code == 2 and out['stopped']['step'] == 'S7' and fake.power_state()['gx_on'] and 'GBIF_HALT_ACK' in out['quiesce_left'] and not fake.violations,
          'a GBIF halt that is not acknowledged stops the quiesce with GX left on')
    code, out, s, fake = go(until='S6', over={'ring.halt_steps': None})
    check(code == 6 and not [e for e in gx_accesses(fake) if e[0] == 'w'], 'S6 without halt steps refuses before any GX write')
    code, out, s, fake = go(until='S6', over={'ring.copy_sizes': [4096, 4 << 20]})
    check(code == 6 and 'S6' not in s.wrote and not gx_accesses(fake), 'a 4 MiB copy is refused before a word of S6 is written')
    code, out, s, fake = go(until='S6', allow_writes=False)
    check(code == 6 and not [e for e in fake.log if e[0] in ('w', 'wm')], 'S6 with writes off: refused')
    cold = FakeSP11(X.Board(board_data()), IMAGE_WORDS).power_state()
    code, out, s, fake = go(until='S6')
    check(fake.power_state() == cold, 'the power state after a full run and its quiesce equals the cold state')


def test_stage_order():
    code, out, s, fake = go(until='S6')
    seen = []
    for st in [e['step'] for e in s.log if e.get('reg')]:
        if not seen or seen[-1] != stage_of(st):
            seen.append(stage_of(st))
    check(seen == ['S0', 'S1', 'S2', 'S3', 'S4', 'S5', 'S6', 'S7'], 'stages run in order and S7 last')
    by_stage = {}
    for e in s.log:
        if e.get('reg'):
            by_stage.setdefault(stage_of(e['step']), set()).add(e['reg'])
    plan = {st['id']: set(st['registers']) for st in X.STAGE_PLAN}
    for sid, names in by_stage.items():
        check(names <= plan[sid], f'{sid} touches only the registers its plan lists ({sorted(names - plan[sid])})')
    check(all(e['reg'] in R.REGS for e in s.log if e.get('reg')), 'every access names a table register')
    writes = [e for e in s.log if e['op'] in ('write', 'writemem')]
    check(writes and all(stage_of(e['step']) not in ('S0', 'S2') for e in writes), 'S0 and S2 write nothing')
    check(code == 0 and out['accesses'] == len(s.log), 'the run record carries every access')


def test_mutants():
    """Deliberately faulty tools. Each must be caught by the model or by the tool's own rules, or the model proves nothing."""
    board = X.Board(board_data())
    fake = FakeSP11(board, IMAGE_WORDS, gcc_cfg_ahb_on=False)               # 1. a GPUCC read with its AHB branch off
    try:
        fake.read32(A('GPU_CC_CX_GDSCR'))
        check(False, 'mutant 1 must hang the model')
    except FakeHang:
        check(fake.violations[-1][0] == 'hang', 'mutant 1: a GPUCC read without the AHB branch hangs the model')
    fake = FakeSP11(board, IMAGE_WORDS)                                       # 2. a GX read before the GMU powers GX
    try:
        fake.read32(A('GPU_RBBM_STATUS'))
        check(False, 'mutant 2 must be caught')
    except FakeHang:
        check(fake.violations[-1][0] == 'gx', 'mutant 2: a GX read before GX is on is a violation')
    fake = FakeSP11(board, IMAGE_WORDS)                                       # 3. a CX read with the GDSC off: an SError
    fake.serror_strict(True)
    try:
        fake.read32(A('GMU_CM3_SYSRESET'))
        check(False, 'mutant 3 must raise')
    except Q.ProxyRemoteError as problem:
        check(problem.status == Q.S_SERROR, 'mutant 3: a CX read with the GDSC off is an SError')
    saved = X.park_rcg                                                        # 4. no RCG park, on a dead parent: the model wedges
    X.park_rcg = lambda s, base: 'skipped'
    try:
        code, out, s, fake = go(until='S1', gmu_rcg_src=5, gcc_vote=0)
    finally:
        X.park_rcg = saved
    check(any(v[0] == 'wedge' for v in fake.violations) and code == 5, 'mutant 4: powering the GDSC without parking the RCG wedges it and the run ends as a lost link')
    saved = X.GMU_CHIPID_WORD                                                 # 5. the X2's chip-id word: the GMU never answers
    X.GMU_CHIPID_WORD = 0x08010100
    try:
        code, out, s, fake = go(until='S3')
    finally:
        X.GMU_CHIPID_WORD = saved
    check(code == 2 and out['stopped']['step'] == 'S3', 'mutant 5: a wrong chip-id word leaves the GMU silent')

    def naive_quiesce(s, out):                                                # 6. reset and collapse without waiting for GX off
        s.step = 'S7'
        s.wr('GMU_HOST2GMU_INTR_SET', 1 << X.OOB_GPU_SET_CLEAR_BIT)
        s.wr('GMU_CM3_SYSRESET', 1)
        s.update('GPU_CC_CX_GDSCR', R.GDSC_SW_COLLAPSE, R.GDSC_SW_COLLAPSE)
        out['quiesce_left'] = None
        return out
    saved = X.stage_quiesce
    X.stage_quiesce = naive_quiesce
    try:
        code, out, s, fake = go(until='S5', gx_stuck_on=True)
    finally:
        X.stage_quiesce = saved
    check(any(v[0] == 'unsafe' for v in fake.violations), 'mutant 6: tearing the GMU down while GX is on is caught')
    fake = FakeSP11(board, IMAGE_WORDS)                                       # 7. DRAM outside the arena
    try:
        fake.writemem(0x1000, b'\0' * 4)
        check(False, 'mutant 7 must be caught')
    except FakeHang:
        check(fake.violations[-1][0] == 'dram', 'mutant 7: a DRAM write outside the descriptor arenas is caught')
    code, out, s, fake = go(until='S3', over={'hfi.arena': dict(HFI_ARENA, phys=HFI_ARENA['phys'] + 0x4000)})   # 8. wrong physical address
    check(code == 5 and any(v[0] == 'dram' for v in fake.violations), 'mutant 8: a DRAM write to an address outside the device arena is caught')


def test_cli():
    buffer = io.StringIO()
    with contextlib.redirect_stdout(buffer):
        check(X.main(['plan']) == 0 and X.main(['board']) == 0, 'plan and board run')
    text = buffer.getvalue()
    check(all(f'S{i} ' in text for i in range(8)) and 'sha256' in text and '0x03d90000' in text, 'plan lists S0..S7; board shows the public bases')
    try:
        with contextlib.redirect_stderr(io.StringIO()):
            X.main(['run'])
        check(False, 'a run command must not exist')
    except SystemExit:
        check(True, 'there is no command that connects to hardware')


def main():
    BUILD.mkdir(exist_ok=True)
    WORK['dir'] = Path(tempfile.mkdtemp(dir=BUILD, prefix='x8a-test-'))
    WORK['image'] = WORK['dir'] / 'gmu.bin'
    WORK['image'].write_bytes(IMAGE)
    try:
        for test in (test_registry, test_session_refusals, test_survey, test_survey_stops, test_guard_and_faults, test_cx_power,
                     test_rsc_and_gmu, test_stage_preconditions, test_hfi_and_gx, test_quiesce_rules, test_stage_order, test_mutants,
                     test_cli):
            test()
    finally:
        shutil.rmtree(WORK['dir'], ignore_errors=True)
    print(f'PASS: {checks} sp11 X8a register/power-model checks (offline fake device, no hardware)')
    return 0


if __name__ == '__main__':
    sys.exit(main())
