#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Mutation sweep of tools/test-sp11-gpu-x8a.py: the test of the test.

HOST ONLY. Each mutant is a one-line text edit of tools/sp11_gpu_x8a.py, sp11_gpu_session.py, sp11_gpu_regs.py or
sp11_gpu_fake.py, made in a scratch copy under build/ (ignored by git; the sources are never changed). The fake-device test is
run against each copy and must fail on it. A mutant that survives is either a gap in the test or a rule the tool enforces twice
(`equivalent` below: the run refuses writes both in run() and in Session, and a GX register is refused both by its domain and by
its gate); every other survivor is a failure of this sweep.

  python3 tools/test-sp11-gpu-x8a-mutants.py
"""
from __future__ import annotations

from pathlib import Path
import shutil
import subprocess
import sys

TOOLS = Path(__file__).resolve().parent
WORK = TOOLS.parent / 'build' / 'x8a-mutants'
FILES = {'x8a': 'sp11_gpu_x8a.py', 'regs': 'sp11_gpu_regs.py', 'session': 'sp11_gpu_session.py', 'fake': 'sp11_gpu_fake.py'}
COPIED = ('q1n1proxy.py', 'sp11_gpu_regs.py', 'sp11_gpu_session.py', 'sp11_gpu_x8a.py', 'sp11_gpu_fake.py', 'test-sp11-gpu-x8a.py')

COLLAPSE_CLEAR = "    s.update('GPU_CC_CX_GDSCR', R.GDSC_SW_COLLAPSE, 0)\n    s.udelay(1)\n    s.poll('GPU_CC_CX_GDS_HW_CTRL', R.GDSC_PWR_ON, R.GDSC_PWR_ON, 'gdsc')\n"
RETAIN_FF = "    s.udelay(1)\n    s.update('GPU_CC_CX_GDSCR', R.GDSC_RETAIN_FF, R.GDSC_RETAIN_FF)\n"
# (name, file, old text, new text, equivalent)
MUTANTS = (
    ('park skipped', 'x8a', "out['rcg_park'] = park_rcg(s, 'GMU')", "out['rcg_park'] = 'skipped'", False),
    ('retain_ff before collapse clear', 'x8a', COLLAPSE_CLEAR + RETAIN_FF,
     "    s.update('GPU_CC_CX_GDSCR', R.GDSC_RETAIN_FF, R.GDSC_RETAIN_FF)\n" + COLLAPSE_CLEAR, False),
    ('no hub parent check', 'x8a', "if not hub_source_ready(source, s.survey['GCC_PROC_VOTE_ENA']):", "if False:", False),
    ('hub accepts PLL1', 'x8a', "return (source == R.RCG_SRC_XO or", "return (source in (R.RCG_SRC_XO, 3) or", False),
    ('no thermal check', 'x8a', "if not s.board.has('thermal.sensor') or not s.board.has('thermal.stop_c'):", "if False:", False),
    ('quiesce does not wait for GX off', 'x8a', "status = s.poll('GMU_SPTPRAC_PWR_CLK_STATUS', 0x1, 0x1, 'oob')", "status = 0", False),
    ('no FAL veto', 'x8a', "    s.wr('GPU_GMU_CX_GMU_CX_FAL_INTF', 1)\n", "", False),
    ('no TCM retention', 'x8a', "    s.wr('CX_MISC_TCM_RET_CNTL', 1)\n", "", False),
    ('no boot config', 'x8a', "    s.wr('GMU_CM3_BOOT_CONFIG', GMU_BOOT_CONFIG_VALUE)\n", "", False),
    ('no M3 config', 'x8a', "    s.wr('GMU_CM3_CFG', GMU_CM3_CFG_VALUE)\n", "", False),
    ('fence range value', 'x8a', "| 0x32 << 18 | 0x8a0", "| 0x32 << 18 | 0x8c0", False),
    ('copy limit 4 MiB', 'x8a', "MAX_COPY_BYTES = 1 << 20 ", "MAX_COPY_BYTES = 4 << 20 ", False),
    ('survey reads GX', 'x8a', "'GPU_CC_HUB_RCG_CFG', 'GPU_CC_XO_RCG_CMD')", "'GPU_CC_HUB_RCG_CFG', 'GPU_CC_XO_RCG_CMD', 'GPU_RBBM_STATUS')", False),
    ('HW control ignored', 'x8a', "    if gdscr & R.GDSC_HW_CONTROL:\n        return 'hw_control'\n", "", False),
    ('CX status from GDSCR', 'x8a', "not values['GPU_CC_CX_GDS_HW_CTRL'] & R.GDSC_PWR_ON", "not values['GPU_CC_CX_GDSCR'] & R.GDSC_PWR_ON", False),
    ('no late SError poll', 'x8a', "proxy.read64(previous['address'])", "pass", False),
    ('HFI table to the iova', 'x8a', "s.dram_write(table.phys, hfi_table_words(table))", "s.dram_write(table.iova, hfi_table_words(table))", False),
    ('no chip id', 'x8a', "    s.wr('GMU_GENERAL_10', GMU_CHIPID_WORD)\n", "", False),
    ('error word ignored', 'x8a', "if response[2] != 0:", "if False:", False),
    ('ack header not matched', 'x8a', " or response[1] != header:", ":", False),
    ('rsc review ignored', 'x8a', "if s.board.data.get('rsc', {}).get('reviewed') is not True:", "if False:", False),
    ('warm GMU accepted', 'x8a', "    if out.get('tcm_retained'):\n", "    if False:\n", False),
    ('collapse a GDSC that is not ours', 'x8a', "            if s.owned_gdsc:\n", "            if True:\n", False),
    ('SError not fatal', 'session', "if self.guarded and getattr(problem, 'status', None) in (q1n1proxy.S_SERROR, q1n1proxy.ST_XFRERR):", "if False:", False),
    ('lost link not fatal', 'session', "if isinstance(problem, q1n1proxy.ProxyTimeout):", "if False:", False),
    ('owned branches not tracked', 'x8a', "        s.owned.append(name)\n", "        pass\n", False),
    ('arena check off', 'session', "        if not any(a.contains_phys(address, size) for a in self.arenas):\n            raise Refused(f'DRAM {address:#x}+{size:#x} is outside every arena of the descriptor')\n", "        pass\n", False),
    ('writes-off check in run only', 'x8a', "            if STAGE_PLAN[index]['writes'] and not allow_writes:", "            if False:", True),
    ('gx domain check off in session', 'session', "(reg.domain == 'GX' and 'gx_on' not in self.proven)", "False", True),
    ('write abort ignored', 'session', "        faults = self.p.get_exc_count()\n        if faults:\n            self.dead = True\n            raise AbortStop(self.step, f'write",
     "        faults = self.p.get_exc_count()\n        if False:\n            self.dead = True\n            raise AbortStop(self.step, f'write", False),
    ('read abort ignored', 'session', "if value == MARKER32 and self.p.get_exc_count():", "if False:", False),
    ('dead session still talks', 'session', "        if self.dead:\n            raise Refused('the link is dead (SError, abort or no answer): nothing more is sent to the GPU')\n", "", False),
    ('S5 does not need hfi', 'x8a', "for gate in ('gmu_up', 'cx_on', 'hfi'):", "for gate in ('gmu_up', 'cx_on'):", False),
    ('halt steps not required', 'x8a', "    s.board.need('ring.halt_steps')\n", "", False),
    ('CP halt skipped in quiesce', 'x8a', "if 'S6' in s.wrote and 'gx_on' in s.proven:", "if False:", False),
    ('quiesce failure keeps exit 0', 'x8a', "        if out.get('quiesce_left') and code == 0:", "        if False:", False),
    ('SMMU read without its clocks', 'x8a', "    if smmu_gate(values):", "    if True:", False),
    ('survey CX reads without gate', 'x8a', "    if out['cx_gate'] != 'on':\n        out['note']", "    if False:\n        out['note']", False),
    ('GPUCC read without AHB', 'x8a', "    if not running(R.REGS['GCC_GPU_CFG_AHB_CBCR'], values['GCC_GPU_CFG_AHB_CBCR']):", "    if False:", False),
    ('segments unchecked', 'x8a', "offset + size > window[1] or source + size > len(image)", "False", False),
    ('image hash unchecked', 'x8a', "if len(data) != size or hashlib.sha256(data).hexdigest() != want:", "if False:", False),
    ('reset not released', 'x8a', "    s.wr('GMU_CM3_SYSRESET', 0)\n    s.poll", "    s.poll", False),
    ('wrong firmware rule', 'x8a', "(None, 0x1ff, 0x100))", "(None, 0xffffffff, 0x100))", False),
    ('oob ack bit', 'x8a', "OOB_GPU_SET_ACK_BIT, OOB_GPU_SET_CLEAR_BIT = 30, 31, 31", "OOB_GPU_SET_ACK_BIT, OOB_GPU_SET_CLEAR_BIT = 30, 30, 31", False),
    ('table: GX register gate', 'regs', "gate='gx_on', domain='GX')\n# RBBM_SECVID", "gate='cx_on', domain='GX')\n# RBBM_SECVID", False),
    ('table: SMMU gate', 'regs', "'smmu': ('CX', 'cx_smmu'),", "'smmu': ('CX', 'cx_on'),", False),
    ('fake: GX check off', 'fake', "            if not self.gx_on:\n                self.violate('gx'", "            if False:\n                self.violate('gx'", False),
)


def run(name, kind, old, new):
    source = (TOOLS / FILES[kind]).read_text()
    if old not in source:
        return 'BAD MUTANT: the text to mutate is not in the source'
    directory = WORK / name.replace(' ', '_').replace(':', '')
    (directory / 'tools').mkdir(parents=True)
    for file in COPIED:
        shutil.copy(TOOLS / file, directory / 'tools' / file)
    (directory / 'tools' / FILES[kind]).write_text(source.replace(old, new, 1))
    done = subprocess.run([sys.executable, '-B', str(directory / 'tools' / 'test-sp11-gpu-x8a.py')], capture_output=True, text=True,
                          cwd=str(directory), timeout=300)
    shutil.rmtree(directory)
    if done.returncode == 0:
        return 'SURVIVED'
    return 'killed: ' + (done.stdout + done.stderr).strip().splitlines()[-1][:100]


def main():
    shutil.rmtree(WORK, ignore_errors=True)
    WORK.mkdir(parents=True)
    survivors, equivalent = [], []
    try:
        for name, kind, old, new, is_equivalent in MUTANTS:
            verdict = run(name, kind, old, new)
            print(f'{name:<36} {verdict}', flush=True)
            if verdict.startswith(('SURVIVED', 'BAD')):
                (equivalent if is_equivalent and verdict == 'SURVIVED' else survivors).append(name)
    finally:
        shutil.rmtree(WORK, ignore_errors=True)
    print(f'{len(MUTANTS)} mutants: {len(MUTANTS) - len(survivors) - len(equivalent)} killed, {len(equivalent)} equivalent (a rule enforced twice), '
          f'{len(survivors)} surviving')
    if survivors:
        print('FAIL: a mutant the test does not catch:', ', '.join(survivors))
        return 1
    print('PASS: every mutant that is not an equivalent one is caught (offline, no hardware)')
    return 0


if __name__ == '__main__':
    sys.exit(main())
