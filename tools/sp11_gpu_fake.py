# SPDX-License-Identifier: MIT
"""FakeSP11: a register and power model of the Surface Pro 11 GPU subsystem, the device of tools/test-sp11-gpu-x8a.py.

HOST ONLY. The model is the author's reading of the cited Linux files (power domains, clocks, GMU, HFI), written here
independently of the tool under test (its own clock lists, ids, bit numbers and constants), not a hardware result.

It models GCC, GPUCC (branches, shared RCGs, the CX and GX GDSCs), the blocks behind the CX GDSC (GMU, RSCC, CX_MISC, SMMU),
the GMU firmware's start, an HFI queue pair in DRAM with an acknowledging GMU, the GMU's out-of-band GX request and the GX
registers. It enforces what the hardware would punish: a GPUCC access without GCC_GPU_CFG_AHB, a GDSC powered up while its
shared RCG sits on a dead parent, a CX-side access while the GDSC may collapse (HW control) or is off (a bus hang or an
SError), any GX access before the GMU says GX is on, a DRAM access outside the descriptor's arenas, and tearing CX or the GMU
down while GX may still be on. Scenario keywords (COLD) make it a faulty device: a GDSC that never comes up, a GMU that never
answers, an RPMh vote refused, an SError or a lost link at a chosen access.
"""
from __future__ import annotations

from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import sp11_gpu_regs as R  # noqa: E402
from sp11_gpu_session import Refused, q1n1proxy as Q  # noqa: E402


class FakeHang(Q.ProxyTimeout):
    """What a bus hang looks like from the host: the link stops answering."""


BASE = {k: v[0] for k, v in R.BOARD_PUBLIC.items()}
# hamoa.dtsi:4184-4197 (gmu node) and 4268-4276 (adreno_smmu node), transcribed here on their own.
GMU_CLOCKS_DT = ('GPU_CC_AHB_CBCR', 'GPU_CC_CX_GMU_CBCR', 'GPU_CC_CXO_CBCR', 'GCC_DDRSS_GPU_AXI_CBCR', 'GCC_GPU_MEMNOC_GFX_CBCR',
                 'GPU_CC_HUB_CX_INT_CBCR', 'GPU_CC_DEMET_CBCR')
SMMU_CLOCKS_DT = ('GPU_CC_HLOS1_VOTE_GPU_SMMU_CBCR', 'GCC_GPU_MEMNOC_GFX_CBCR', 'GCC_GPU_SNOC_DVM_GFX_CBCR', 'GPU_CC_AHB_CBCR')
EXPECTED_CHIPID = 0x07050001              # written out here on purpose: a tool that changes its constant must be caught
OLD_RULE_VERSION, NEW_RULE_VERSION = 0x20010004, 0x20010005
HFI_VOTE_ID, HFI_ACK_ID = 30, 126
HFI_ARENA = {'iova': 0x60010000, 'phys': 0x960010000, 'size': 0x4000}
LOG_ARENA = {'iova': 0x60000000, 'phys': 0x960000000, 'size': 0x4000}

COLD = dict(
    guard=True, mechanism=2,
    gcc_cfg_ahb_on=True, gcc_vote=0, cx_on=False, hw_control=False, off_clock=None, smmu_clocks_on=False,
    gmu_rcg_src=0, hub_rcg_src=0, gdsc_delay=2, gdsc_stuck=False, other_vote=False, branch_delay=1,
    tcs_busy=False, tcm_ret=0, fw_stall=False, hfi_never=False,
    vote_refused=False, ack_wrong_header=False, ack_never=False, oob_ack_never=False, gx_never=False,
    gx_stuck_on=False, gx_delay=2, gx_off_delay=2, ring_stall=False, halt_ack_never=False, secvid_refuse=False,
    serror_at=None, late_serror_at=None, hang_at=None, sync_abort_at=None, write_abort_at=None, end_serror=False,
)


def A(name, index=0):
    reg = R.REGS[name]
    return reg.at(BASE[reg.block], index)


class FakeSP11:
    def __init__(self, board, image_words, **scenario):
        unknown = set(scenario) - set(COLD)
        assert not unknown, unknown
        self.sc = sc = dict(COLD, **scenario)
        self.log, self.violations = [], []              # (op, addr, value, reg name); (kind, address, why)
        self.strict, self.pending_serror, self.exc, self.state_calls = False, False, 0, 0
        self.serror = dict.fromkeys(Q.SERROR_FIELDS, 0)
        self.serror.update(magic=Q.SERROR_MAGIC, mechanism=sc['mechanism'])
        self.by_addr = {}
        for reg in R.REGS.values():
            for i in range(reg.count if reg.off is not None else 0):
                self.by_addr[reg.at(BASE[reg.block], i)] = reg
        self.arena = board.arena('hfi.arena')
        self.arenas = [(self.arena.phys, self.arena.size)]
        self.dram = {}
        self.expect_itcm = dict(image_words)
        # power state
        self.vote = sc['gcc_vote']
        self.enabled = {'GCC_QMIP_GPU_AHB_CBCR', 'GPU_CC_CXO_AON_CBCR', 'GPU_CC_HUB_AON_CBCR', 'GPU_CC_SLEEP_CBCR'}
        if sc['gcc_cfg_ahb_on']:
            self.enabled.add('GCC_GPU_CFG_AHB_CBCR')
        self.rcg = {'GMU': {'cmd': 0, 'cfg': sc['gmu_rcg_src'] << 8, 'upd': 0},
                    'HUB': {'cmd': 0, 'cfg': sc['hub_rcg_src'] << 8, 'upd': 0},
                    'XO': {'cmd': 0, 'cfg': 0, 'upd': 0}}
        self.gdscr = R.GDSC_SW_COLLAPSE
        self.gdsc_on, self.gdsc_pending, self.wedged, self.just_collapsed = False, None, False, False
        if sc['cx_on']:
            self.gdscr = R.CX_GDSC_WAITS | R.GDSC_RETAIN_FF | (R.GDSC_HW_CONTROL if sc['hw_control'] else 0)
            self.gdsc_on = True
            self.enabled |= set(GMU_CLOCKS_DT) - {sc['off_clock']}
            if sc['smmu_clocks_on']:
                self.enabled |= set(SMMU_CLOCKS_DT)
        self.branch_reads = {n: 99 for n in self.enabled}
        # GMU, HFI, OOB, GX
        self.g = {'GMU_CM3_SYSRESET': 1}
        self.itcm, self.dtcm = {}, {}
        self.tcm_ret = sc['tcm_ret']
        self.gmu_running, self.hfi_started, self.intr = False, False, 0
        self.gx_on, self.gx_pending, self.gx_off_pending = False, None, None
        self.gx = {}

    # --- the power model ------------------------------------------------------------------------------------------------
    def source_running(self, cfg):
        return {0: True, 5: bool(self.vote & 1 << 15), 6: bool(self.vote & 1 << 16)}.get(cfg >> 8 & 7, False)

    def branch_running(self, name):
        if name not in self.enabled:
            return False
        if name.startswith('GCC_') or name in ('GPU_CC_CXO_AON_CBCR', 'GPU_CC_HUB_AON_CBCR', 'GPU_CC_SLEEP_CBCR'):
            return True
        if not self.gdsc_on:
            return False
        if name == 'GPU_CC_CX_GMU_CBCR' and not self.source_running(self.rcg['GMU']['cfg']):
            return False
        if name in ('GPU_CC_AHB_CBCR', 'GPU_CC_HUB_CX_INT_CBCR') and not self.source_running(self.rcg['HUB']['cfg']):
            return False
        return self.branch_reads.get(name, 0) >= self.sc['branch_delay']

    def violate(self, kind, addr, why):
        self.violations.append((kind, hex(addr), why))
        if kind in ('hang', 'gx', 'unknown', 'dram', 'unsafe', 'wedge'):
            raise FakeHang(f'{kind} at {addr:#x}: {why}')
        self.raise_serror(addr)

    def raise_serror(self, addr):
        self.serror['during'] += 1
        self.serror.update(last_when=2, last_address=addr)
        if self.strict:
            raise Q.ProxyRemoteError('opcode rejected (status -83)', Q.S_SERROR)

    def check_domain(self, reg, addr):
        if reg.block == 'gcc':
            return
        if reg.block == 'gpucc':
            if self.wedged or not self.branch_running('GCC_GPU_CFG_AHB_CBCR'):
                self.violate('hang', addr, 'GPUCC access without GCC_GPU_CFG_AHB (or a wedged GDSC)')
            return
        if reg.domain == 'GX':
            if not self.gx_on:
                self.violate('gx', addr, f'{reg.name}: GX touched while the GMU has not powered it')
            return
        if self.wedged:
            self.violate('hang', addr, 'CX access behind a wedged GDSC')
        if self.gdsc_on and self.gdscr & R.GDSC_HW_CONTROL:
            self.violate('hang', addr, 'CX access while the GDSC is under HW control and may collapse')
        needed = SMMU_CLOCKS_DT if reg.block == 'smmu' else GMU_CLOCKS_DT
        if not (self.gdsc_on and all(self.branch_running(n) for n in needed)):
            self.violate('serror', addr, f'{reg.name}: CX-side access with the GDSC or a clock off')

    def unsafe_if_gx(self, what, addr):
        if self.gx_on or self.gx_off_pending is not None:
            self.violate('unsafe', addr, f'{what} while GX may still be on')

    # --- proxy surface ---------------------------------------------------------------------------------------------------
    def _before(self, op, addr):
        self.serror['checks'] += 1
        if self.pending_serror:
            self.pending_serror = False
            self.serror['before'] += 1
            self.serror.update(last_when=1, last_address=addr)
            if self.strict:
                self.serror['refused'] += 1
                raise Q.ProxyRemoteError('opcode rejected (status -83)', Q.S_SERROR)

    def _lookup(self, addr):
        for name in ('GMU_CM3_ITCM_START', 'GMU_CM3_DTCM_START'):
            lo = A(name)
            if lo <= addr < lo + 0x4000 and addr % 4 == 0:
                return R.REGS[name], (addr - lo) // 4
        if addr in self.by_addr:
            return self.by_addr[addr], None
        self.violate('unknown', addr, 'an address the model does not know')

    def read32(self, addr):
        self._before('r', addr)
        if self.sc['hang_at'] == (addr, 'r'):
            raise FakeHang(f'bus hang at {addr:#x}')
        reg, word = self._lookup(addr)
        self.check_domain(reg, addr)
        value = self._read(reg, word)
        self.log.append(('r', addr, value, reg.name))
        if self.sc['serror_at'] == (addr, 'r'):
            self.raise_serror(addr)
        if self.sc['late_serror_at'] == (addr, 'r'):
            self.pending_serror = True
        if self.sc['sync_abort_at'] == addr:
            self.exc += 1
            return Q.GUARD_MARKER & 0xFFFFFFFF
        return value

    def write32(self, addr, value):
        self._before('w', addr)
        if self.sc['hang_at'] == (addr, 'w'):
            raise FakeHang(f'bus hang at {addr:#x}')
        reg, word = self._lookup(addr)
        self.check_domain(reg, addr)
        self.log.append(('w', addr, value, reg.name))
        self._write(reg, word, value)
        if self.sc['write_abort_at'] == addr:
            self.exc += 1
        if self.sc['serror_at'] == (addr, 'w'):
            self.raise_serror(addr)
        if self.sc['late_serror_at'] == (addr, 'w'):
            self.pending_serror = True

    def read64(self, addr):
        self._before('r64', addr)
        return Q.SERROR_MAGIC

    def get_exc_count(self):
        count, self.exc = self.exc, 0
        return count

    def udelay(self, microseconds):
        self.log.append(('udelay', microseconds, None, None))

    def _in_arena(self, addr, size):
        return any(lo <= addr and addr + size <= lo + n for lo, n in self.arenas)

    def readmem(self, addr, size, live=False):
        self._before('m', addr)
        if not self._in_arena(addr, size):
            self.violate('dram', addr, 'DRAM read outside the descriptor arenas')
        self.log.append(('m', addr, size, None))
        return b''.join(self.dram.get(addr + i, 0).to_bytes(4, 'little') for i in range(0, size, 4))

    def writemem(self, addr, data):
        self._before('wm', addr)
        if not self._in_arena(addr, len(data)) or addr % 4 or len(data) % 4:
            self.violate('dram', addr, 'DRAM write outside the descriptor arenas, or unaligned')
        self.log.append(('wm', addr, len(data), None))
        for i in range(0, len(data), 4):
            self.dram[addr + i] = int.from_bytes(data[i:i + 4], 'little')

    def _guard(self):
        if not self.sc['guard']:
            raise Q.ProxyRemoteError('opcode 0x5131 rejected (status -1)', -1)

    def serror_state(self):
        self.state_calls += 1
        self._guard()
        return dict(self.serror, flags=int(self.strict), address=0xB0001000)

    def serror_reset(self):
        self._guard()
        for key in ('checks', 'before', 'during', 'refused', 'unconsumed', 'last_syndrome', 'last_when', 'last_opcode', 'last_address'):
            self.serror[key] = 0

    def serror_strict(self, enabled):
        self._guard()
        self.strict = bool(enabled)

    # --- registers -------------------------------------------------------------------------------------------------------
    def branch_value(self, name):
        if name in self.enabled:
            self.branch_reads[name] = self.branch_reads.get(name, 0) + 1
        running = self.branch_running(name)
        return (R.CBCR_ENABLE if name in self.enabled else 0) | (0 if running else R.CBCR_CLK_OFF)

    def _read(self, reg, word):
        n = reg.name
        if word is not None:
            return (self.itcm if 'ITCM' in n else self.dtcm).get(word, 0)
        if n.endswith('_CBCR'):
            return self.branch_value(n)
        if n == 'GCC_PROC_VOTE_ENA':
            return self.vote
        if n == 'GPU_CC_CX_GDSCR':
            return self.gdscr
        if n == 'GPU_CC_CX_CFG_GDSCR':
            return R.GDSC_POWER_UP_COMPLETE if self.gdsc_on else R.GDSC_POWER_DOWN_COMPLETE
        if n == 'GPU_CC_CX_GDS_HW_CTRL':
            if self.gdsc_pending is not None:
                self.gdsc_pending -= 1
                if self.gdsc_pending <= 0:
                    self.gdsc_on, self.gdsc_pending = True, None
            if self.just_collapsed and self.sc['end_serror']:
                self.pending_serror = True
            return R.GDSC_PWR_ON if self.gdsc_on else 0
        if n == 'GPU_CC_GX_GDSCR':
            return 0 if self.gx_on else R.GDSC_SW_COLLAPSE
        if n == 'GPU_CC_GX_CFG_GDSCR':
            return R.GDSC_POWER_UP_COMPLETE if self.gx_on else R.GDSC_POWER_DOWN_COMPLETE
        if n == 'GPU_CC_GX_CLAMP_IO_CTRL':
            return 0 if self.gx_on else 1
        if n.endswith('_RCG_CMD') or n.endswith('_RCG_CFG'):
            rcg = self.rcg[n.split('_')[2]]
            if n.endswith('_CFG'):
                return rcg['cfg']
            cmd = rcg['cmd']
            if rcg['upd'] > 0:
                rcg['upd'] -= 1
                cmd |= R.RCG_UPDATE
            root_on = bool(cmd & R.RCG_ROOT_EN) and self.source_running(rcg['cfg'])
            return cmd | (0 if root_on else R.RCG_ROOT_OFF)
        if n == 'CX_MISC_TCM_RET_CNTL':
            return self.tcm_ret
        if n == 'GMU_CM3_SYSRESET':
            return self.g.get(n, 1)
        if n == 'GMU_SPTPRAC_PWR_CLK_STATUS':
            if self.gx_pending is not None:
                self.gx_pending -= 1
                if self.gx_pending <= 0:
                    self.gx_on, self.gx_pending = not self.sc['gx_never'], None
            if self.gx_off_pending is not None:
                self.gx_off_pending -= 1
                if self.gx_off_pending <= 0:
                    self.gx_on, self.gx_off_pending = False, None
            return 0 if self.gx_on else 0x3
        if n == 'GMU_GMU2HOST_INTR_INFO':
            return self.intr
        if n == 'GMU_HFI_CTRL_STATUS':
            return int(self.hfi_started)
        if n.startswith('RSCC_TCS'):
            return 0 if self.sc['tcs_busy'] and n == 'RSCC_TCS3_DRV0_STATUS' else 1
        if n == 'RSCC_PDC_SEQ_START_ADDR':
            return 0x2a
        if n.startswith('SMMU_'):
            return {'SMMU_ID0': 0x00000a20, 'SMMU_ID1': 0x00010a10, 'SMMU_ID2': 0x14, 'SMMU_ID7': 0x21}.get(n, 0)
        if reg.domain == 'GX':
            if n == 'GPU_RBBM_GBIF_HALT_ACK':
                return int(bool(self.gx.get('GPU_RBBM_GBIF_HALT', 0) & 1) and not self.sc['halt_ack_never'])
            return self.gx.get(n, 0)
        return self.g.get(n, 0)

    def _write(self, reg, word, value):
        n = reg.name
        if word is not None:
            (self.itcm if 'ITCM' in n else self.dtcm)[word] = value
            return
        if n.endswith('_CBCR'):
            if value & R.CBCR_ENABLE:
                self.enabled.add(n)
            else:
                if n in GMU_CLOCKS_DT:
                    self.unsafe_if_gx('a clock of the GMU node disabled', A(n))
                self.enabled.discard(n)
                self.branch_reads.pop(n, None)
            return
        if n == 'GPU_CC_CX_GDSCR':
            old, self.gdscr = self.gdscr, value
            if old & R.GDSC_SW_COLLAPSE and not value & R.GDSC_SW_COLLAPSE:
                if not self.source_running(self.rcg['GMU']['cfg']):
                    self.wedged = True
                    self.violations.append(('wedge', hex(A(n)), 'GDSC powered up with its shared RCG on a dead parent'))
                elif not self.sc['gdsc_stuck']:
                    self.gdsc_pending = self.sc['gdsc_delay']
            if not old & R.GDSC_SW_COLLAPSE and value & R.GDSC_SW_COLLAPSE:
                self.unsafe_if_gx('the CX GDSC collapsed', A(n))
                if not self.sc['other_vote']:
                    self.gdsc_on, self.gdsc_pending, self.just_collapsed = False, None, True
            return
        if n.endswith('_RCG_CMD') or n.endswith('_RCG_CFG'):
            rcg = self.rcg[n.split('_')[2]]
            if n.endswith('_CFG'):
                rcg['cfg'] = value
            else:
                rcg['cmd'] = value & R.RCG_ROOT_EN
                if value & R.RCG_UPDATE:
                    rcg['upd'] = 1
            return
        if n == 'CX_MISC_TCM_RET_CNTL':
            self.tcm_ret = value
            return
        if n == 'GMU_CM3_SYSRESET':
            old = self.g.get(n, 1)
            self.g[n] = value
            if value & 1 and not old & 1:
                self.unsafe_if_gx('the GMU held in reset', A(n))
                self.gmu_running = False
            if not value & 1 and old & 1:
                self.release()
            return
        if n == 'GMU_GMU2HOST_INTR_CLR':
            self.intr &= ~value
            return
        if n == 'GMU_HFI_CTRL_INIT':
            self.hfi_started = bool(value & 1) and self.gmu_running and not self.sc['hfi_never']
            return
        if n == 'GMU_HOST2GMU_INTR_SET':
            self.doorbell(value)
            return
        if reg.domain == 'GX':
            if n == 'GPU_RBBM_SECVID_TRUST_CNTL' and self.sc['secvid_refuse']:
                return
            self.gx[n] = value
            if n == 'GPU_CP_RB_WPTR' and not self.sc['ring_stall']:
                self.gx['GPU_CP_RB_RPTR'] = value
            return
        self.g[n] = value

    # --- the GMU ---------------------------------------------------------------------------------------------------------
    def release(self):
        """What the firmware needs to come up: the image where the tool says it put it, the M3 config, the chip-id word, the boot
        config, the FAL veto and a valid HFI table in DRAM. Anything missing leaves the init result unset."""
        g = self.g
        ok = (self.itcm == self.expect_itcm and g.get('GMU_CM3_CFG') == 0x4052 and g.get('GMU_GENERAL_10') == EXPECTED_CHIPID
              and g.get('GMU_CM3_BOOT_CONFIG') == 2 and g.get('GPU_GMU_CX_GMU_CX_FAL_INTF') == 1
              and g.get('GPU_GMU_CX_GMU_CX_FALNEXT_INTF') == 1 and self.tcm_ret == 1 and self.table_valid()
              and g.get('GMU_CM3_FW_INIT_RESULT') == 0 and not self.sc['fw_stall'])
        if ok:
            version = self.dtcm.get(0xff8, 0)
            self.g['GMU_CM3_FW_INIT_RESULT'] = 0xbabeface if version <= OLD_RULE_VERSION else 0x12345100
            self.gmu_running = True

    def dword(self, iova):
        return self.dram.get(self.arena.phys_of(iova), 0)

    def table_valid(self):
        table = self.g.get('GMU_HFI_QTBL_ADDR')
        if table is None or self.g.get('GMU_HFI_QTBL_INFO') != 1:
            return False
        try:
            head = [self.dword(table + 4 * i) for i in range(6)]
            qh = [self.dword(table + 24 + 4 * i) for i in range(12)]
        except Refused:
            return False
        return head == [0, 168, 6, 12, 3, 3] and qh[0] == 1 and qh[1] == table + 4096 and qh[3] == 1024

    def doorbell(self, value):
        if not self.gmu_running:
            return
        if value & 1 and self.hfi_started:
            self.serve_queue()
        if value >> 30 & 1 and not self.sc['oob_ack_never']:
            self.intr |= 1 << 31
            self.gx_pending = self.sc['gx_delay']
        if value >> 31 & 1 and not value >> 30 & 1 and not self.sc['gx_stuck_on']:
            self.gx_off_pending = self.sc['gx_off_delay'] if self.gx_on else None

    def serve_queue(self):
        table = self.g['GMU_HFI_QTBL_ADDR']
        cmd_hdr, rsp_hdr = table + 24, table + 24 + 48
        rd, wr = self.dword(cmd_hdr + 40), self.dword(cmd_hdr + 44)
        size, data = self.dword(cmd_hdr + 12), table + 4096
        while rd != wr:
            first = self.dword(data + 4 * rd)
            words = [self.dword(data + 4 * ((rd + i) % size)) for i in range(first >> 8 & 0xff)]
            rd = (rd + len(words) + (-(rd + len(words)) % 4)) % size
            if self.sc['ack_never']:
                continue
            ret = words[0] ^ (1 << 20) if self.sc['ack_wrong_header'] else words[0]
            error = 7 if self.sc['vote_refused'] and words[0] & 0xff == HFI_VOTE_ID else 0
            self.respond(rsp_hdr, table + 8192, [HFI_ACK_ID | 3 << 8, ret, error])
        self.dram[self.arena.phys_of(cmd_hdr + 40)] = rd

    def respond(self, header, data, words):
        wr, size = self.dword(header + 44), self.dword(header + 12)
        for i, w in enumerate(words):
            self.dram[self.arena.phys_of(data + 4 * ((wr + i) % size))] = w
        wr = (wr + len(words)) % size
        while wr % 4:
            self.dram[self.arena.phys_of(data + 4 * wr)] = 0xfafafafa
            wr = (wr + 1) % size
        self.dram[self.arena.phys_of(header + 44)] = wr
        self.intr |= 1

    # --- views for the tests ---------------------------------------------------------------------------------------------
    def power_state(self):
        return {'cx_gdsc_on': self.gdsc_on, 'sw_collapse': bool(self.gdscr & R.GDSC_SW_COLLAPSE),
                'gmu_in_reset': bool(self.g.get('GMU_CM3_SYSRESET', 1) & 1), 'gx_on': self.gx_on,
                'cx_clocks_enabled': frozenset(self.enabled & set(GMU_CLOCKS_DT))}

    def accesses(self, *, op=None, blocks=None, since=0):
        found = []
        for i, (kind, addr, value, name) in enumerate(self.log[since:], since):
            if name is None or (op and kind != op):
                continue
            reg = R.REGS[name]
            if blocks is None or (reg.window or reg.block) in blocks:
                found.append((i, kind, name, value))
        return found
