# SPDX-License-Identifier: MIT
"""The checked access path of the SP11 GPU host model (Adreno X1-85): the board descriptor, and the Session that checks,
performs and logs every access. Split from tools/sp11_gpu_x8a.py, which holds the stages.

HOST MODEL ONLY. Nothing here has run on a Surface Pro 11 and nothing authorises a run. Counterpart of the Session of
tools/a16gpu.py (same gates, guard handling and exit codes): 0 done, 2 an abort criterion stopped the run, 3 SError or
abort, 4 no SError guard, 5 the target stopped answering (a possible bus hang: nothing more is sent), 6 the tool refused an
access its own rules forbid.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import time

TOOLS = Path(__file__).resolve().parent
sys.path.insert(0, str(TOOLS))
import sp11_gpu_regs as R  # noqa: E402

_spec = importlib.util.spec_from_file_location('q1n1proxy', TOOLS / 'q1n1proxy.py')
q1n1proxy = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(q1n1proxy)

BOARD_SCHEMA = 'sp11-gpu-board/1'
POLL_LIMITS = {'gdsc': 20, 'branch': 10, 'rcg': 10, 'rsc': 20, 'gmu': 50, 'hfi': 50, 'oob': 50, 'ring': 100}
POLL_BUDGET_S = {'gdsc': 1.0, 'branch': 0.5, 'rcg': 0.5, 'rsc': 1.0, 'gmu': 2.0, 'hfi': 2.0, 'oob': 2.0, 'ring': 2.0}
MARKER32 = q1n1proxy.GUARD_MARKER & 0xFFFFFFFF


class Stop(Exception):
    """An abort criterion: stop touching the hardware and write down what is known."""
    exit_code = 2

    def __init__(self, step, reason, **detail):
        super().__init__(f'{step}: {reason}')
        self.step, self.reason, self.detail = step, reason, detail


class SErrorStop(Stop):
    exit_code = 3


class AbortStop(Stop):
    exit_code = 3


class PollTimeout(Stop):
    pass


class GuardMissing(Stop):
    exit_code = 4


class LinkLost(Stop):
    exit_code = 5


class Refused(Exception):
    """The request breaks a rule of this tool (an unlisted register, a gate not proven, a null value). Nothing was sent."""
    exit_code = 6


def hx(value):
    return f'{value:#010x}'


def serror_json(state):
    return {'mechanism': q1n1proxy.SERROR_MECHANISMS.get(state['mechanism'], state['mechanism']),
            'strict': bool(state['flags'] & q1n1proxy.SERROR_STRICT), 'checks': state['checks'], 'before': state['before'],
            'during': state['during'], 'refused': state['refused'], 'unconsumed': state['unconsumed'],
            'last_when': q1n1proxy.SERROR_WHEN.get(state['last_when']), 'last_address': hex(state['last_address'])}


# --- the board descriptor --------------------------------------------------------------------------------------------------
def as_int(value, where):
    if value is None:
        return None
    if isinstance(value, str):
        value = int(value, 0)
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise Refused(f'board descriptor: {where} is not a non-negative integer')
    return value


class Arena:
    """A DRAM region the host writes through the proxy (`phys`) and the GMU sees at `iova`. Both are stated, never assumed equal."""

    def __init__(self, iova, phys, size):
        self.iova, self.phys, self.size = iova, phys, size

    def contains_phys(self, address, size):
        return self.phys <= address and address + size <= self.phys + self.size

    def phys_of(self, iova):
        if not self.iova <= iova < self.iova + self.size:
            raise Refused(f'iova {iova:#x} is outside the arena at {self.iova:#x}+{self.size:#x}')
        return self.phys + (iova - self.iova)


class Board:
    """What the unit's descriptor says. Public Linux facts fill the register blocks; everything else is null until the
    operator supplies it, and `need` refuses a null before a stage writes anything."""

    def __init__(self, data=None):
        data = dict(data or {})
        if data.get('schema', BOARD_SCHEMA) != BOARD_SCHEMA:
            raise Refused(f'board descriptor: schema {data.get("schema")!r}, expected {BOARD_SCHEMA!r}')
        self.data = data
        self.blocks = {k: v[0] for k, v in R.BOARD_PUBLIC.items()}
        self.overrides = {}
        for key, value in (data.get('blocks') or {}).items():
            if key not in R.BOARD_PUBLIC:
                raise Refused(f'board descriptor: unknown block {key!r}')
            base = as_int(value, f'blocks.{key}')
            if base is not None and base % 4:
                raise Refused(f'board descriptor: blocks.{key} is not 4-byte aligned')
            if base != R.BOARD_PUBLIC[key][0]:
                self.overrides[key] = base
            self.blocks[key] = base

    def base(self, block):
        base = self.blocks.get(block)
        if base is None:
            raise Refused(f'board descriptor: block {block} has no base address (null)')
        return base

    def need(self, path):
        """The value at a dotted path, or a refusal naming it."""
        node = self.data
        for part in path.split('.'):
            node = node.get(part) if isinstance(node, dict) else None
        if node is None:
            raise Refused(f'board descriptor: {path} is null; the stage that needs it refuses')
        return node

    def has(self, path):
        try:
            self.need(path)
            return True
        except Refused:
            return False

    def arena(self, path):
        node = self.need(path)
        values = [as_int(node.get(k) if isinstance(node, dict) else None, f'{path}.{k}') for k in ('iova', 'phys', 'size')]
        if None in values:
            raise Refused(f'board descriptor: {path} needs iova, phys and size (null)')
        iova, phys, size = values
        if size == 0 or iova % 4096 or phys % 4096 or size % 4096 or iova + size > 1 << 32:
            raise Refused(f'board descriptor: {path} must be 4 KiB aligned, non-empty, and below 4 GiB as the GMU sees it')
        return Arena(iova, phys, size)

    def sha256(self):
        canonical = json.dumps({'data': self.data, 'blocks': self.blocks}, sort_keys=True, separators=(',', ':'))
        return hashlib.sha256(canonical.encode()).hexdigest()


def load_board(path=None):
    if path is None:
        return Board()
    with open(path) as f:
        return Board(json.load(f))


# --- the only path to the hardware -----------------------------------------------------------------------------------------
class Session:
    """Checks, performs and logs every access. A register must be named in sp11_gpu_regs, its gate must be proven, a write
    needs allow_writes, a GX register is refused until the GMU has said GX is on, and DRAM is touched only inside arenas the
    descriptor names."""

    def __init__(self, proxy, board, allow_writes=False, guarded=True, clock=time.monotonic):
        self.p, self.board = proxy, board
        self.allow_writes, self.guarded, self.clock = allow_writes, guarded, clock
        self.proven = {'always': 'AO'}
        self.log, self.polls, self.step = [], [], 'setup'
        self.dead = False                  # an SError, an abort or a lost link: no more GPU accesses
        self.silent = False                # the link itself is lost: no traffic at all
        self.wrote = set()                 # stages that wrote (or tried to), by their two-character id
        self.owned = []                    # branches this run turned on, for S7
        self.owned_gdsc = False            # S1 powered (or asked to power) the CX GDSC, so S7 gives that vote back
        self.arenas = []                   # DRAM the host may touch
        self.oob_requested = False         # a GPU_SET request is being written: GX may be powering up
        self.survey = {}                   # raw values of S0 (ints)

    def prove(self, gate, evidence):
        self.proven[gate] = evidence

    def withdraw(self, gate):
        self.proven.pop(gate, None)

    def _check(self, reg, write):
        if self.dead:
            raise Refused('the link is dead (SError, abort or no answer): nothing more is sent to the GPU')
        if reg.gate == 'never' or (reg.domain == 'GX' and 'gx_on' not in self.proven):
            raise Refused(f'{reg.name} ({reg.domain}/{reg.gate}) is not touched before the GMU reports GX on')
        if reg.gate not in self.proven:
            raise Refused(f'{reg.name} needs gate {reg.gate}; proven: {sorted(self.proven)}')
        if write and ('w' not in reg.access or not self.allow_writes):
            raise Refused(f'write to {reg.name} not allowed (access {reg.access!r}, writes {"on" if self.allow_writes else "off"})')
        if not write and 'r' not in reg.access:
            raise Refused(f'{reg.name} is not readable')

    def _addr(self, name, index):
        if name not in R.REGS:
            raise Refused(f'{name} is not in tools/sp11_gpu_regs.py')
        reg = R.REGS[name]
        if reg.off is None:
            raise Refused(f'{name} has no cited offset (null)')
        return reg, reg.at(self.board.base(reg.block), index)

    def _note(self, op, reg, addr, value=None, **extra):
        entry = {'seq': len(self.log), 'step': self.step, 'op': op, 'reg': reg.name if reg else None, 'addr': hx(addr),
                 'domain': reg.domain if reg else 'DRAM'}
        if value is not None:
            entry['value'] = hx(value)
        entry.update(extra)
        self.log.append(entry)

    def _failure(self, problem, op, reg, addr):
        self._note(op, reg, addr, failed=str(problem))
        where = f'{op} {reg.name if reg else "memory"} @ {addr:#010x}'
        if isinstance(problem, q1n1proxy.ProxyTimeout):
            self.dead = self.silent = True
            raise LinkLost(self.step, f'{where}: the target stopped answering (possible bus hang); nothing more is sent')
        if self.guarded and getattr(problem, 'status', None) in (q1n1proxy.S_SERROR, q1n1proxy.ST_XFRERR):
            self.dead = True
            detail = {}
            try:
                detail['serror'] = serror_json(self.p.serror_state())
            except q1n1proxy.ProxyRemoteError as unreadable:
                detail['serror_unreadable'] = str(unreadable)
            raise SErrorStop(self.step, f'SError or abort at {where}; nothing more is sent to the GPU', **detail)
        raise Stop(self.step, f'{where}: proxy error {problem}')

    def _after_write(self, reg, addr):
        faults = self.p.get_exc_count()
        if faults:
            self.dead = True
            raise AbortStop(self.step, f'write {reg.name} @ {addr:#010x}: synchronous abort ({faults})')

    def _stage_wrote(self):
        self.wrote.add(self.step[:2])

    def rd(self, name, index=0):
        reg, addr = self._addr(name, index)
        self._check(reg, write=False)
        try:
            value = int(self.p.read32(addr)) & 0xFFFFFFFF
        except q1n1proxy.ProxyError as problem:
            self._failure(problem, 'read', reg, addr)
        if value == MARKER32 and self.p.get_exc_count():
            self._note('read', reg, addr, value, abort=True)
            self.dead = True
            raise AbortStop(self.step, f'read {name} @ {addr:#010x}: synchronous abort (guard marker)')
        self._note('read', reg, addr, value)
        return value

    def wr(self, name, value, index=0):
        reg, addr = self._addr(name, index)
        self._check(reg, write=True)
        self._stage_wrote()
        try:
            self.p.write32(addr, value & 0xFFFFFFFF)
        except q1n1proxy.ProxyError as problem:
            self._failure(problem, 'write', reg, addr)
        self._note('write', reg, addr, value & 0xFFFFFFFF)
        self._after_write(reg, addr)

    def update(self, name, mask, bits):
        """regmap_update_bits: read, change only mask, write if it differs. Returns the register's new value."""
        old = self.rd(name)
        new = (old & ~mask) | (bits & mask)
        if new != old:
            self.wr(name, new)
        return new

    def udelay(self, microseconds):
        self.p.udelay(microseconds)
        self.log.append({'seq': len(self.log), 'step': self.step, 'op': 'udelay', 'us': microseconds})

    def poll(self, name, mask, want, kind, index=0):
        limit, deadline = POLL_LIMITS[kind], self.clock() + POLL_BUDGET_S[kind]
        value, attempt = 0, 0
        for attempt in range(1, limit + 1):
            value = self.rd(name, index)
            if value & mask == want:
                self.polls.append({'reg': name, 'reads': attempt, 'ok': True})
                return value
            if self.clock() > deadline:
                break
        self.polls.append({'reg': name, 'reads': attempt, 'ok': False})
        raise PollTimeout(self.step, f'{name} = {hx(value)}: (value & {mask:#x}) != {want:#x} after {attempt} reads',
                          reg=name, value=hx(value))

    # GMU TCM windows: the window size comes from the descriptor, never from an assumption.
    def _window(self, name, byte_offset):
        key = 'firmware.gmu.itcm_size' if 'ITCM' in name else 'firmware.gmu.dtcm_size'
        size = as_int(self.board.need(key), key)
        if byte_offset < 0 or byte_offset % 4 or byte_offset + 4 > size:
            raise Refused(f'{name}+{byte_offset:#x} is outside the {size:#x}-byte window of the descriptor')
        reg, base = self._addr(name, 0)
        return reg, base + byte_offset

    def wr_at_window(self, name, byte_offset, value):
        reg, addr = self._window(name, byte_offset)
        self._check(reg, write=True)
        self._stage_wrote()
        try:
            self.p.write32(addr, value & 0xFFFFFFFF)
        except q1n1proxy.ProxyError as problem:
            self._failure(problem, 'write', reg, addr)
        self._note('write', reg, addr, value & 0xFFFFFFFF, window=name)
        self._after_write(reg, addr)

    def rd_at_window(self, name, byte_offset):
        reg, addr = self._window(name, byte_offset)
        self._check(reg, write=False)
        try:
            value = int(self.p.read32(addr)) & 0xFFFFFFFF
        except q1n1proxy.ProxyError as problem:
            self._failure(problem, 'read', reg, addr)
        self._note('read', reg, addr, value, window=name)
        return value

    # DRAM: only inside the arenas a stage registered from the descriptor.
    def allow_dram(self, arena):
        self.arenas.append(arena)

    def _arena_for(self, address, size):
        if not any(a.contains_phys(address, size) for a in self.arenas):
            raise Refused(f'DRAM {address:#x}+{size:#x} is outside every arena of the descriptor')

    def dram_write(self, address, words):
        if not self.allow_writes:
            raise Refused('DRAM write with writes off')
        if self.dead:
            raise Refused('the link is dead: nothing more is sent')
        self._arena_for(address, 4 * len(words))
        self._stage_wrote()
        try:
            self.p.writemem(address, b''.join((w & 0xFFFFFFFF).to_bytes(4, 'little') for w in words))
        except q1n1proxy.ProxyError as problem:
            self._failure(problem, 'writemem', None, address)
        self._note('writemem', None, address, size=4 * len(words))

    def dram_read(self, address, count):
        if self.dead:
            raise Refused('the link is dead: nothing more is sent')
        self._arena_for(address, 4 * count)
        try:
            data = self.p.readmem(address, 4 * count)
        except q1n1proxy.ProxyError as problem:
            self._failure(problem, 'readmem', None, address)
        return [int.from_bytes(data[i:i + 4], 'little') for i in range(0, 4 * count, 4)]
