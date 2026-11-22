#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""The host side of the payload write table (platform/uefi/sp11-payload-wtab-abi.h, docs/SP11-PAYLOAD-WTAB.md).

    python3 tools/sp11_wtab.py check  TABLE.json            # every refusal rule, then the author's own (provenance, windows)
    python3 tools/sp11_wtab.py sha    TABLE.json            # SHA-256 of the packed table: the one the runner prints and the operator quotes
    python3 tools/sp11_wtab.py emit-c TABLE.json            # the C header a payload includes (to stdout)
    python3 tools/sp11_wtab.py note   TABLE.json [--payload-sha HEX] [--payload NAME] [--runner-sha HEX]   # the approval note (to stdout)
    python3 tools/sp11_wtab.py decode BLOB                  # a packed table (a file) back to text; refuses what the runner refuses (a draft is shown: the runner's gate refuses it)

A table is a JSON file: the author's claim of every device word a payload may change, with, for each row, why, from which source and
with which evidence label. The packed blob (header, rows, windows) is what the payload carries and the runner executes; the rest of the
JSON (why, source, label, the allowed device blocks) is for the approval note and is never in the blob.

validate_blob() holds the runner's refusal rules (platform/uefi/sp11-payload-wtab.c, q1n1_wtab_validate) on raw bytes, in the same order and
with the same names: tools/test-q1n1-sp11-payload-wtab.py runs both on thousands of damaged tables and demands the same answer.
Nothing here touches a device, a stick or the network. Hardware: NOT RUN. Evidence: EXPERIMENTAL (host tool)."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import sys

MAGIC = int.from_bytes(b'Q1N1WTB1', 'little')
OPS_MAGIC = int.from_bytes(b'Q1N1WOP1', 'little')
VERSION = 1
ROWS_MAX, WINDOWS_MAX, STEPS_MAX = 48, 8, 16
PAUSE_MAX_S = 30
POLL_MAX_US, DELAY_MAX_US = 100000, 1000
LINES_MAX, REFUSED_LINES = 32, 2
F_RESTORE_AT_END, F_ALLOW_IRREVERSIBLE = 1, 2
UNDO_NONE, UNDO_RESTORE, UNDO_VALUE = 0, 1, 2
UNDO_NAMES = {UNDO_NONE: 'none', UNDO_RESTORE: 'restore', UNDO_VALUE: 'value'}
FLAG_NAMES = {'restore_at_end': F_RESTORE_AT_END, 'allow_irreversible': F_ALLOW_IRREVERSIBLE}

HEADER = struct.Struct('<Q7I3I16s')
ROW = struct.Struct('<9I2H4B4I4H8s3I')
WINDOW = struct.Struct('<4I')
assert (HEADER.size, ROW.size, WINDOW.size) == (64, 88, 16)

# The order of the C enum (X macro Q1N1_WTAB_REASONS in the ABI header); a test compares the two.
REASONS = ('OK', 'SIZE_SHORT', 'MAGIC', 'VERSION', 'HEADER_RESERVED', 'COUNTS', 'BYTES', 'FLAGS', 'PAUSE', 'NAME',
           'ROW_ADDR', 'ROW_MASK_VALUE', 'ROW_CHECK', 'ROW_FOUND', 'ROW_NO_FOUND', 'ROW_NEVER_WRITES', 'ROW_NO_READBACK', 'ROW_RB', 'ROW_RB_CONTRADICTS',
           'ROW_TIMES', 'ROW_UNDO', 'ROW_UNDO_RB', 'ROW_STEP', 'ROW_RESERVED', 'ROW_TAG',
           'WIN_RANGE', 'WIN_AFTER', 'WIN_OVERLAP', 'WIN_ROW_READS', 'STEPS', 'LINES', 'DRAFT',
           'NOT_IN_IMAGE', 'REOPEN', 'ROW_ADDR_TYPE', 'PLATFORM', 'ROW_ATTR',
           'NOT_OPEN', 'INDEX', 'ORDER', 'STOPPED', 'FOUND', 'FAULT', 'SERROR', 'READBACK', 'COUNTER', 'BUDGET', 'WINDOW_READ', 'UNDO_FAILED')
FONT = set('ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 :-./=?()_')
ROW_FIELDS = ('addr', 'mask', 'value', 'found_mask', 'found_value', 'rb_addr', 'rb_mask', 'rb_value', 'rb_timeout_us', 'settle_us', 'after_us',
              'undo_kind', 'res0', 'res1', 'res2', 'undo_value', 'undo_rb_addr', 'undo_rb_mask', 'undo_rb_value', 'undo_timeout_us',
              'undo_after_us', 'step', 'flags', 'tag', 'rsv0', 'rsv1', 'rsv2')


def text_ok(raw, need_nul):
    """Page-font characters up to the first NUL (or the end), then zeros only, at least one character."""
    n = raw.find(b'\0')
    n = len(raw) if n < 0 else n
    if n == 0 or (need_nul and n == len(raw)):
        return False
    return all(chr(c) in FONT for c in raw[:n]) and not any(raw[n:])


class RawRow:
    def __init__(self, raw):
        values = ROW.unpack(raw)
        self.__dict__.update(dict(zip(ROW_FIELDS, values)))


def line_cost(rows):
    """The ordinary lines a table can cost at most: the open line, an ATTR line for each row, one or two lines for each row, a NEXT line for each step that writes."""
    cost, steps = 1 + len(rows), set()
    for r in rows:
        cost += 2 if r.mask else 1
        if r.mask:
            steps.add(r.step)
    return cost + len(steps)


def line_reserve(rows, windows):
    """The lines kept back for what must always be printed: the STOP (or AUTO_UNWIND) line and the END line, a U line and at most one U FAIL line for the undo of
    each write row, and the lines that refuse a read of a window."""
    return 2 + 2 * sum(1 for r in rows if r.mask) + (REFUSED_LINES if windows else 0)


def draft_named(name):
    """The name's text up to its first NUL ends -DRAFT (the author's label for expectations nobody has observed)."""
    text = name.split(b'\0')[0]
    return text.endswith(b'-DRAFT')


def in_window(w, addr):
    return w[0] <= addr < w[0] + w[1]


def row_reason(flags, r, prev):
    check = r.mask == 0
    if not r.addr or r.addr & 3:
        return 'ROW_ADDR'
    if r.value & ~r.mask & 0xffffffff:
        return 'ROW_MASK_VALUE'
    if check and (r.value or r.undo_kind or r.undo_value or r.undo_rb_addr or r.undo_rb_mask or r.undo_rb_value or r.undo_timeout_us or
                  r.undo_after_us or (not r.found_mask and not r.rb_mask)):
        return 'ROW_CHECK'
    if r.found_value & ~r.found_mask & 0xffffffff:
        return 'ROW_FOUND'
    if not check and r.found_mask & r.mask != r.mask:
        return 'ROW_NO_FOUND'
    if not check and r.found_mask & r.mask == r.mask and r.found_value & r.mask == r.value:
        return 'ROW_NEVER_WRITES'
    if not check and not r.rb_mask:
        return 'ROW_NO_READBACK'
    if (not r.rb_addr or r.rb_addr & 3 or r.rb_value & ~r.rb_mask & 0xffffffff) if r.rb_mask else (r.rb_addr or r.rb_value or r.rb_timeout_us):
        return 'ROW_RB'
    if r.rb_mask and r.rb_addr == r.addr and not check and (r.rb_value ^ r.value) & r.rb_mask & r.mask:
        return 'ROW_RB_CONTRADICTS'
    if r.rb_timeout_us > POLL_MAX_US or r.settle_us > DELAY_MAX_US or r.after_us > DELAY_MAX_US or r.undo_after_us > DELAY_MAX_US:
        return 'ROW_TIMES'
    if not check:
        if r.undo_kind > UNDO_VALUE:
            return 'ROW_UNDO'
        if r.undo_kind == UNDO_NONE and (not flags & F_ALLOW_IRREVERSIBLE or r.undo_value or r.undo_rb_addr or r.undo_rb_mask or
                                         r.undo_rb_value or r.undo_timeout_us or r.undo_after_us):
            return 'ROW_UNDO'
        if r.undo_kind == UNDO_RESTORE and r.undo_value:
            return 'ROW_UNDO'
        if r.undo_kind == UNDO_VALUE and (r.undo_value & ~r.mask & 0xffffffff or r.undo_value == r.value):
            return 'ROW_UNDO'
        if r.undo_kind != UNDO_NONE and ((not r.undo_rb_addr or r.undo_rb_addr & 3 or r.undo_rb_value & ~r.undo_rb_mask & 0xffffffff)
                                         if r.undo_rb_mask else (r.undo_rb_addr or r.undo_rb_value)):
            return 'ROW_UNDO_RB'
    if (r.step != prev.step and r.step != prev.step + 1) if prev else r.step != 0:
        return 'ROW_STEP'
    if r.step >= STEPS_MAX:
        return 'ROW_STEP'
    if r.flags or r.res0 or r.res1 or r.res2 or r.rsv0 or r.rsv1 or r.rsv2:
        return 'ROW_RESERVED'
    if not text_ok(r.tag, False):
        return 'ROW_TAG'
    return None


def validate_blob(blob, avail=None, allow_draft=False):
    """(reason name, index): the runner's refusal of `blob` and the row or window it names (None for the header); ('OK', None) when it
    accepts it. `avail` is how many bytes the runner may read (the whole blob by default); `allow_draft` is the runner's build-time Q1N1_WTAB_ALLOW_DRAFT
    (the Makefile never sets it)."""
    avail = len(blob) if avail is None else avail
    if avail < HEADER.size or len(blob) < HEADER.size:
        return 'SIZE_SHORT', None
    magic, version, nbytes, nrows, nwin, flags, pause, steps, r0, r1, r2, name = HEADER.unpack_from(blob)
    if magic != MAGIC:
        return 'MAGIC', None
    if version != VERSION:
        return 'VERSION', None
    if r0 or r1 or r2:
        return 'HEADER_RESERVED', None
    if not nrows or nrows > ROWS_MAX or nwin > WINDOWS_MAX or not steps or steps > STEPS_MAX:
        return 'COUNTS', None
    if nbytes != HEADER.size + ROW.size * nrows + WINDOW.size * nwin or nbytes > avail or nbytes > len(blob):
        return 'BYTES', None
    if flags & ~(F_RESTORE_AT_END | F_ALLOW_IRREVERSIBLE):
        return 'FLAGS', None
    if pause > PAUSE_MAX_S:
        return 'PAUSE', None
    if not text_ok(name, True):
        return 'NAME', None
    rows = [RawRow(blob[HEADER.size + i * ROW.size:HEADER.size + (i + 1) * ROW.size]) for i in range(nrows)]
    base = HEADER.size + ROW.size * nrows
    windows = [WINDOW.unpack_from(blob, base + j * WINDOW.size) for j in range(nwin)]
    for i, r in enumerate(rows):
        reason = row_reason(flags, r, rows[i - 1] if i else None)
        if reason:
            return reason, i
    for j, w in enumerate(windows):
        wbase, size, after, reserved = w
        if not size or wbase & 3 or size & 3 or wbase + size > 1 << 32 or reserved:
            return 'WIN_RANGE', j
        if after >= nrows:
            return 'WIN_AFTER', j
        if any(wbase < o[0] + o[1] and o[0] < wbase + size for o in windows[:j]):
            return 'WIN_OVERLAP', j
        for r in rows[:after + 1]:
            if in_window(w, r.addr) or (r.rb_mask and in_window(w, r.rb_addr)) or (r.undo_kind and r.undo_rb_mask and in_window(w, r.undo_rb_addr)):
                return 'WIN_ROW_READS', j
    if steps != rows[-1].step + 1:
        return 'STEPS', None
    if line_cost(rows) + line_reserve(rows, windows) > LINES_MAX:
        return 'LINES', None
    if not allow_draft and draft_named(name):
        return 'DRAFT', None
    return 'OK', None


# ---- The author's table --------------------------------------------------------------------------------------------------------

def num(value):
    return value if isinstance(value, int) else int(value, 0)


class Row:
    FIELDS = ('tag', 'step', 'addr', 'mask', 'value', 'found_mask', 'found_value', 'rb_addr', 'rb_mask', 'rb_value', 'rb_timeout_us', 'settle_us',
              'after_us', 'undo_kind', 'undo_value', 'undo_rb_addr', 'undo_rb_mask', 'undo_rb_value', 'undo_timeout_us', 'undo_after_us')

    def __init__(self, source):
        s = dict(source)
        self.tag, self.step = s['tag'], int(s['step'])
        self.addr, self.mask, self.value = num(s['addr']), num(s.get('mask', 0)), num(s.get('value', 0))
        found = s.get('found', [0, 0])
        self.found_mask, self.found_value = num(found[0]), num(found[1])
        rb = s.get('readback')
        self.rb_addr, self.rb_mask, self.rb_value, self.rb_timeout_us, self.settle_us = 0, 0, 0, 0, 0
        if rb:
            self.rb_addr, self.rb_mask, self.rb_value = num(rb['addr']), num(rb['mask']), num(rb['value'])
            self.rb_timeout_us, self.settle_us = int(rb.get('timeout_us', 0)), int(rb.get('settle_us', 0))
        self.after_us = int(s.get('after_us', 0))
        undo = s.get('undo') or {'kind': 'none'}
        kind = undo['kind']
        self.undo_kind = {v: k for k, v in UNDO_NAMES.items()}[kind] if isinstance(kind, str) else int(kind)
        self.undo_value = num(undo.get('value', 0))
        urb = undo.get('readback')
        self.undo_rb_addr = self.undo_rb_mask = self.undo_rb_value = 0
        if urb:
            self.undo_rb_addr, self.undo_rb_mask, self.undo_rb_value = num(urb['addr']), num(urb['mask']), num(urb['value'])
        self.undo_timeout_us, self.undo_after_us = int(undo.get('timeout_us', 0)), int(undo.get('after_us', 0))
        self.why, self.source, self.label = s.get('why', ''), s.get('source', ''), s.get('label', '')
        self.rmw = s.get('rmw', '')
        self.effect = s.get('effect', '')
        self.raw_tag = None


class Table:
    def __init__(self, source):
        self.source = source
        self.name = source['name']
        self.flags = 0
        for flag in source.get('flags', []):
            self.flags |= FLAG_NAMES[flag]
        self.pause_s = int(source.get('pause_s', 0))
        self.rows = [Row(r) for r in source['rows']]
        index = {r.tag: i for i, r in enumerate(self.rows)}
        self.windows = []
        for w in source.get('windows', []):
            after = w['after_row']
            self.windows.append((num(w['base']), num(w['size']), index[after] if isinstance(after, str) else int(after), w.get('name', '')))
        self.allowed = [(a['name'], num(a['base']), num(a['size'])) for a in source.get('allowed_windows', [])]
        self.note = source.get('note', {})
        self.draft = list(source.get('draft', []))

    def pack(self):
        rows = b''.join(ROW.pack(r.addr, r.mask, r.value, r.found_mask, r.found_value, r.rb_addr, r.rb_mask, r.rb_value, r.rb_timeout_us,
                                 r.settle_us, r.after_us, r.undo_kind, 0, 0, 0, r.undo_value, r.undo_rb_addr, r.undo_rb_mask, r.undo_rb_value,
                                 r.undo_timeout_us, r.undo_after_us, r.step, 0, r.tag.encode('ascii').ljust(8, b'\0')[:8], 0, 0, 0)
                        for r in self.rows)
        windows = b''.join(WINDOW.pack(b, s, a, 0) for b, s, a, _ in self.windows)
        steps = self.rows[-1].step + 1
        header = HEADER.pack(MAGIC, VERSION, HEADER.size + len(rows) + len(windows), len(self.rows), len(self.windows), self.flags, self.pause_s,
                             steps, 0, 0, 0, self.name.encode('ascii').ljust(16, b'\0')[:16])
        return header + rows + windows

    def sha256(self):
        return hashlib.sha256(self.pack()).hexdigest()


def load(path):
    return Table(json.loads(Path(path).read_text(encoding='utf-8')))


def problems(table, allow_draft=False):
    """Sentences for everything wrong with a table: the runner's refusal first, then what only the author's own fields can show (a row without a
    source or a label, an address outside the blocks the table says it may touch, a write without the evidence that its register is read-modify-write
    safe, an expectation nobody has observed yet: a draft)."""
    found = []
    if table.draft and not allow_draft:
        found += [f'DRAFT: {reason}' for reason in table.draft]
    if bool(table.draft) != table.name.endswith('-DRAFT'):
        found.append('the name of a table ends with -DRAFT exactly when it is a draft: the runner prints the name and the policy tooling refuses the binary')
    if len(table.name) >= 16 or any(len(r.tag) > 8 for r in table.rows):
        found.append('a name of 16 characters or more, or a tag of more than 8: the packed table would cut it')
    reason, index = validate_blob(table.pack(), allow_draft=allow_draft)
    if reason != 'OK':
        found.append(f'the runner refuses the packed table: {reason}' + ('' if index is None else f' at {index}'))
    for r in table.rows:
        if r.mask and not (r.why and r.source and r.label):
            found.append(f'row {r.tag} writes and has no why, source or label')
        if r.mask and not r.rmw:
            found.append(f'row {r.tag} writes and does not say why its register is safe to read, modify and write (no write-one-to-clear bit, no read side effect)')
        if r.mask and not r.effect:
            found.append(f'row {r.tag} writes and does not say what is known of the effect of the write (the label of the found state is not the label of the effect)')
        if r.label not in ('VERIFIED', 'OBSERVED', 'INFERRED', 'EXPERIMENTAL', 'UNKNOWN', ''):
            found.append(f'row {r.tag}: label {r.label!r} is not an evidence label')
        if table.allowed:
            for what, address in (('addr', r.addr), ('readback', r.rb_addr if r.rb_mask else None), ('undo readback', r.undo_rb_addr if r.undo_rb_mask else None)):
                if address is not None and not any(b <= address < b + s for _, b, s in table.allowed):
                    found.append(f'row {r.tag}: {what} {address:#x} is in none of the allowed blocks')
    tags = [r.tag for r in table.rows]
    if len(set(tags)) != len(tags):
        found.append('two rows have the same tag')
    return found


# ---- The C header, the note ----------------------------------------------------------------------------------------------------

def c_name(tag):
    return re.sub(r'[^A-Za-z0-9]', '_', tag).upper()


def emit_c(table, symbol=None):
    """The header a payload includes: the table as a constant of exactly the packed layout, the row count and one index macro for each row."""
    symbol = symbol or f'wtab_{c_name(table.name).lower()}'
    if table.draft:
        notice = [f'/* The write table {table.name}, generated by tools/sp11_wtab.py from its JSON. Do not edit. This table is a DRAFT and is NOT to be approved:',
                  f' * its SHA-256 ({table.sha256()}) only names it, and the runner refuses a draft unless it was built to take one. */']
    else:
        notice = [f'/* The write table {table.name}, generated by tools/sp11_wtab.py from its JSON. Do not edit: the SHA-256 of these bytes is what the',
                  f' * operator approves ({table.sha256()}). */']
    lines = ['/* SPDX-License-Identifier: MIT */', *notice, '#pragma once', '#include "sp11-payload-wtab-abi.h"', '',
             f'#define WTAB_ROWS {len(table.rows)}u', f'#define WTAB_WINDOWS {len(table.windows)}u', f'#define WTAB_DRAFT {1 if table.draft else 0}',
             f'#define WTAB_TABLE_SYMBOL {symbol}']
    for i, r in enumerate(table.rows):
        lines.append(f'#define WROW_{c_name(r.tag)} {i}u')
    lines.append('/* One X(index) per row, in table order: the payload expands it into one straight-line call for each row. */')
    lines.append('#define WTAB_ROW_LIST(X) \\')
    lines.append(' '.join(f'X(WROW_{c_name(r.tag)})' for r in table.rows))
    for j, (base, size, after, name) in enumerate(table.windows):
        lines.append(f'#define WTAB_WINDOW_{j}_BASE {base:#x}u')
        lines.append(f'#define WTAB_WINDOW_{j}_SIZE {size:#x}u')
    lines += ['', f'static const struct {{', '    struct q1n1_wtab_header header;', f'    struct q1n1_wtab_row rows[{len(table.rows)}];']
    if table.windows:
        lines.append(f'    struct q1n1_wtab_window windows[{len(table.windows)}];')
    lines += [f'}} {symbol} = {{', '    .header = {']
    blob = table.pack()
    magic, version, nbytes, nrows, nwin, flags, pause, steps, _, _, _, name = HEADER.unpack_from(blob)
    lines += [f'        .magic = Q1N1_WTAB_TABLE_MAGIC, .version = {version}u, .bytes = {nbytes}u, .rows = {nrows}u, .windows = {nwin}u,',
              f'        .flags = {flags:#x}u, .pause_s = {pause}u, .steps = {steps}u, .name = "{table.name}",', '    },', '    .rows = {']
    for i, r in enumerate(table.rows):
        lines.append(f'        /* {i} {r.tag} */ {{')
        lines.append(f'            .addr = {r.addr:#x}u, .mask = {r.mask:#x}u, .value = {r.value:#x}u, .found_mask = {r.found_mask:#x}u, .found_value = {r.found_value:#x}u,')
        lines.append(f'            .rb_addr = {r.rb_addr:#x}u, .rb_mask = {r.rb_mask:#x}u, .rb_value = {r.rb_value:#x}u, .rb_timeout_us = {r.rb_timeout_us}u,')
        lines.append(f'            .settle_us = {r.settle_us}u, .after_us = {r.after_us}u, .undo_kind = {r.undo_kind}u, .undo_value = {r.undo_value:#x}u,')
        lines.append(f'            .undo_rb_addr = {r.undo_rb_addr:#x}u, .undo_rb_mask = {r.undo_rb_mask:#x}u, .undo_rb_value = {r.undo_rb_value:#x}u,')
        lines.append(f'            .undo_timeout_us = {r.undo_timeout_us}u, .undo_after_us = {r.undo_after_us}u, .step = {r.step}u, .tag = "{r.tag}",')
        lines.append('        },')
    lines.append('    },')
    if table.windows:
        lines.append('    .windows = {')
        for b, s, a, _ in table.windows:
            lines.append(f'        {{.base = {b:#x}u, .size = {s:#x}u, .after_row = {a}u}},')
        lines.append('    },')
    lines += ['};', f'_Static_assert(sizeof {symbol} == {nbytes}, "the generated table is the packed layout");', '']
    return '\n'.join(lines)


def hexs(value):
    return f'{value:#010x}'


def digest_text(value, what):
    """A SHA-256 the note quotes: 64 hex digits in either case, written in lower case; None is "not given". Anything else is an error, not a line of a note an operator would quote."""
    if value is None:
        return None
    if not re.fullmatch(r'[0-9a-fA-F]{64}', value):
        raise ValueError(f'{what} is not a SHA-256 (64 hex digits): {value!r}')
    return value.lower()


def render_note(table, payload=None, payload_sha=None, runner_sha=None):
    """The approval note: what the run changes, row by row, what stops it, what a bad outcome costs, the pre-conditions the operator decides, what the operator does when
    it hangs, and the four digests he quotes (this note, the table, the payload, the runner). A draft table has none."""
    if table.draft:
        raise ValueError('a draft table has no approval note: ' + '; '.join(table.draft))
    payload_sha, runner_sha = digest_text(payload_sha, 'the payload digest'), digest_text(runner_sha, 'the runner digest')
    blob = table.pack()
    reason, _ = validate_blob(blob)
    writes = [r for r in table.rows if r.mask]
    out = [f'WRITE TABLE APPROVAL NOTE: {table.name}', '',
           f'table SHA-256   {hashlib.sha256(blob).hexdigest()}  ({len(blob)} bytes, {len(table.rows)} rows, {len(writes)} of them WRITE, {len(table.windows)} read windows)',
           f'runner prints   WTAB ATTR <tag> DEVICE|NORMAL|NONE|UNKNOWN for each of the {len(table.rows)} rows, then '
           f'WTAB OPEN {table.name} ROWS={len(table.rows)} STEPS={table.rows[-1].step + 1} SHA={hashlib.sha256(blob).hexdigest()[:16].upper()}',
           f'payload         {payload or "(not given)"}  SHA-256 {payload_sha or "(not given)"}',
           f'runner          the WTAB=1 runner image  SHA-256 {runner_sha or "(not given)"}',
           f'runner refuses  {"nothing" if reason == "OK" else reason}',
           f'flags           {", ".join(n for n, v in FLAG_NAMES.items() if table.flags & v) or "none"}; a pause of {table.pause_s} s before each step that writes',
           f'lines           {line_cost(table.rows)} ordinary lines at most and {line_reserve(table.rows, table.windows)} kept back for STOP, one U per write row and END, of {LINES_MAX}',
           '', 'ROWS, IN ORDER (a row reads first, writes only the masked bits, reads back, and has an undo that the runner proves)', '']
    for i, r in enumerate(table.rows):
        kind = 'CHECK' if not r.mask else 'WRITE'
        out.append(f'{i:2d} step {r.step} {r.tag:8s} {kind} {hexs(r.addr)}')
        if r.mask:
            out.append(f'     writes bits {hexs(r.mask)} to {hexs(r.value)}, the other bits as they were read (read-modify-write)')
            if r.rmw:
                out.append(f'     read-modify-write is safe because: {r.rmw}')
        if r.found_mask:
            out.append(f'     expects to find {hexs(r.found_value)} under {hexs(r.found_mask)}; any other value stops the run before this row writes')
        if r.rb_mask:
            out.append(f'     read-back {hexs(r.rb_addr)} & {hexs(r.rb_mask)} == {hexs(r.rb_value)} within {r.rb_timeout_us} us (after {r.settle_us} us)')
        if r.mask:
            undo = UNDO_NAMES[r.undo_kind]
            out.append(f'     undo: {undo}' + (f' to {hexs(r.undo_value)}' if r.undo_kind == UNDO_VALUE else ' (the bits go back to what was found)' if r.undo_kind == UNDO_RESTORE
                                              else ' (IRREVERSIBLE)') + (f'; then {hexs(r.undo_rb_addr)} & {hexs(r.undo_rb_mask)} == {hexs(r.undo_rb_value)}' if r.undo_rb_mask else ''))
        if r.why:
            out.append(f'     why: {r.why}  [found state: {r.label}] source: {r.source}')
        if r.mask:
            out.append(f'     effect of this write: {r.effect}')
    out += ['', 'READ WINDOWS (the payload may read them only once the named row is done, and never after a stop or the undo)', '']
    if not table.windows:
        out.append('   none: the payload reads no word behind anything this table switches on')
    for b, s, a, name in table.windows:
        out.append(f'   {name or "window":10s} {hexs(b)} + {s:#x}  opens after row {a} ({table.rows[a].tag})')
    out += ['', 'WHAT THE RUNNER ASKS BEFORE IT RUNS: the table must be well formed and not a draft (a name ending -DRAFT is refused: DRAFT); a row that writes must be at an address that is in no',
            'memory of the firmware\'s map; the platform must be able to read, store, see an SError and count (a counter that does not advance is refused: PLATFORM); and the mapping of',
            'the page of every row is printed (WTAB ATTR <tag> DEVICE|NORMAL|NONE|UNKNOWN: classified as the stk survey does). A row that WRITES needs DEVICE, anything else, an',
            'answer it cannot give included, is refused: ROW_ATTR. A table without a WRITE row only prints them: the line of a CHECK row that reads the word a live row would store to is',
            'the unit\'s answer for that page, and it is kept in the film.', '',
            'WHAT STOPS THE RUN: a read that faults, a found value that is not the expected one, an SError pending before a store, or raised by a store, a read-back or an undo, a store',
            'that faults (the word is then unknown: the row counts as in force and its undo proves it), a read-back that does not match in time, a counter that does not count, a row asked',
            'out of order, a read of a window that is not open. Nothing is retried. On a stop the runner prints WHY, undoes every row it changed in reverse, proves each undo, and prints',
            'END; STOP, one U line per write row and END are never crowded out of the page. A stop never leaves the next row to run.', '',
            'WHAT THE RUNNER REFUSES FOR THE PAYLOAD (not a stop): ops.hex writes only inside the payload\'s stack and ops.puts reads only from its stack or its image, as ops.load32 always',
            'wrote only inside the stack. A payload that hands them another pointer gets nothing; the refusal is counted in REFUSED of the PAYLOAD DONE line and the first one of each op is',
            'a "PAYLOAD OP REFUSED" line of the page. Any such line in a film means the payload is not the reviewed one.', '',
            'EXPOSURE: what a bad outcome costs. The worst outcomes are a hang and a board reset: the runner cannot recover a hang (see HANG), and a reset takes every earlier line of the page',
            'with it unless it was filmed. ' + (f'The run changes {len(writes)} device word{"s" if len(writes) != 1 else ""} ({", ".join(f"{r.tag} {hexs(r.addr)}" for r in writes)}) and puts '
                                                f'{"it" if len(writes) == 1 else "them"} back and, by the reviewed bytes of the payload named above, nothing else; a hang during the change leaves it changed '
                                                'until a hard power-off.'
                                                if writes else 'This table writes no device word: no store is made, no undo is needed, and by the reviewed bytes of the payload named above nothing else is stored to a device word.'),
            'The run writes no storage: it reads the stick at start and never modifies it (the QEMU test holds that no file of the stick changes), and the unit\'s SSD is not touched.',
            'Recovery is a power cycle. INFERRED, never observed on the unit: a hard power-off returns every register this table touches to its power-on state.', '',
            'PRE-CONDITIONS, decided by the operator and written here (the runner cannot know them; a line left blank is a run not started):',
            '  1. AC power connected, or battery at 50 % or more (AGENTS.md hardware safety rule): ____________________',
            '  2. one hardware client only: no other session on the unit\'s link, no other run in progress: ____________________',
            '  3. film from the Shell countdown until 2 minutes after PAYLOAD DONE (10 minutes if there is none): ____________________']
    if writes:
        out += ['  4. thermal: the runner has no thermal service, so the operator reads the SoC sensors before the boot (the tsnap payload prints them) and writes the baseline and the',
                '     threshold above which the run is not started: baseline ______ C, threshold ______ C. A write with no thermal read is the operator\'s written decision: ____________________']
    else:
        out += ['  4. thermal: not needed, this table writes nothing.']
    out += ['', 'HOW TO READ A HANG: the WTAB ATTR lines are printed at open, one for each row in table order. A stop with no WTAB line after PAYLOAD CALL is in the open itself (the counter',
            'check or the page walk of the first row); a stop after fewer ATTR lines than the table has rows is in the page walk of the first row that has no ATTR line yet. After the ATTR',
            'lines the last line of a row says where the run is: a stop after the line "C n", "S n" or "R n" is in row n + 1 (its read, then its store and read-back), a stop on a "W n"',
            'line is the store of row n itself, and a stop on a "NEXT STEP" line is its pause. A stop right after the line of a check row',
            'may also be in the payload\'s own reads between two rows' + (f' ({table.note["reads"]})' if 'reads' in table.note else '') + ' and not in the next row.', '']
    for key in ('hang', 'unknown', 'after'):
        if key in table.note:
            out.append(f'{key.upper()}: {table.note[key]}')
    out += ['', 'APPROVAL: the operator quotes four SHA-256 values: of this note, of the table above, of the payload and of the runner image named above (a run with another payload or',
            'another runner is not the approved run).', '']
    return '\n'.join(out)


def decode(blob, allow_draft=True):
    reason, index = validate_blob(blob, allow_draft=allow_draft)
    if reason != 'OK':
        return f'REFUSED {reason}' + ('' if index is None else f' AT {index}')
    magic, version, nbytes, nrows, nwin, flags, pause, steps, _, _, _, name = HEADER.unpack_from(blob)
    out = [f'table {name.rstrip(bytes(1)).decode()} rows={nrows} windows={nwin} flags={flags:#x} pause_s={pause} steps={steps} sha256={hashlib.sha256(blob[:nbytes]).hexdigest()}']
    for i in range(nrows):
        r = RawRow(blob[HEADER.size + i * ROW.size:HEADER.size + (i + 1) * ROW.size])
        out.append(f'  {i:2d} step {r.step} {r.tag.rstrip(bytes(1)).decode():8s} addr={r.addr:#x} mask={r.mask:#x} value={r.value:#x} found={r.found_value:#x}/{r.found_mask:#x} '
                   f'rb={r.rb_addr:#x}/{r.rb_mask:#x}/{r.rb_value:#x}/{r.rb_timeout_us} undo={r.undo_kind}')
    return '\n'.join(out)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    parser.add_argument('command', choices=('check', 'sha', 'emit-c', 'note', 'decode'))
    parser.add_argument('path')
    parser.add_argument('--payload-sha')
    parser.add_argument('--payload')
    parser.add_argument('--runner-sha', help='SHA-256 of the WTAB=1 runner image the run is staged with (named in the note, quoted by the operator)')
    parser.add_argument('--allow-draft', action='store_true', help='check, sha and emit-c a draft table (host model and tests only: a draft has no note)')
    args = parser.parse_args(argv)
    if args.command == 'decode':
        text = decode(Path(args.path).read_bytes())
        print(text)
        return 0 if not text.startswith('REFUSED') else 1
    table = load(args.path)
    found = problems(table, allow_draft=args.allow_draft and args.command != 'note')
    if args.command == 'check':
        for sentence in found:
            print(sentence)
        print('OK' if not found else f'{len(found)} problems')
        return 1 if found else 0
    if found:
        print('\n'.join(found), file=sys.stderr)
        return 1
    if args.command == 'sha':
        print(table.sha256())
    elif args.command == 'emit-c':
        sys.stdout.write(emit_c(table))
    else:
        try:
            sys.stdout.write(render_note(table, args.payload, args.payload_sha, args.runner_sha))
        except ValueError as error:
            print(error, file=sys.stderr)
            return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
