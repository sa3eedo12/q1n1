# SPDX-License-Identifier: MIT
"""Seeded bugs of the payload `inpsnap2` (payloads/inpsnap2.c, payloads/inpsnap2-regs.h) that the host test must refuse, each for its own reason
(tools/test-q1n1-sp11-payload-inpsnap2.py runs them; docs/SP11-PAYLOAD-INPSNAP2-EVIDENCE.md lists them). A mutant is a list of exact, once-only replacements (a needle that is not in the
text exactly once is a stale mutant: an error, never a pass) and names the stage that must refuse it and what that stage must say:

  harness  the native host test (tools/test-q1n1-sp11-payload-inpsnap2.c) built over the mutant exits non-zero, every suite in `suites` is among the ones that FAILED, and its
           diagnostics hold `reason` (the text of the failed check or of the model's violation; for a crash the sanitizer's report)
  caps     the same, built with `defs` (a smaller line or load cap), which runs only the cap suite
  build    the mutant does not compile, and the compiler's message holds `reason` (a static assertion of the payload: a defence the compiler holds)
  audit    the IR audit (tools/sp11_payload_inpsnap2_audit.py) reports a problem that holds `reason`
  binary   the mutant links and the `inpsnap2` policy reports a violation that holds `reason`, or the link refuses it with a message that holds `reason`
  stack    the deepest chain of frames is deeper than the stack the ABI leaves

The audit and binary mutants are never run natively: some of them store to a device address. The mutants of the rows and the lines of the table are generated from the header's text
(one per row and kind, one per line and field); the others are written out below and in tools/sp11_payload_inpsnap2_mutants_more.py. A defence that the shipped table never trips has
a second defence behind it (the room test of a line and of its NEXT line), and the host test calls each of them on its own; the ones without a mutant are listed in the document.
Hardware: NOT RUN. Evidence: EXPERIMENTAL (host model and compiled code only)."""
from collections import namedtuple
from pathlib import Path
import re
import shutil
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import sp11_payload_testlib as lib  # noqa: E402
import sp11_payload_inpsnap2_audit as audit  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
C, H = 'payloads/inpsnap2.c', 'payloads/inpsnap2-regs.h'
STAGES = ('harness', 'caps', 'build', 'audit', 'binary', 'stack')
Mutant = namedtuple('Mutant', 'name edits stage suites reason defs')


def m(name, file, old, new, stage='harness', suites=(), reason='', defs=()):
    return Mutant(name, ((file, old, new),), stage, tuple(suites), reason, tuple(defs))


def mm(name, edits, stage='harness', suites=(), reason='', defs=()):
    return Mutant(name, tuple(edits), stage, tuple(suites), reason, tuple(defs))


# ---- Generated: one mutant per row and kind, one per line and field --------------------------------------------------------------------------------------------------------------------
ROW = re.compile(r'X\((\w+), "(\w+)", (0x[0-9a-f]+), (WIN_\w+), (B_\w+), ([^,]+), (\d+)\)')
LINE = re.compile(r'\{(R_\w+), (R_\w+), (B_\w+), 0, "(\w+)"\}')
NEXT_BLOCK = {'B_GATE': 'B_RCG', 'B_RCG': 'B_PLL', 'B_PLL': 'B_LVL', 'B_LVL': 'B_GATE', 'B_QUP': 'B_LVL'}


def table(root=ROOT):
    text = (Path(root) / H).read_text(encoding='utf-8')
    return ROW.findall(text), LINE.findall(text)


def generated(root=ROOT):
    """The mutants of the table: a row's offset moved one word, its key changed, its block changed; the window of six rows; the flags and vote bits; a line's end, block and head."""
    rows, lines = table(root)
    out = []
    ids = [row[0] for row in rows]
    for rid, key, off, win, block, flags, vbit in rows:
        head = f'X({rid}, "{key}", '
        out.append(m(f'row-offset-{key}', H, f'{head}{off}, ', f'{head}0x{int(off, 16) + 4:0{len(off) - 2}x}, ', suites=('table',), reason=f'r->off == x->off: {key}'))
        out.append(m(f'row-key-{key}', H, head, f'X({rid}, "{key}Q", ', suites=('table',), reason=f'!strcmp(r->key, x->key): {key}'))
        out.append(m(f'row-block-{key}', H, f'{head}{off}, {win}, {block},', f'{head}{off}, {win}, {NEXT_BLOCK[block]},', suites=('table',), reason=f'r->block == x->block: {key}'))
        if key in ('MA0', 'VT0', 'DFS', 'MODE', 'LM3', 'VER'):
            other = 'WIN_QUP' if win == 'WIN_GCC' else 'WIN_GCC'
            out.append(m(f'row-window-{key}', H, f'{head}{off}, {win},', f'{head}{off}, {other},', suites=('table',), reason=f'r->win == x->win: {key}'))
    flags_of = {row[1]: (row[0], row[2], row[3], row[4], row[5], row[6]) for row in rows}

    def flag(name, key, new_flags, new_vbit, reason):
        rid, off, win, block, old_flags, old_vbit = flags_of[key]
        head = f'X({rid}, "{key}", {off}, {win}, {block}, '
        out.append(m(name, H, f'{head}{old_flags}, {old_vbit})', f'{head}{new_flags}, {new_vbit})', suites=('table',), reason=f'{reason}: {key}'))
    for key in ('MA0', 'SA0', 'CR0', 'SE0'):
        rest = [part for part in flags_of[key][4].split(' | ') if part != 'F_CBCR']
        flag(f'flag-clock-dropped-{key}', key, ' | '.join(rest) or '0', flags_of[key][5], '!!(r->flags & F_CBCR) == !!x->kind')
    for key in ('VT0', 'GV', 'CMD', 'VER'):
        flag(f'flag-clock-added-{key}', key, 'F_CBCR', flags_of[key][5], '!!(r->flags & F_CBCR) == !!x->kind')
    for key in ('MA0', 'SA0'):
        flag(f'flag-hwcg-dropped-{key}', key, 'F_CBCR | F_WRAP', flags_of[key][5], '!!(r->flags & F_HWCG) == (x->kind == 2)')
    flag('flag-hwcg-added-CR0', 'CR0', 'F_CBCR | F_HWCG | F_WRAP', 0, '!!(r->flags & F_HWCG) == (x->kind == 2)')
    flag('flag-hwcg-added-SE0', 'SE0', 'F_CBCR | F_HWCG', 0, '!!(r->flags & F_HWCG) == (x->kind == 2)')
    for key in ('MA0', 'SA0', 'CR0'):
        rest = [part for part in flags_of[key][4].split(' | ') if part != 'F_WRAP']
        flag(f'flag-wrapper-dropped-{key}', key, ' | '.join(rest), flags_of[key][5], '!!(r->flags & F_WRAP) == (i <= XR_CR0)')
    flag('flag-wrapper-added-SE0', 'SE0', 'F_CBCR | F_WRAP', 0, '!!(r->flags & F_WRAP) == (i <= XR_CR0)')
    flag('flag-wrapper-added-VT0', 'VT0', 'F_WRAP', 0, '!!(r->flags & F_WRAP) == (i <= XR_CR0)')
    for name, key, new in (('vote-bit-of-MA0-is-7', 'MA0', 7), ('vote-bit-of-MA0-is-5', 'MA0', 5), ('vote-bit-of-SA0-is-6', 'SA0', 6), ('vote-bit-of-SA0-is-8', 'SA0', 8),
                           ('vote-bit-set-on-CR0', 'CR0', 1)):
        flag(name, key, flags_of[key][4], new, 'r->vbit == (i < 2 ? X_VOTE_BIT[i] : 0u)')
    for n, (first, end, block, head) in enumerate(lines):
        text = f'{{{first}, {end}, {block}, 0, "{head}"}}'
        before = 'R_VER' if end == 'R_COUNT' else 'R_' + ids[ids.index(end[2:]) - 1]
        out.append(m(f'line-end-{n}', H, text, f'{{{first}, {before}, {block}, 0, "{head}"}}', suites=('table',), reason=f'd->end == XL_FIRST[l] + XL_COUNT[l]: line {n}'))
        out.append(m(f'line-block-{n}', H, text, f'{{{first}, {end}, {NEXT_BLOCK[block]}, 0, "{head}"}}', suites=('table',), reason=f'd->block == XR_[XL_FIRST[l]].block: line {n}'))
        out.append(m(f'line-head-{n}', H, text, f'{{{first}, {end}, {block}, 0, "{head}X"}}', suites=('table',), reason=f'!strcmp(d->head, XB_HEAD[XR_[XL_FIRST[l]].block]): line {n}'))
    return out


# ---- Written out: the windows, the text of the page and the helpers that build it, the line cap and the check of a line ----------------------------------------------------------------
WINDOWS_AND_TEXT = [
    m('gcc-window-base-moved', H, '{0x00100000u, GCC_BYTES, 0}', '{0x00101000u, GCC_BYTES, 0}', suites=('table',), reason='windows[w].base == XW[w].base: GCC'),
    m('qup-window-base-moved', H, '{0x00bc0000u, QUP_BYTES, 0}', '{0x00bc1000u, QUP_BYTES, 0}', suites=('table',), reason='windows[w].base == XW[w].base: QUP'),
    m('qup-window-is-the-engine', H, '{0x00bc0000u, QUP_BYTES, 0}', '{0x00b88000u, QUP_BYTES, 0}', suites=('table',), reason='windows[w].base == XW[w].base: QUP'),
    m('gcc-window-size-halved', H, '#define GCC_BYTES 0x200000u', '#define GCC_BYTES 0x100000u', suites=('table',), reason='windows[w].size == XW[w].size: GCC'),
    m('qup-window-size-doubled', H, '#define QUP_BYTES 0x2000u', '#define QUP_BYTES 0x4000u', suites=('table',), reason='windows[w].size == XW[w].size: QUP'),
    m('windows-in-the-other-order', H, '{{0x00100000u, GCC_BYTES, 0}, {0x00bc0000u, QUP_BYTES, 0}}', '{{0x00bc0000u, QUP_BYTES, 0}, {0x00100000u, GCC_BYTES, 0}}', suites=('table',),
      reason='windows[w].base == XW[w].base: GCC'),
    m('window-names-swapped', H, '{"GCC", "QUP"}', '{"QUP", "GCC"}', suites=('table',), reason='!strcmp(window_name[0], "GCC")'),
    m('block-head-gate-renamed', H, '{"GATE", "RCG", "PLL", "LVL", "QUP"}', '{"GAT", "RCG", "PLL", "LVL", "QUP"}', suites=('table',), reason='!strcmp(block_head[b], XB_HEAD[b]): GATE'),
    m('block-head-rcg-renamed', H, '{"GATE", "RCG", "PLL", "LVL", "QUP"}', '{"GATE", "RC", "PLL", "LVL", "QUP"}', suites=('table',), reason='!strcmp(block_head[b], XB_HEAD[b]): RCG'),
    m('block-head-pll-renamed', H, '{"GATE", "RCG", "PLL", "LVL", "QUP"}', '{"GATE", "RCG", "PL", "LVL", "QUP"}', suites=('table',), reason='!strcmp(block_head[b], XB_HEAD[b]): PLL'),
    m('block-head-lvl-renamed', H, '{"GATE", "RCG", "PLL", "LVL", "QUP"}', '{"GATE", "RCG", "PLL", "LV", "QUP"}', suites=('table',), reason='!strcmp(block_head[b], XB_HEAD[b]): LVL'),
    m('block-head-qup-renamed', H, '{"GATE", "RCG", "PLL", "LVL", "QUP"}', '{"GATE", "RCG", "PLL", "LVL", "QU"}', suites=('table',), reason='!strcmp(block_head[b], XB_HEAD[b]): QUP'),
    m('prefix-loses-the-version-digit', C, '#define PREFIX "PAYLOAD INPSNAP2 "', '#define PREFIX "PAYLOAD INPSNAP "', suites=('table',), reason='!strcmp(PREFIX, "PAYLOAD INPSNAP2 ")'),
    m('header-says-stage-i1', C, '"READ ONLY EL=2 STAGE=I0 CAP="', '"READ ONLY EL=2 STAGE=I1 CAP="', suites=('unit',), reason='STAGE=I1'),
    m('header-says-el-1', C, '"READ ONLY EL=2 STAGE=I0 CAP="', '"READ ONLY EL=1 STAGE=I0 CAP="', suites=('unit',), reason='EL=1 STAGE=I0'),
    m('header-caps-swapped', C, '    dec(&line, LOAD_CAP);\n    tx(&line, "/");\n    dec(&line, LINE_CAP);', '    dec(&line, LINE_CAP);\n    tx(&line, "/");\n    dec(&line, LOAD_CAP);', suites=('unit',),
      reason='CAP=24/44'),
    m('header-caps-separator', C, '    tx(&line, "/");\n', '    tx(&line, ":");\n', suites=('unit',), reason='CAP=44:24'),
    m('header-line-lost', C, '    emit(&c, &line, 0);\n    say(&c, LEGEND, 0);\n', '    say(&c, LEGEND, 0);\n', suites=('unit',), reason='page line 0 is "PAYLOAD INPSNAP2 KEY=VALUE'),
    m('legend-line-lost', C, '    say(&c, LEGEND, 0);\n', '', suites=('unit',), reason='page line 1 is "PAYLOAD INPSNAP2 NEXT GATE"'),
    m('legend-says-clk', C, 'KEY=VALUE .ON .OFF .HW .ODD=CLOCK', 'KEY=VALUE .ON .OFF .HW .ODD=CLK', suites=('unit',), reason='.ODD=CLK'),
    m('legend-forgets-the-check', C, ' SKIP=NOT READ K=LINE CRC16"', ' SKIP=NOT READ"', suites=('unit',), reason='SKIP=NOT READ", not'),
    m('next-has-a-colon', C, 'tx(&line, "NEXT ");', 'tx(&line, "NEXT: ");', suites=('unit',), reason='NEXT: GATE'),
    m('next-names-the-block-before', C, '    tx(&line, block_head[block]);\n    return emit(c, &line, 0);', '    tx(&line, block_head[block ? block - 1u : 0u]);\n    return emit(c, &line, 0);', suites=('unit',),
      reason='NEXT RCG", not'),
    m('end-says-load', C, 'tx(&line, "END LOADS=");', 'tx(&line, "END LOAD=");', suites=('unit',), reason='END LOAD=44'),
    m('end-says-fault', C, 'tx(&line, " FAULTS=");', 'tx(&line, " FAULT=");', suites=('unit',), reason='FAULT=0'),
    m('end-says-skip', C, 'tx(&line, " SKIPS=");', 'tx(&line, " SKIP=");', suites=('unit',), reason='SKIP=0'),
    m('end-says-blocks', C, 'tx(&line, " BLK=");', 'tx(&line, " BLOCKS=");', suites=('unit',), reason='BLOCKS=0'),
    m('end-says-cut', C, 'tx(&line, " CUTS=");', 'tx(&line, " CUT=");', suites=('unit',), reason='CUT=0'),
    m('end-says-line', C, 'tx(&line, " LINES=");', 'tx(&line, " LINE=");', suites=('unit',), reason='LINE=21'),
    m('end-says-stopped', C, 'tx(&line, " STOP=");', 'tx(&line, " STOPPED=");', suites=('unit',), reason='STOPPED=NONE'),
    m('end-says-no-for-none', C, 'else tx(&line, "NONE");', 'else tx(&line, "NO");', suites=('unit',), reason='STOP=NO",'),
    m('end-lines-without-itself', C, '    dec(&line, c.lines + 1u);\n', '    dec(&line, c.lines);\n', suites=('unit',), reason='LINES=20'),
    m('end-loads-is-the-lines', C, '    dec(&line, c.loads);\n', '    dec(&line, c.lines);\n', suites=('unit',), reason='END LOADS=20'),
    m('end-blocks-in-decimal', C, '    num(&c, &line, c.blocks);\n', '    dec(&line, c.blocks);\n', suites=('stop',), reason='BLK=30'),
    m('end-stop-names-the-next-row', C, '    if (c.stop) tx(&line, regs[c.stop - 1u].key);', '    if (c.stop) tx(&line, regs[c.stop].key);', reason='!strcmp(m_end_stop(), XR_[i].key) && m_end_field("SKIPS") == skips: MA0'),
    m('end-stop-blocks-not-marked', C, '    if (c.stop) {\n        for (unsigned block = regs[c.stop - 1u].block; block < BLOCKS; block++) c.blocks |= 1u << block;\n    }\n', '', suites=('stop',), reason='BLK='),
    m('end-stop-leaves-its-own-block', C, 'for (unsigned block = regs[c.stop - 1u].block; block < BLOCKS; block++)', 'for (unsigned block = regs[c.stop - 1u].block + 1u; block < BLOCKS; block++)', suites=('stop',),
      reason='BLK='),
    m('k-label-changed', C, '    tx(&line, " K=");\n', '    tx(&line, " CK=");\n', suites=('unit',), reason=' CK=3886'),
    m('k-label-dropped', C, '    tx(&line, " K=");\n    hex4(&line, crc);', '    hex4(&line, crc);', suites=('unit',), reason='3886", not'),
    m('k-check-shifted', C, '    hex4(&line, crc);\n    emit(c, &line, 0);', '    hex4(&line, crc >> 1);\n    emit(c, &line, 0);', suites=('unit',), reason='K=1C43'),
    m('key-and-value-run-together', C, '    tx(line, " ");\n    tx(line, r->key);', '    tx(line, r->key);', suites=('unit',), reason='GATEMA0=0.ONSA0=0.ON'),
    m('equals-is-a-colon', C, '    tx(line, "=");\n    switch (w->st) {', '    tx(line, ":");\n    switch (w->st) {', suites=('unit',), reason='MA0:0.ON'),
    m('on-says-ok', C, 'tx(line, ".ON");', 'tx(line, ".OK");', suites=('unit',), reason='MA0=0.OK'),
    m('off-says-of', C, 'tx(line, ".OFF");', 'tx(line, ".OF");', suites=('unit',), reason='SE0=0X80004000.OF VT0'),
    m('hw-says-hc', C, 'tx(line, ".HW");', 'tx(line, ".HC");', suites=('decode',), reason='.HC'),
    m('odd-says-od', C, 'tx(line, ".ODD");', 'tx(line, ".OD");', suites=('decode',), reason='MA0 is 0XFFFFFFFF.OD, not 0XFFFFFFFF.ODD'),
    m('fault-has-an-equals', C, 'tx(line, "FAULT:");', 'tx(line, "FAULT=");', suites=('faults',), reason='FAULT='),
    m('fault-code-not-printed', C, '        tx(line, "FAULT:");\n        dec(line, w->v);\n', '        tx(line, "FAULT:");\n', suites=('faults',), reason='FAULT:'),
    m('skip-says-skipped', C, 'tx(line, "SKIP");', 'tx(line, "SKIPPED");', suites=('faults',), reason='SKIPPED'),
    m('budget-says-budge', C, 'tx(line, "BUDGET");', 'tx(line, "BUDGE");', suites=('units',), reason=' MA0=BUDGET'),
    m('na-says-n-a', C, 'tx(line, "NA");', 'tx(line, "N/A");', suites=('units',), reason=' MA0=NA'),
    m('no-verdict-on-any-clock', C, '        if (r->flags & F_CBCR) {\n            switch', '        if (0) {\n            switch', suites=('unit',), reason='GATE MA0=0 SA0=0 CR0=0X4000 K=3886"'),
    m('verdict-on-every-word', C, '        if (r->flags & F_CBCR) {\n            switch', '        if (1) {\n            switch', suites=('unit',), reason='GV=1.ON'),
    m('put-row-ignores-hwcg', C, 'switch (clock_state(w->v, r->flags & F_HWCG)) {', 'switch (clock_state(w->v, 0)) {', suites=('decode',), reason='0X80000002.OFF'),
    m('numbers-all-decimal', C, '        num(c, line, w->v);\n        if (r->flags & F_CBCR) {', '        dec(line, w->v);\n        if (r->flags & F_CBCR) {', suites=('unit',), reason='CR0=16384.ON'),
    m('gate-off-says-gate-off-text', C, 'say(c, "QUP GATED OFF", 0);', 'say(c, "QUP GATE OFF", 0);', suites=('gate',), reason='QUP GATE OFF'),
    m('gate-err-says-gate-err-text', C, 'say(c, "QUP GATED ERR", 0);', 'say(c, "QUP GATE ERR", 0);', suites=('gate',), reason='QUP GATE ERR'),
    m('gate-texts-swapped', C, 'if (gate == GATE_OFF) say(c, "QUP GATED OFF", 0);\n        else say(c, "QUP GATED ERR", 0);', 'if (gate == GATE_OFF) say(c, "QUP GATED ERR", 0);\n        else say(c, "QUP GATED OFF", 0);',
      suites=('gate',), reason='QUP GATED ERR'),
    m('not-at-el2-text', C, 'say(&c, "SKIPPED_NOT_AT_EL2", 1);', 'say(&c, "SKIPPED NOT AT EL2", 1);', suites=('el',), reason='SKIPPED NOT AT EL2'),
    m('no-load32-text', C, 'say(&c, "REFUSED_NO_LOAD32", 1);', 'say(&c, "REFUSED", 1);', suites=('el',), reason='without load32 one line says so'),
    # -- The number and text helpers.
    m('dec-prints-nothing-for-zero', C, "    do {\n        digits[n++] = (char)('0' + value % 10);\n        value /= 10;\n    } while (value);\n",
      "    while (value) {\n        digits[n++] = (char)('0' + value % 10);\n        value /= 10;\n    }\n", suites=('units',), reason='!strcmp(line.buf, "0")'),
    m('dec-radix-nine', C, "digits[n++] = (char)('0' + value % 10);", "digits[n++] = (char)('0' + value % 9);", suites=('units',), reason='!strcmp(line.buf, "10")'),
    m('dec-overruns-a-full-line', C, '    while (n && line->len < Q1N1_PAYLOAD_LINE_MAX) line->buf[line->len++] = digits[--n];', '    while (n) line->buf[line->len++] = digits[--n];', reason="runtime error: index 101 out of bounds for type 'char[101]'"),
    m('num-hex-from-nine', C, '    if (value < 10) dec(line, value);', '    if (value < 9) dec(line, value);', suites=('units',), reason='!strcmp(line.buf, "9")'),
    m('num-decimal-to-ten', C, '    if (value < 10) dec(line, value);', '    if (value < 11) dec(line, value);', suites=('units',), reason='!strcmp(line.buf, "0XA")'),
    m('num-always-hex', C, '    if (value < 10) dec(line, value);\n    else hx(c, line, value);', '    hx(c, line, value);', suites=('units',), reason='!strcmp(line.buf, "9")'),
    m('hx-gives-the-op-one-byte-less', C, 'line->len += c->hex(line->buf + line->len, Q1N1_PAYLOAD_LINE_MAX + 1 - line->len, value);',
      'line->len += c->hex(line->buf + line->len, Q1N1_PAYLOAD_LINE_MAX - line->len, value);', suites=('units',), reason='hx at the end of a line: the line is 99 characters (its text 99), not 100'),
    m('hx-gives-the-op-one-byte-more', C, 'line->len += c->hex(line->buf + line->len, Q1N1_PAYLOAD_LINE_MAX + 1 - line->len, value);',
      'line->len += c->hex(line->buf + line->len, Q1N1_PAYLOAD_LINE_MAX + 2 - line->len, value);', suites=('units',), reason='hx at the end of a line: the line is 101 characters (its text 101), not 100'),
    m('hx-forgets-the-length', C, 'line->len += c->hex(line->buf + line->len, Q1N1_PAYLOAD_LINE_MAX + 1 - line->len, value);', 'c->hex(line->buf + line->len, Q1N1_PAYLOAD_LINE_MAX + 1 - line->len, value);',
      suites=('decode',), reason='CR0=.ON'),
    m('hex4-in-lower-case', C, '"0123456789ABCDEF"[value >> shift & 15]', '"0123456789abcdef"[value >> shift & 15]', suites=('unit',), reason='not in the page font'),
    m('hex4-three-digits', C, '    for (unsigned shift = 16; shift;) {', '    for (unsigned shift = 12; shift;) {', suites=('unit',), reason='K=886'),
    m('hex4-seven-bits-a-digit', C, '"0123456789ABCDEF"[value >> shift & 15]', '"0123456789ABCDEF"[value >> shift & 7]', suites=('unit',), reason='K=3886'),
    m('hex4-overruns-a-full-line', C, '        if (line->len < Q1N1_PAYLOAD_LINE_MAX) line->buf[line->len++] = "0123456789ABCDEF"[value >> shift & 15];', '        line->buf[line->len++] = "0123456789ABCDEF"[value >> shift & 15];',
      reason="runtime error: index 101 out of bounds for type 'char[101]'"),
    # -- The line cap: room, emit and the closing line.
    m('room-takes-the-closing-slot', C, '    return c->lines + CLOSING_LINES < LINE_CAP;', '    return c->lines < LINE_CAP;', suites=('units',), reason='the line before the closing slot has no room'),
    m('room-spares-one-line-too-many', C, '    return c->lines + CLOSING_LINES < LINE_CAP;', '    return c->lines + CLOSING_LINES + 1u < LINE_CAP;', suites=('units',), reason='a line that leaves the closing slot free has room'),
    m('room-is-always-there', C, '    return c->lines + CLOSING_LINES < LINE_CAP;', '    return 1;', stage='caps', suites=('caps',), reason="more lines than", defs=('-DINPSNAP2_LINE_CAP=12u',)),
    m('closing-line-ignores-the-cap', C, 'if (closing ? c->lines >= LINE_CAP : !room(c)) {', 'if (!room(c)) {', suites=('units',), reason='the end line takes the closing slot'),
    m('closing-line-one-past-the-cap', C, 'if (closing ? c->lines >= LINE_CAP : !room(c)) {', 'if (closing ? c->lines > LINE_CAP : !room(c)) {', suites=('units',), reason='nothing goes past the line cap, not even the end line'),
    m('a-cut-line-is-not-counted', C, '        c->cuts++;\n        return 0;\n    }\n    c->lines++;', '        return 0;\n    }\n    c->lines++;', suites=('units',), reason='a line without room is counted as cut'),
    m('a-cut-line-is-printed-anyway', C, '        c->cuts++;\n        return 0;\n    }\n    c->lines++;', '        c->cuts++;\n    }\n    c->lines++;', suites=('units',), reason='a line without room is not printed'),
    m('a-printed-line-is-not-counted', C, '    c->lines++;\n    c->puts(line->buf);', '    c->puts(line->buf);', suites=('unit',), reason='LINES=1'),
    m('end-line-takes-the-room-of-a-line', C, '    emit(&c, &line, 1);\n    return 0;', '    emit(&c, &line, 0);\n    return 0;', stage='caps', suites=('caps',), reason='m_end_field("LINES") == m_nlines', defs=('-DINPSNAP2_LINE_CAP=6u',)),
]

# ---- The check of a line --------------------------------------------------------------------------------------------------------------------------------------------------------------
CRC = [
    m('crc-starts-from-zero', H, '#define CRC_INIT 0xffffu', '#define CRC_INIT 0x0000u', suites=('table',), reason='CRC_INIT == 0xffffu'),
    m('crc-polynomial-8005', H, '#define CRC_POLY 0x1021u', '#define CRC_POLY 0x8005u', suites=('crc',), reason='m_crc_of_bytes("123456789") == 0x29b1u'),
    m('crc-polynomial-1020', H, '#define CRC_POLY 0x1021u', '#define CRC_POLY 0x1020u', suites=('crc',), reason='m_crc_of_bytes("123456789") == 0x29b1u'),
    m('crc-tests-bit-14', C, '(crc & 0x8000u ? crc << 1 ^ CRC_POLY : crc << 1)', '(crc & 0x4000u ? crc << 1 ^ CRC_POLY : crc << 1)', suites=('crc',), reason='m_crc_of_bytes("123456789") == 0x29b1u'),
    m('crc-byte-enters-at-bit-7', C, '    crc ^= byte << 8;', '    crc ^= byte << 7;', suites=('crc',), reason='m_crc_of_bytes("123456789") == 0x29b1u'),
    m('crc-eight-steps-become-seven', C, 'for (unsigned bit = 0; bit < 8; bit++) crc =', 'for (unsigned bit = 0; bit < 7; bit++) crc =', suites=('crc',), reason='m_crc_of_bytes("123456789") == 0x29b1u'),
    m('crc-skips-the-state-byte', C, '    crc = crc_byte(crc, w->st);\n', '', suites=('crc',), reason='crc_word(CRC_INIT, &w) == r_crc(0xffff, bytes, 5)'),
    m('crc-state-byte-is-zero', C, '    crc = crc_byte(crc, w->st);\n', '    crc = crc_byte(crc, 0);\n', suites=('crc',), reason='crc_word(CRC_INIT, &w) == r_crc(0xffff, bytes, 5)'),
    m('crc-value-big-endian', C, 'crc_byte(crc, w->v >> 8 * byte & 0xffu)', 'crc_byte(crc, w->v >> 8 * (3 - byte) & 0xffu)', suites=('crc',), reason='crc_word(CRC_INIT, &w) == r_crc(0xffff, bytes, 5)'),
    m('crc-three-value-bytes', C, 'for (unsigned byte = 0; byte < 4; byte++) crc = crc_byte', 'for (unsigned byte = 0; byte < 3; byte++) crc = crc_byte', suites=('crc',),
      reason='crc_word(CRC_INIT, &w) == r_crc(0xffff, bytes, 5)'),
    m('crc-leaves-the-first-word-out', C, '        crc = crc_word(crc, &c->v[id]);\n', '        if (id != d->first) crc = crc_word(crc, &c->v[id]);\n', suites=('unit',), reason='K=3886'),
    m('crc-leaves-the-last-word-out', C, '        crc = crc_word(crc, &c->v[id]);\n', '        if (id + 1u != d->end) crc = crc_word(crc, &c->v[id]);\n', suites=('unit',), reason='K=3886'),
    m('crc-takes-the-first-word-of-the-line-for-all', C, '        crc = crc_word(crc, &c->v[id]);\n', '        crc = crc_word(crc, &c->v[d->first]);\n', suites=('unit',), reason='K=3886'),
    m('crc-is-not-reset-between-words', C, '    uint32_t crc = CRC_INIT;\n    if (!room(c)) {', '    uint32_t crc = CRC_INIT ^ c->lines;\n    if (!room(c)) {', suites=('unit',), reason='K=3886'),
]


def all_mutants(root=ROOT):
    """Every seeded bug, in the order of the document: the generated ones of the table, then the written-out groups."""
    import sp11_payload_inpsnap2_mutants_more as more
    return generated(root) + WINDOWS_AND_TEXT + CRC + more.LOADS + more.CLOCK + more.GATE + more.BLOCKS + more.ENTRY + more.BUILD + more.AUDIT


# ---- Running a mutant -------------------------------------------------------------------------------------------------------------------------------------------------------------------
def stale(mutant, texts):
    """The edits of `mutant` whose needle is not exactly once in the text of its file, as the earlier edits of the same mutant leave it ({file: text} in)."""
    texts, found = dict(texts), []
    for file, old, new in mutant.edits:
        if texts[file].count(old) != 1:
            found.append((mutant.name, file, old[:60], texts[file].count(old)))
        texts[file] = texts[file].replace(old, new, 1)
    return found


def apply(mutant, directory, root=ROOT):
    """Writes the two sources of `root` into `directory` with the edits of `mutant` (none for None); returns the path of inpsnap2.c."""
    directory = Path(directory)
    shutil.rmtree(directory, ignore_errors=True)
    directory.mkdir(parents=True)
    texts = {file: (Path(root) / file).read_text(encoding='utf-8') for file in (C, H)}
    if mutant is not None:
        bad = stale(mutant, texts)
        if bad:
            raise ValueError(f'stale mutant: {bad}')
        for file, old, new in mutant.edits:
            texts[file] = texts[file].replace(old, new, 1)
    for file, text in texts.items():
        (directory / Path(file).name).write_text(text, encoding='utf-8')
    return directory / 'inpsnap2.c'


def build_harness(source, out, defs=(), root=ROOT):
    """(CompletedProcess, binary): the host test built over `source` under ASan and UBSan; -Werror is off, a seeded bug may be sloppy."""
    out = Path(out)
    out.parent.mkdir(parents=True, exist_ok=True)
    flags = ['-std=gnu11', '-O1', '-Wall', '-Wextra', '-Wno-error', '-DQ1N1_PAYLOAD_HOST_TEST=1', '-Iplatform/uefi', '-Ipayloads', f'-DINPSNAP2_SRC="{source}"', *defs,
             '-fsanitize=address,undefined', '-fno-sanitize-recover=undefined']
    return lib.run(['clang', *flags, '-o', str(out), str(Path(root) / 'tools' / 'test-q1n1-sp11-payload-inpsnap2.c')], cwd=root), out


def suite_results(text):
    return dict(re.findall(r'^suite (\w+)\s+(ok|FAILED)\b', text, re.M))


def check(mutant, work, root=ROOT):
    """(refused, why) of one mutant: refused is True only when the stage the mutant names refuses it for the reason it names; `why` says what happened otherwise."""
    work = Path(work)
    source = apply(mutant, work / 'src', root)
    if mutant.stage in ('harness', 'caps'):
        built, binary = build_harness(source, work / 'harness', mutant.defs, root)
        if built.returncode:
            return False, 'the seeded bug does not compile, so nothing was shown: ' + built.stderr[-300:]
        try:
            done = lib.run([str(binary)], cwd=root, timeout=300)
        except subprocess.TimeoutExpired:
            return False, 'timed out: a seeded bug must be refused by a failed check, not a hang'
        output = done.stdout + done.stderr
        if done.returncode == 0:
            return False, 'the host test passed on a seeded bug'
        failed = sorted(name for name, status in suite_results(done.stdout).items() if status == 'FAILED')
        if not set(mutant.suites) <= set(failed):
            return False, f'wanted {list(mutant.suites)} among the failing suites, got {failed}'
        if mutant.reason not in output:
            fails = [line[:260] for line in output.splitlines() if line.startswith('FAIL') or 'AddressSanitizer' in line or 'runtime error' in line][:3]
            return False, f'refused (suites {failed}), but not for the reason it names: ' + ' | '.join(fails)
        return True, f'suites {failed}'
    if mutant.stage == 'build':
        done, _, _ = lib.build_payload(source, work / 'bin', name='inpsnap2', extra_cflags=('-Wno-error',), root=root)
        if not done.returncode:
            return False, 'the seeded bug compiled and linked'
        text = done.stdout + done.stderr
        return (mutant.reason in text), (text[-300:] if mutant.reason not in text else 'refused by the compiler')
    if mutant.stage == 'audit':
        problems, _ = audit.provenance(audit.build_ir(source, work / 'ir', root, extra=('-Wno-error',)))
        return any(mutant.reason in problem for problem in problems), ' | '.join(problems[:4])
    done, elf, flat = lib.build_payload(source, work / 'bin', name='inpsnap2', extra_cflags=('-Wno-error',), root=root)
    if mutant.stage == 'binary':
        if done.returncode:
            return mutant.reason in done.stdout + done.stderr, (done.stdout + done.stderr)[-300:]
        problems = lib.binary_violations(elf, flat, lib.POLICIES['inpsnap2'])
        return any(mutant.reason in problem for problem in problems), ' | '.join(problems[:4])
    if done.returncode:
        return False, 'does not build: ' + done.stderr[-300:]
    sizes = audit.frame_sizes(source, work / 'stack', root)
    depth, _ = audit.stack_depth(sizes, lib.run(['llvm-objdump', '-d', '--no-show-raw-insn', str(elf)]).stdout)
    if depth <= audit.STACK_USABLE:
        return False, f'the deepest chain of frames is {depth} bytes, within the {audit.STACK_USABLE} the runner leaves'
    message = f'the deepest chain of frames is {depth} bytes, more than the {audit.STACK_USABLE} the runner leaves'
    return mutant.reason in message, message
