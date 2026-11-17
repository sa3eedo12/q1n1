# SPDX-License-Identifier: MIT
"""The seeded bugs of the payload `xhci` (tools/test-q1n1-sp11-payload-xhci.py): each is an edit of one or more of its files, applied to
a copy of the tree, that the host harness must reject. Each edit's needle must occur exactly once, so that a change of the source that
moves a target is reported as a stale mutant and not as a survivor. A mutant names the builds that must catch it: a controller and,
for the bugs of the line budget, a shrunken budget (`cap`); and, for the bugs of a gate, the one suite that must catch it by itself
(the gates are called directly there, with no faulty caller to help). Hardware: NOT RUN."""
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import sp11_payload_xhci_lib as x  # noqa: E402

CTL, IO, MAP, MAIN, TEXT, WATCH, REGS, SMMU = ('payloads/xhci-ctl.c', 'payloads/xhci-io.c', 'payloads/xhci-map.c', 'payloads/xhci.c', 'payloads/xhci-text.c',
                                               'payloads/xhci-watch.c', 'payloads/xhci-regs.h', 'payloads/xhci-smmu.c')
NORMAL = [(1, None, None)]
BOTH = [(1, None, None), (0, None, None)]
FW = [(0, None, None)]
TIGHT = [(1, 16, None), (1, 24, None), (0, 20, None)]
LOADS = [(1, None, 700), (0, None, 1200)]

ERSTSZ = '    if (store(c, G_PROGRAM, SR_ERSTSZ, 1)) return W_STORE;\n'
ERDP = '    if (store(c, G_PROGRAM, SR_ERDP_LO, (uint32_t)event) || store(c, G_PROGRAM, SR_ERDP_HI, (uint32_t)(event >> 32))) return W_STORE;\n'
ERSTBA = '    if (store(c, G_PROGRAM, SR_ERSTBA_LO, (uint32_t)erst) || store(c, G_PROGRAM, SR_ERSTBA_HI, (uint32_t)(erst >> 32))) return W_STORE;\n'
DCBAAP = '    if (store(c, G_PROGRAM, SR_DCBAAP_LO, (uint32_t)dcbaa) || store(c, G_PROGRAM, SR_DCBAAP_HI, (uint32_t)(dcbaa >> 32))) return W_STORE;\n'
CRCR = '    if (store(c, G_PROGRAM, SR_CRCR_LO, (uint32_t)cmd | CRCR_RCS) || store(c, G_PROGRAM, SR_CRCR_HI, (uint32_t)(cmd >> 32))) return W_STORE;\n'
CONFIG = '    if (store(c, G_PROGRAM, SR_CONFIG, x->slots)) return W_STORE;\n'
DOORBELL = '    if (store(c, G_NOOP, SR_DB0, 0)) return W_STORE;\n'
IMAN = '    if (store(c, G_NOOP, SR_IMAN, IMAN_IP)) return W_STORE;\n'
HANDBACK = '(uint32_t)dequeue | ERDP_EHB'
HCRST_POLL = '    why = poll_xhc(c, x->op + OP_USBCMD, "USBCMD", CMD_HCRST, 0, T_RESET_US, &cmd);\n    if (why) return why == W_EVENT ? W_HCRST : why;\n'
CNR_POLL = '    why = poll_xhc(c, x->op + OP_USBSTS, "USBSTS", STS_CNR, 0, T_CNR_US, &sts);\n    r->sts = sts;\n    if (why) return why == W_EVENT ? W_CNR : why;\n'
HALT = '    if (c->armed & ~(unsigned)G_ARENA) {\n        stopped = xhc_halt(c, &sts);'
ZERO = '    if (r->halted == 1 && (c->armed & G_ARENA)) arena_zero(c);'
VERDICT_OK = '    if (r.verdict == V_OK) say(&c, "VERDICT NOOP_OK ARENA=%d", U(c.arena.id));'
RUN_ORDER = '    if (!why) why = announce(c, G_RUN, "RUN", 0, 0);\n    if (!why) why = xhc_run(c, r);\n'
RAM_BOUNDS = ' || address - c->arena.base > size - 4'
CLOSING = '    if (c->lines + (c->closing ? 0u : CLOSING_LINES) >= LINE_CAP) {'
ZERO_LOOP = '    for (uint64_t at = c->arena.base; at < c->arena.base + (uint64_t)c->arena.pages * PAGE; at += 4) ram_put(c, at, 0);'
OVERRUN = ZERO_LOOP.replace('* PAGE; at += 4)', '* PAGE + PAGE; at += 4)')
BUILD_ZERO = '    for (uint64_t at = ar->base; at < ar->base + (uint64_t)ar->pages * PAGE; at += 4) ram_put(c, at, 0);\n    if (scratch) {'
BUILD_CLEAN = '    clean_range(c, ar->base, (uint64_t)ar->pages * PAGE);\n}\n\n/* After the halt'
ZERO_CLEAN = '    clean_range(c, c->arena.base, (uint64_t)c->arena.pages * PAGE);\n'
CLEAN_GATE = '        if (!arena_range(c, at, CACHE_STEP)) break;\n'
EVENT_GATE = '            if (!arena_range(c, at, CACHE_STEP)) return W_STORE;\n'
EVENT_CIVAC = '            dc_civac(at);\n'
EXIT = 'c.cuts ? " LINES_CUT" : "");\n    return 0;\n}'
SMMU_EXTRA = '    c.closing = 1;\n    if (r.verdict == V_OK)'
WATCH_RESERVE = '    watch_run(&c, eligible * ATTEMPT_LINES_MIN + 1u + CLOSING_LINES);\n'
SMMU1_PRINT = ('            if (room(&c, faults_lines(&c, &now) - 1u + later * ATTEMPT_LINES_MIN + CLOSING_LINES)) say_faults(&c, "SMMU1", attempts, &now);\n'
               '            else c.cuts++;\n')
REDIRECT = '            return !r->events && (sts & STS_EINT) && !(before & STS_EINT) ? W_REDIRECT : W_EVENT;\n'
COUNTER_BACK = '        if (now < start) return 0;\n'
BERR_COMPARE = 'a->berr == b->berr && a->berr_valid == b->berr_valid;'
RESET_VERDICT = 'return sts & STS_HCE ? W_HCE : sts & STS_HSE ? W_HSE : sts & STS_HCH ? W_NONE : W_HCH;'
DIGITS = '    char digits[20];\n'


def m(name, edits, builds=NORMAL, suite=None):
    return (name, [tuple(edit) for edit in edits], builds, suite)


def gate(name, file, needle, replacement=''):
    """One rule of a gate removed, with every caller as it is: only the gates suite, which calls the gates directly, may be what catches it."""
    return m(name, [(file, needle, replacement)], NORMAL, 'gates')


MUTANTS = [
    # -- the order of the programming and the width of the registers
    m('erstba-before-erstsz', [(CTL, ERSTSZ, ''), (CTL, ERSTBA, ERSTBA + ERSTSZ)]),
    m('erstba-before-erdp', [(CTL, ERDP, ''), (CTL, ERSTBA, ERSTBA + ERDP)]),
    m('erstba-high-word-first', [(CTL, 'store(c, G_PROGRAM, SR_ERSTBA_LO, (uint32_t)erst) || store(c, G_PROGRAM, SR_ERSTBA_HI, (uint32_t)(erst >> 32))',
                                  'store(c, G_PROGRAM, SR_ERSTBA_HI, (uint32_t)(erst >> 32)) || store(c, G_PROGRAM, SR_ERSTBA_LO, (uint32_t)erst)')]),
    m('dcbaap-high-word-first', [(CTL, 'store(c, G_PROGRAM, SR_DCBAAP_LO, (uint32_t)dcbaa) || store(c, G_PROGRAM, SR_DCBAAP_HI, (uint32_t)(dcbaa >> 32))',
                                  'store(c, G_PROGRAM, SR_DCBAAP_HI, (uint32_t)(dcbaa >> 32)) || store(c, G_PROGRAM, SR_DCBAAP_LO, (uint32_t)dcbaa)')]),
    m('crcr-without-the-cycle-state-bit', [(CTL, '(uint32_t)cmd | CRCR_RCS', '(uint32_t)cmd')]),
    m('config-above-max-slots', [(CTL, CONFIG, '    if (store(c, G_PROGRAM, SR_CONFIG, x->slots + 1u)) return W_STORE;\n')]),
    m('erstba-in-the-wrong-group', [(CTL, 'store(c, G_PROGRAM, SR_ERSTBA_LO, (uint32_t)erst)', 'store(c, G_NOOP, SR_ERSTBA_LO, (uint32_t)erst)')]),
    m('crcr-high-word-at-the-wrong-offset', [(REGS, '{0, OP_CRCR + 4}', '{0, OP_CRCR + 8}')]),
    # -- the No Op, its doorbell and the event
    m('no-doorbell', [(CTL, DOORBELL, '')]),
    m('doorbell-with-a-target', [(CTL, 'SR_DB0, 0)', 'SR_DB0, 1)')]),
    m('no-iman-clear', [(CTL, IMAN, '')]),
    m('erdp-handed-back-without-ehb', [(CTL, HANDBACK, '(uint32_t)dequeue')]),
    m('completion-code-not-checked', [(CTL, 'return pointer != trb ? W_POINTER : r->cc != CC_SUCCESS ? W_CODE : W_NONE;',
                                       'return pointer != trb ? W_POINTER : W_NONE;')]),
    m('completion-pointer-not-checked', [(CTL, 'return pointer != trb ? W_POINTER : r->cc != CC_SUCCESS ? W_CODE : W_NONE;',
                                          'return r->cc != CC_SUCCESS ? W_CODE : W_NONE;')]),
    m('event-cycle-bit-not-checked', [(CTL, '        if (!(control & 1u)) return -1;\n', '')]),
    m('hse-is-a-timeout', [(CTL, 'why == W_HSE || why == W_HCE ? V_HSE :', '')]),
    m('never-waits-for-hcrst-to-clear', [(CTL, HCRST_POLL, '    why = 0;\n    (void)cmd;\n')]),
    m('never-waits-for-cnr', [(CTL, CNR_POLL, '    why = 0;\n')]),
    # -- the cache
    m('the-noop-trb-is-not-cleaned', [(CTL, '    clean_range(c, trb, TRB_BYTES);\n', '')]),
    m('the-event-is-not-invalidated', [(CTL, EVENT_CIVAC, '')]),
    m('the-arena-is-not-cleaned', [(MAP, BUILD_CLEAN, '}\n\n/* After the halt')]),
    m('no-barrier-after-the-clean', [(IO, '    dsb_sy();\n}', '}')]),
    m('cache-step-larger-than-a-line', [(REGS, '#define CACHE_STEP 16u', '#define CACHE_STEP 128u')]),
    # -- announce, wait, then write
    m('no-wait-before-a-write', [(CTL, '    if (!delay_ticks(c, c->hz * WAIT_BEFORE_WRITE_S)) return W_CLOCK;\n', '')]),
    m('waits-four-seconds', [(REGS, '#define WAIT_BEFORE_WRITE_S 8u', '#define WAIT_BEFORE_WRITE_S 4u')]),
    m('no-announcement-of-the-later-groups', [(CTL, '    else printed = say(c, "NEXT %s AFTER 8 S", what);\n', '    else printed = 1;\n')]),
    m('runs-before-announcing-run', [(CTL, RUN_ORDER, '    if (!why) why = xhc_run(c, r);\n    if (!why) why = announce(c, G_RUN, "RUN", 0, 0);\n')]),
    m('runs-before-announcing-run-and-the-gate-is-open', [(CTL, RUN_ORDER, '    if (!why) why = xhc_run(c, r);\n    if (!why) why = announce(c, G_RUN, "RUN", 0, 0);\n'),
                                                          (IO, '    if (group ? !(c->armed & group) : !c->armed) return STORE_NOT_ARMED;\n', '')]),
    m('arms-without-a-printed-announcement', [(CTL, '    if (!printed) return W_LINES;\n', '')], TIGHT),
    # -- the memory the xHC may reach
    m('ram-store-outside-the-arena', [(MAP, ZERO_LOOP, OVERRUN)]),
    m('ram-store-outside-the-arena-and-the-gate-is-open', [(MAP, ZERO_LOOP, OVERRUN), (IO, RAM_BOUNDS, '')]),
    m('arena-two-without-the-guard-page', [(MAP, '        base = a->stack_base + PAGE;\n', '        base = a->stack_base;\n')]),
    m('arena-two-ignores-the-stack-the-payload-keeps', [(MAP, '        if (bytes > a->stack_size - PAGE - STACK_KEPT) return AR_TOO_BIG;\n',
                                                         '        if (bytes > a->stack_size - PAGE) return AR_TOO_BIG;\n')]),
    m('arena-one-ignores-the-memory-map', [(MAP, '        if (!map_range_in(c, base, base + bytes, 1u << MT_BOOT_DATA | 1u << MT_CONVENTIONAL)) return AR_NOT_FREE;\n', '')], FW),
    m('arena-four-without-ac64', [(MAP, '        if (!c->x[TARGET].ac64) return AR_NO_AC64;\n', '')]),
    m('no-scratchpad-array', [(MAP, '        ram_put64(c, ar->base + OFF_DCBAA, ar->base + OFF_SPARR);\n', '')]),
    m('scratchpad-entries-name-one-page', [(MAP, 'ar->base + (uint64_t)(1u + i) * PAGE);', 'ar->base + PAGE);')]),
    m('the-arena-is-not-zeroed-first', [(MAP, BUILD_ZERO, '    if (scratch) {')]),
    m('the-arena-is-not-zeroed-at-the-end', [(CTL, ZERO, '    if (0) arena_zero(c);')]),
    m('the-arena-is-zeroed-under-a-controller-that-may-run', [(CTL, ZERO, '    if (c->armed & G_ARENA) arena_zero(c);')]),
    m('no-halt-at-the-end', [(CTL, HALT, '    if (0) {\n        stopped = xhc_halt(c, &sts);')]),
    # -- the pre-flight
    m('a-running-controller-is-not-refused', [(MAIN, '    if ((x->cmd & CMD_RS) || !(x->sts & STS_HCH)) {\n        *key = "CMD";', '    if (0) {\n        *key = "CMD";')]),
    m('the-dwc3-id-is-not-checked', [(MAIN, '        if (x->dwc3_id != XHCI_S1_DWC3_ID) {', '        if (0) {')]),
    m('caplength-is-not-checked', [(MAIN, '    if (x->caplen != XHCI_S1_CAPLENGTH) {', '    if (0) {')]),
    m('the-load-budget-is-not-kept', [(IO, '    } else if (c->loads >= LOAD_CAP) {\n        rc = RD_BUDGET;\n    } else {', '    } else {')], LOADS),
    m('no-bound-on-a-poll', [(CTL, '        if (elapsed >= (uint64_t)timeout_us * c->hz / 1000000u) return W_EVENT;\n', '')]),
    m('no-bound-on-the-event-wait', [(CTL, '        if (c->a->ops.counter() - start >= (uint64_t)T_EVENT_US * c->hz / 1000000u) {\n', '        if (0) {\n')]),
    # -- what it must never write
    m('a-store-to-the-smmu', [(MAIN, SMMU_EXTRA, '    mmio_store32(windows[WIN_SMMU].base + SMMU_GFSR, 0xffffffffu);\n' + SMMU_EXTRA)]),
    m('a-store-to-a-port-register', [(MAIN, SMMU_EXTRA, '    mmio_store32(windows[TARGET].base + c.x[TARGET].op + OP_PORTSC(1), 0x200u);\n' + SMMU_EXTRA)]),
    m('the-watch-writes-a-port-register', [(WATCH, '    emit(c, &line);\n    while ((now = c->a->ops.counter()) >= start && now - start < total) {',
                                            '    emit(c, &line);\n    mmio_store32(windows[TARGET].base + c->x[TARGET].op + OP_PORTSC(1), 0x80u);\n    while ((now = c->a->ops.counter()) >= start && now - start < total) {')]),
    # -- the page and the verdict
    m('the-verdict-is-ok-whatever-happened', [(MAIN, VERDICT_OK, '    if (1) say(&c, "VERDICT NOOP_OK ARENA=%d", U(c.arena.id));')]),
    m('returns-nonzero', [(MAIN, EXIT, 'c.cuts ? " LINES_CUT" : "");\n    return 1;\n}')]),
    m('an-unreadable-smmu-is-the-same', [(MAIN, '            smmu = "UNREAD";\n', '            smmu = "SAME";\n')]),
    m('a-changed-smmu-is-the-same', [(MAIN, '            if (!faults_same(&c.before, &now)) smmu = "CHANGED";\n', '            if (0) smmu = "CHANGED";\n')]),
    m('no-plug-watch', [(MAIN, WATCH_RESERVE, '')]),
    m('the-watch-is-three-seconds', [(REGS, '#define WATCH_S 30u', '#define WATCH_S 3u')]),
    m('the-watch-counts-no-change', [(WATCH, '                    changes++;\n', '')]),
    # -- the line budget
    m('the-verdict-can-be-crowded-out', [(TEXT, CLOSING, '    if (c->lines >= LINE_CAP) {')], TIGHT),
    m('the-page-has-no-line-cap', [(TEXT, CLOSING, '    if (0) {')], TIGHT),
    m('the-watch-takes-the-lines-of-the-attempts', [(MAIN, WATCH_RESERVE, '    watch_run(&c, 1u + CLOSING_LINES);\n')], FW),
    m('an-smmu-report-takes-the-lines-of-the-attempts', [(MAIN, SMMU1_PRINT, '            say_faults(&c, "SMMU1", attempts, &now);\n')], FW),
    # -- a bad completion ends the run, and what counts as one
    m('a-bad-completion-moves-on-to-the-next-arena', [(CTL, 'r->verdict == V_BAD || ', '')]),
    m('a-redirect-is-a-timeout', [(CTL, ' || why == W_REDIRECT ? V_BAD', ' ? V_BAD')]),
    m('a-redirect-is-not-detected', [(CTL, REDIRECT, '            return W_EVENT;\n')]),
    m('a-redirect-ignores-whether-eint-was-set-before-the-doorbell', [(CTL, ' && !(before & STS_EINT)', '')]),
    m('a-redirect-ignores-the-events-in-the-ring', [(CTL, '!r->events && ', '')]),
    m('the-smmu-baseline-is-not-refreshed', [(MAIN, 'c.before = now;', '(void)0;')]),
    # -- every cache operation is inside the arena
    m('the-arena-clean-overruns-by-a-page', [(MAP, ZERO_CLEAN, ZERO_CLEAN.replace('* PAGE);', '* PAGE + PAGE);'))]),
    m('the-arena-clean-overruns-by-a-page-and-the-gate-is-open', [(MAP, ZERO_CLEAN, ZERO_CLEAN.replace('* PAGE);', '* PAGE + PAGE);')), (IO, CLEAN_GATE, '')]),
    m('the-event-is-invalidated-a-megabyte-above-its-slot', [(CTL, EVENT_CIVAC, '            dc_civac(at + 0x100000);\n')]),
    m('the-event-slot-is-not-range-checked-and-the-civac-is-above', [(CTL, EVENT_GATE, ''), (CTL, EVENT_CIVAC, '            dc_civac(at + 0x100000);\n')]),
    # -- the offsets the controller gives, and the waits of a reset
    m('the-store-limit-is-not-checked-before-the-run', [(MAIN, '        if (reg_offset(x, reg) > store_limit() - 4u) {', '        if (0) {')]),
    m('the-store-limit-is-checked-nowhere', [(MAIN, '        if (reg_offset(x, reg) > store_limit() - 4u) {', '        if (0) {'),
                                             (IO, '    if (off & 3 || off > store_limit() - 4) return STORE_RANGE;\n', '    if (off & 3) return STORE_RANGE;\n')]),
    m('the-alignment-of-dboff-and-rtsoff-is-not-checked', [(MAIN, '    if ((x->dboff & 3u) || (x->rtsoff & 0x1fu)) {', '    if (0) {')]),
    m('a-reset-gets-a-tenth-of-a-second', [(REGS, '#define T_RESET_US 1000000u', '#define T_RESET_US 100000u')]),
    m('cnr-gets-a-tenth-of-a-second', [(REGS, '#define T_CNR_US 1000000u', '#define T_CNR_US 100000u')]),
    m('a-long-wait-is-polled-every-millisecond', [(CTL, 'delay_us(c, elapsed < fast ? POLL_US : POLL_SLOW_US)', 'delay_us(c, POLL_US)')]),
    # -- the plug watch is bounded like every other wait
    m('the-watch-does-not-notice-a-counter-that-stopped', [(WATCH, '            if (++same >= COUNTER_STUCK_READS) break;\n', '')]),
    # -- a counter that is set back, a fault that only the DWC3 shows, an error the reset itself ends with (the worlds of the `edges` and `faults` suites)
    m('a-counter-that-is-set-back-ends-a-wait-at-once', [(IO, COUNTER_BACK, '')], NORMAL, 'edges'),
    m('the-bus-error-address-and-valid-bit-are-not-compared', [(SMMU, BERR_COMPARE, '1;')], NORMAL, 'edges'),
    m('the-bus-error-address-is-not-compared', [(SMMU, BERR_COMPARE, 'a->berr_valid == b->berr_valid;')], NORMAL, 'edges'),
    m('the-bus-error-valid-bit-is-not-compared', [(SMMU, BERR_COMPARE, 'a->berr == b->berr;')], NORMAL, 'edges'),
    m('hse-at-the-reset-is-not-noticed', [(CTL, RESET_VERDICT, 'return sts & STS_HCE ? W_HCE : sts & STS_HCH ? W_NONE : W_HCH;')], NORMAL, 'faults'),
    m('hce-at-the-reset-is-not-noticed', [(CTL, RESET_VERDICT, 'return sts & STS_HSE ? W_HSE : sts & STS_HCH ? W_NONE : W_HCH;')], NORMAL, 'faults'),
    # -- an offset inside a buffer of the payload: its base is the payload's own, so the store audit of the IR passes it and only the sanitizers of the harness see it
    m('a-digit-buffer-that-is-too-small', [(TEXT, DIGITS, '    char digits[2];\n')]),
    # -- the gates, one rule at a time, with every caller as it is
    gate('gate-takes-a-register-that-is-not-one-of-the-thirteen', IO, '    if (reg >= SR_COUNT) return STORE_BAD_REG;\n'),
    gate('gate-lets-usbcmd-change-another-bit', IO, '((value ^ c->cmd_seen) & ~(uint32_t)(CMD_RS | CMD_HCRST)) || '),
    gate('gate-lets-usbcmd-set-rs-and-hcrst-together', IO, ' || (value & CMD_RS && value & CMD_HCRST)'),
    gate('gate-lets-usbcmd-be-stored-in-the-wrong-group', IO, '        if (group != (value & CMD_HCRST ? G_RESET : value & CMD_RS ? G_RUN : G_STOP)) return STORE_BITS;\n'),
    gate('gate-lets-a-register-be-stored-in-any-group', IO, '!(reg_groups[reg] & group) || '),
    gate('gate-lets-iman-take-more-than-ip', IO, ' || (reg == SR_IMAN && value != IMAN_IP)'),
    gate('gate-lets-the-doorbell-take-a-target', IO, ' || (reg == SR_DB0 && value)'),
    gate('gate-stores-outside-an-open-group', IO, '    if (group ? !(c->armed & group) : !c->armed) return STORE_NOT_ARMED;\n'),
    gate('gate-stores-to-a-window-that-faulted', IO, '    if (c->dead & (1u << TARGET)) return STORE_DEAD;\n'),
    gate('gate-stores-to-an-unaligned-offset', IO, '    if (off & 3 || off > store_limit() - 4) return STORE_RANGE;\n', '    if (off > store_limit() - 4) return STORE_RANGE;\n'),
    gate('gate-stores-at-or-above-the-dwc3-registers', IO, '    if (off & 3 || off > store_limit() - 4) return STORE_RANGE;\n', '    if (off & 3) return STORE_RANGE;\n'),
    gate('ram-gate-stores-with-the-arena-group-closed', IO, '!(c->armed & G_ARENA) || '),
    gate('ram-gate-stores-an-unaligned-word', IO, '(address & 3) || '),
    gate('ram-gate-admits-anything-to-an-arena-of-no-pages', IO, 'size < 4 || '),
    gate('ram-gate-stores-outside-the-arena', IO, RAM_BOUNDS),
    gate('cache-gate-takes-a-range-of-no-bytes', IO, '!bytes || '),
    gate('cache-gate-takes-a-range-longer-than-the-arena', IO, 'bytes > size || '),
    gate('cache-gate-takes-a-range-outside-the-arena', IO, ' || start - c->arena.base > size - bytes'),
    gate('clean-range-does-not-stop-at-the-arena', IO, CLEAN_GATE),
]


def evaluate(mutant, build_dir):
    """(status, detail): 'caught', 'survived', 'stale' (a needle is not in its file exactly once) or 'broken' (no build). A mutant with a suite is run
    on that suite alone."""
    name, edits, builds, suite = mutant
    directory = Path(build_dir) / f'mutant-{name}'
    x.copy_tree(directory)
    for file, needle, replacement in edits:
        path = directory / file
        text = path.read_text(encoding='utf-8')
        if text.count(needle) != 1:
            return 'stale', f'target not found exactly once in {file}: {needle[:70]!r}'
        path.write_text(text.replace(needle, replacement, 1), encoding='utf-8')
    for controller, cap, load_cap in builds:
        binary = directory / f'harness-{controller}-{cap}-{load_cap}'
        done = x.build_harness(controller, binary, root=directory, cap=cap, load_cap=load_cap)
        if done.returncode:
            return 'broken', f'controller {controller} cap {cap} loads {load_cap} did not compile: {done.stderr[-400:]}'
        code, output = x.run_harness(binary, *([suite] if suite else []))
        if code != 0:
            seen = [line for line in output.strip().splitlines() if 'Sanitizer' in line]
            last = 'hang' if code is None else (seen or output.strip().splitlines())[-1][:120]
            return 'caught', f'controller {controller} cap {cap} loads {load_cap}: ' + last
    return 'survived', 'every named build still passed'
