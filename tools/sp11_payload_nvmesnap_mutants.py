# SPDX-License-Identifier: MIT
"""Seeded bugs for the payload `nvmesnap` (docs/SP11-PAYLOAD-NVMESNAP.md, tools/test-q1n1-sp11-payload-nvmesnap.py).

Each one edits a copy of payloads/nvmesnap.c, payloads/payload-mmu.h or payloads/payload-page.h and builds the host program of
tools/test-q1n1-sp11-payload-nvmesnap.c against the copy (under ASan and UBSan, as the shipped suites are), then runs its suites one by one. A needle
that does not occur exactly once is a stale mutant and an error, never a pass. A mutant is caught only for its own reason: the suites named in `suites`
must fail, and the FAIL lines they print (or the sanitizer's report) must match `reason`, a regular expression over the host program's own words. A
program that fails for another reason (a crash nobody expected, a hang, a check that trips by accident) is `wrong-reason`, not a pass.

`flags` builds the host program with a smaller page or load cap, where a failure needs one to show. Hardware: NOT RUN. Evidence: EXPERIMENTAL (host
model only); serial on purpose, one build and one run at a time."""
from pathlib import Path
import re
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
try:
    from sp11_payload_nvmesnap_reasons import REASONS
except ImportError:                     # while the table is being written
    REASONS = {}

FILE = 'payloads/nvmesnap.c'
HEADER = 'payloads/payload-mmu.h'
PAGE = 'payloads/payload-page.h'
SUITES = ('unit', 'gates', 'gatemap', 'pages', 'faults', 'nvfaults', 'ctrl', 'queues', 'counter', 'el', 'budget', 'worst', 'fuzz')
PAGE14 = ('-DTEST_BUDGET=14', '-DPL_PAGE_LINES=14u')
CAP20 = ('-DTEST_LOAD_CAP=20', '-DLOAD_CAP=20u')
CAP10 = ('-DTEST_LOAD_CAP=10', '-DLOAD_CAP=10u')
SPIN = ('-DSPIN_MAX=1000u', '-DCOUNTER_STUCK_READS=100u', '-DTEST_SPIN_MAX=1000')
NEXT_CAPS = 'pl_say(a, p, "NEXT", text.buf, 1);'
GUARD_OPEN = '    } else if (win == WIN_NONE) {'
SLOT_WORD = 'w[i] = rd(a, c, at + 4u * words[i]);'
ACQ_ROW = '{"ACQ", 0x30, 1}'


def sub(name, old, new, suites, reason=None, file=FILE, flags=()):
    """(name, file, edits, suites that must fail, reason, flags)"""
    return (name, file, [(old, new)], tuple(suites.split()), reason, tuple(flags))


def two(name, edits, suites, reason=None, file=FILE, flags=()):
    """A seeded bug of several edits at once (a caller's bug and the guard that would have stopped it)."""
    return (name, file, list(edits), tuple(suites.split()), reason, tuple(flags))


MUTANTS = [
    # -- the reading discipline: which words are read, and never after a read that did not return
    sub('a-failed-config-read-does-not-stop-the-function', 'if (r.state != RS_VALUE) f->dead = 1;', '', 'faults'),
    sub('a-failed-register-read-does-not-stop-the-block', 'if (v->reg[i].state != RS_VALUE || (i == NR_CSTS2 && v->reg[i].value == ALL_ONES32)) stopped = 1;',
        'if (i == NR_CSTS2 && v->reg[i].value == ALL_ONES32) stopped = 1;', 'nvfaults'),
    sub('an-all-ones-second-csts-does-not-stop-the-block', 'if (v->reg[i].state != RS_VALUE || (i == NR_CSTS2 && v->reg[i].value == ALL_ONES32)) stopped = 1;',
        'if (v->reg[i].state != RS_VALUE) stopped = 1;', 'ctrl'),
    sub('a-failed-low-word-does-not-stop-the-pair', 'if (lo.state != RS_VALUE) return lo;', '', 'nvfaults'),
    sub('a-failed-high-word-is-a-value', 'if (hi.state != RS_VALUE) return hi;', '', 'nvfaults'),
    sub('a-failed-slot-word-does-not-stop-the-slot', '            return 0;\n        }\n    }\n    return 1;', '        }\n    }\n    return 1;', 'queues'),
    sub('a-failed-sq-read-does-not-stop-the-ram-reads', 'if (sq == Q_FAULT) return sq;', '', 'queues'),
    sub('a-failed-slot-does-not-stop-the-queue', '        if (!whole) {\n            result = Q_FAULT;\n            break;\n        }',
        '        if (!whole) result = Q_FAULT;', 'queues'),
    sub('the-high-word-is-eight-bytes-on', 'hi = rd(a, c, addr + 4u);', 'hi = rd(a, c, addr + 8u);', 'unit'),
    sub('the-pair-drops-its-high-word', 'lo.value |= hi.value << 32;', '', 'unit'),
    sub('the-faults-are-counted-as-refusals', 'if (r.state == RS_FAULT) c->faults++;\n    else c->refused++;', 'c->refused++;', 'faults'),
    sub('the-refusals-are-counted-as-faults', 'if (r.state == RS_FAULT) c->faults++;\n    else c->refused++;', 'c->faults++;', 'pages'),
    sub('the-loads-are-not-counted', '        c->loads++;\n        rc = a->ops.load32(addr, &c->word);', '        rc = a->ops.load32(addr, &c->word);', 'unit'),
    sub('a-refusal-is-called-a-fault', 'r.state = rc == Q1N1_PAYLOAD_LOAD_E_FAULT ? RS_FAULT : RS_REFUSED;', 'r.state = RS_FAULT;', 'pages'),
    sub('a-refusal-hides-its-code', 'pl_text(&item, "REFUSED:");\n        pl_dec(&item, r.code);', 'pl_text(&item, "REFUSED:");', 'pages'),
    # -- the last guard of rd(): a caller's bug is refused by it (visible in the page), and with the guard open it reads outside every window
    sub('the-slot-words-are-64-bytes-late', SLOT_WORD, 'w[i] = rd(a, c, at + 64u + 4u * words[i]);', 'unit queues'),
    two('the-slot-words-are-64-bytes-late-and-the-guard-is-open',
        [(SLOT_WORD, 'w[i] = rd(a, c, at + 64u + 4u * words[i]);'), (GUARD_OPEN, '    } else if (0) {')], 'unit queues', r'stray'),
    sub('acq-is-read-at-the-end-of-the-window', ACQ_ROW, '{"ACQ", 0x38, 1}', 'unit nvfaults'),
    two('acq-is-read-at-the-end-of-the-window-and-the-guard-is-open',
        [(ACQ_ROW, '{"ACQ", 0x38, 1}'), (GUARD_OPEN, '    } else if (0) {')], 'unit nvfaults', r'stray'),
    sub('the-controller-window-is-too-short', '#define NVME_READ_END 0x38u', '#define NVME_READ_END 0x34u', 'unit nvfaults'),
    sub('the-approved-extent-is-eight-bytes', 'approve_ram(a, c, at, (uint64_t)peek * entry_bytes, &type)', 'approve_ram(a, c, at, 8u, &type)', 'unit queues'),
    sub('the-load-cap-is-one-more', 'if (c->loads >= LOAD_CAP) {', 'if (c->loads > LOAD_CAP) {', 'budget', None, flags=CAP20),
    sub('the-load-cap-is-ignored', 'if (c->loads >= LOAD_CAP) {', 'if (0) {', 'budget', None, flags=CAP20),
    # -- what the MMU said of a page: nothing is read where it says no
    sub('the-approval-of-a-page-is-not-consulted', '    } else if (win < PAGE_COUNT && c->approved[win] != PS_OK) {', '    } else if (0) {', 'pages'),
    sub('the-root-ports-approval-is-the-endpoints', 'if (addr >= ROOT_PORT_PAGE && addr < ROOT_PORT_PAGE + CFG_PAGE_BYTES) return PAGE_RP;',
        'if (addr >= ROOT_PORT_PAGE && addr < ROOT_PORT_PAGE + CFG_PAGE_BYTES) return PAGE_EP;', 'pages'),
    sub('the-endpoints-approval-is-the-root-ports', 'if (addr >= ENDPOINT_PAGE && addr < ENDPOINT_PAGE + CFG_PAGE_BYTES) return PAGE_EP;',
        'if (addr >= ENDPOINT_PAGE && addr < ENDPOINT_PAGE + CFG_PAGE_BYTES) return PAGE_RP;', 'pages'),
    sub('the-root-port-is-read-without-asking-the-mmu', 'c.approved[PAGE_RP] = (uint8_t)add_walk(a, &c, "RP", ROOT_PORT_PAGE, 1);',
        'c.approved[PAGE_RP] = PS_OK;', 'pages unit'),
    sub('the-endpoint-is-read-without-asking-the-mmu', 'c.approved[PAGE_EP] = (uint8_t)add_walk(a, &c, "EP", ENDPOINT_PAGE, 1);',
        'c.approved[PAGE_EP] = PS_OK;', 'pages unit'),
    sub('a-normal-mapping-of-the-root-port-is-read', 'c.approved[PAGE_RP] = (uint8_t)add_walk(a, &c, "RP", ROOT_PORT_PAGE, 1);',
        'c.approved[PAGE_RP] = (uint8_t)add_walk(a, &c, "RP", ROOT_PORT_PAGE, 0);', 'pages'),
    sub('a-normal-mapping-of-the-endpoint-is-read', 'c.approved[PAGE_EP] = (uint8_t)add_walk(a, &c, "EP", ENDPOINT_PAGE, 1);',
        'c.approved[PAGE_EP] = (uint8_t)add_walk(a, &c, "EP", ENDPOINT_PAGE, 0);', 'pages'),
    sub('a-normal-mapping-of-the-controller-is-read', 'verdict = page_verdict(&bar_walk, 1);', 'verdict = page_verdict(&bar_walk, 0);', 'gates'),
    sub('an-unmapped-controller-page-is-read', 'why = verdict == PS_UNMAPPED ? W_BAR0_UNMAPPED : verdict == PS_NOT_DEVICE ? W_BAR0_NOT_DEVICE : W_NONE;',
        'why = verdict == PS_NOT_DEVICE ? W_BAR0_NOT_DEVICE : W_NONE;', 'gates'),
    sub('the-controller-page-is-not-asked-of-the-mmu', '            pl_walk_page(bar, &bar_walk);\n            mapped = 1;\n', '            mapped = 0;\n', 'gates unit'),
    sub('the-controller-is-approved-for-reading-without-the-gate', '        c.approved[PAGE_BAR0] = PS_OK;\n', '', 'unit'),
    sub('an-unmapped-queue-page-is-read', '    else if (add_walk(a, c, "MAP", at, 0) != PS_OK) result = Q_UNMAPPED;', '    else if (add_walk(a, c, "MAP", at, 0) == PS_UNASKED) result = Q_UNMAPPED;',
        'queues'),
    sub('a-device-mapping-is-required-of-a-queue-page', '    else if (add_walk(a, c, "MAP", at, 0) != PS_OK) result = Q_UNMAPPED;',
        '    else if (add_walk(a, c, "MAP", at, 1) != PS_OK) result = Q_UNMAPPED;', 'queues'),
    sub('par-f-is-inverted', 'w->mapped = !(par & 1);', 'w->mapped = par & 1;', 'pages gates', None, HEADER),
    sub('attr-from-the-wrong-bits', '(uint8_t)(par >> 56)', '(uint8_t)(par >> 55)', 'pages gates', None, HEADER),
    sub('sh-from-the-wrong-bits', '(uint8_t)(par >> 7 & 3)', '(uint8_t)(par >> 8 & 3)', 'unit pages', None, HEADER),
    sub('write-through-is-device', 'if (outer >> 2 == 2 && inner >> 2 == 2) return PL_ATTR_WT;', 'if (outer >> 2 == 2 && inner >> 2 == 2) return PL_ATTR_DEVICE;',
        'gates', None, HEADER),
    sub('device-with-gathering-bits-is-device', 'if (outer == 0) return (inner & 3u) == 0 ? PL_ATTR_DEVICE : PL_ATTR_OTHER;',
        'if (outer == 0) return PL_ATTR_DEVICE;', 'gates', None, HEADER),
    # -- the configuration space: the first reads of a function
    sub('an-absent-root-port-is-not-noticed', 'if (rp->absent) return W_RP_ABSENT;', '', 'gates'),
    sub('a-vendor-of-ones-is-not-absent', ' || (id.value & 0xffffu) == 0xffffu);', ');', 'gates'),
    sub('the-multi-function-bit-hides-a-bridge', 'type = h->hdr.state == RS_VALUE ? (uint32_t)(h->hdr.value >> 16 & 0x7fu) : 0xffu;',
        'type = h->hdr.state == RS_VALUE ? (uint32_t)(h->hdr.value >> 16 & 0xffu) : 0xffu;', 'gates worst'),
    sub('status-bit-4-is-bit-19', 'if (h->cmd.state == RS_VALUE && (h->cmd.value >> 20 & 1u)) {', 'if (h->cmd.state == RS_VALUE && (h->cmd.value >> 19 & 1u)) {',
        'unit gates'),
    sub('the-capability-pointer-is-not-aligned', 'h->cap_ptr = (uint8_t)(ptr.value & 0xfcu);', 'h->cap_ptr = (uint8_t)(ptr.value & 0xffu);', 'gates'),
    sub('the-bridge-buses-are-not-read', 'h->buses = cfg(a, c, f, 0x18);', 'h->buses = cfg(a, c, f, 0x1c);', 'unit gates'),
    sub('the-bridge-window-is-read-from-the-wrong-dword', 'h->memwin = cfg(a, c, f, 0x20);', 'h->memwin = cfg(a, c, f, 0x24);', 'unit gates'),
    sub('the-endpoints-bar-words-are-swapped', 'h->bar0 = cfg(a, c, f, 0x10);\n        h->bar1 = cfg(a, c, f, 0x14);',
        'h->bar0 = cfg(a, c, f, 0x14);\n        h->bar1 = cfg(a, c, f, 0x10);', 'unit gates'),
    # -- the capability lists and the link
    sub('the-capability-list-is-walked-32-times', '#define CAP_STEPS 16u', '#define CAP_STEPS 32u', 'gates'),
    sub('a-pointer-below-0x40-is-followed', 'ptr >= 0x40u && ptr < 0x100u;', 'ptr >= 0x30u && ptr < 0x100u;', 'gates'),
    sub('the-capability-id-is-sixteen-bits', 'id = (uint32_t)(r.value & 0xffu);', 'id = (uint32_t)(r.value & 0xffffu);', 'unit'),
    sub('a-next-pointer-is-not-aligned', 'ptr = (uint32_t)(r.value >> 8) & 0xfcu;', 'ptr = (uint32_t)(r.value >> 8) & 0xffu;', 'gates'),
    sub('the-walk-of-a-dead-function-is-not-refused', 'if (f->dead) {                                                      /* a read of the header did not return: the lists are not read */\n        out->walk = RS_FAULT;\n        return;\n    }', '', 'faults gates'),
    sub('the-first-power-capability-is-replaced-by-a-later-one', 'if (id == CAP_PM && want_pm && !out->pm_at) {', 'if (id == CAP_PM && want_pm) {', 'gates'),
    sub('the-root-port-reads-a-power-capability', 'read_caps(a, &c, &rp, &snap.rp, 0, &snap.rp_caps);', 'read_caps(a, &c, &rp, &snap.rp, 1, &snap.rp_caps);', 'unit'),
    sub('the-link-registers-are-at-0x08-and-0x0c', 'out->link_cap = cfg(a, c, f, ptr + 0x0cu);\n            out->link_sta = cfg(a, c, f, ptr + 0x10u);',
        'out->link_cap = cfg(a, c, f, ptr + 0x08u);\n            out->link_sta = cfg(a, c, f, ptr + 0x0cu);', 'unit'),
    sub('the-power-state-register-is-at-0x08', 'out->pm_csr = cfg(a, c, f, ptr + 0x04u);', 'out->pm_csr = cfg(a, c, f, ptr + 0x08u);', 'unit'),
    sub('the-link-speed-table-stops-at-gen5', 'speed >= 1u && speed <= 6u ? "GEN" : "SPEED"', 'speed >= 1u && speed <= 5u ? "GEN" : "SPEED"', 'gates'),
    sub('the-link-width-is-five-bits', 'width = sta >> 4 & 63u;', 'width = sta >> 4 & 31u;', 'gates'),
    sub('dlla-is-reported-without-the-capability', 'int reports = k->link_cap.state == RS_VALUE && (k->link_cap.value >> 20 & 1u);',
        'int reports = k->link_cap.state == RS_VALUE;', 'unit gates'),
    sub('dlla-is-bit-28', 'int dll_up = k->link_sta.value >> 29 & 1u,', 'int dll_up = k->link_sta.value >> 28 & 1u,', 'unit gates'),
    sub('training-is-bit-26', 'training = k->link_sta.value >> 27 & 1u;', 'training = k->link_sta.value >> 26 & 1u;', 'gates'),
    sub('aspm-is-three-bits', 'pl_add_dec(a, PG(c), "ASPM", k->link_sta.value & 3u);', 'pl_add_dec(a, PG(c), "ASPM", k->link_sta.value & 7u);', 'gates'),
    sub('the-power-state-is-one-bit', 'pl_add_dec(a, PG(c), "D", k->pm_csr.value & 3u);', 'pl_add_dec(a, PG(c), "D", k->pm_csr.value & 1u);', 'gates unit'),
    # -- the first gate
    sub('an-unread-root-port-word-is-not-noticed',
        'if (rp->id.state != RS_VALUE || rp->cmd.state != RS_VALUE || rp->cls.state != RS_VALUE || rp->hdr.state != RS_VALUE) return W_RP_NOT_READ;',
        'if (rp->id.state != RS_VALUE) return W_RP_NOT_READ;', 'gates'),
    sub('the-bridge-class-is-the-wrong-bits', '(rp->cls.value >> 16 & 0xffffu) != CLASS_BRIDGE', '(rp->cls.value >> 8 & 0xffffu) != CLASS_BRIDGE', 'unit gates'),
    sub('the-port-header-type-ignores-the-multi-function-bit', '(rp->hdr.value >> 16 & 0x7fu) != 1u) return W_RP_NOT_BRIDGE;',
        '(rp->hdr.value >> 16 & 0xffu) != 1u) return W_RP_NOT_BRIDGE;', 'gates'),
    sub('an-unread-bridge-window-is-not-noticed', 'if (rp->buses.state != RS_VALUE || rp->memwin.state != RS_VALUE) return W_RP_NOT_READ;',
        'if (rp->buses.state != RS_VALUE) return W_RP_NOT_READ;', 'gates'),
    sub('an-absent-endpoint-is-not-noticed', 'if (ep->absent) return W_EP_ABSENT;', '', 'gates'),
    sub('an-unread-endpoint-class-is-not-noticed',
        'if (ep->id.state != RS_VALUE || ep->cmd.state != RS_VALUE || ep->cls.state != RS_VALUE || ep->hdr.state != RS_VALUE) return W_EP_NOT_READ;',
        'if (ep->id.state != RS_VALUE || ep->cmd.state != RS_VALUE) return W_EP_NOT_READ;', 'gates'),
    sub('any-mass-storage-endpoint-is-an-nvme-one', '(ep->cls.value >> 8 & 0xffffffu) != CLASS_NVME', '(ep->cls.value >> 16 & 0xffu) != 0x01u', 'gates'),
    sub('any-non-volatile-memory-endpoint-is-an-nvme-one', '(ep->cls.value >> 8 & 0xffffffu) != CLASS_NVME', '(ep->cls.value >> 16 & 0xffffu) != 0x0108u', 'gates'),
    sub('a-bridge-is-an-endpoint', '(ep->hdr.value >> 16 & 0x7fu) != 0u) return W_EP_NOT_NVME;', '(ep->hdr.value >> 16 & 0x7fu) > 1u) return W_EP_NOT_NVME;', 'gates'),
    sub('an-endpoint-with-the-multi-function-bit-is-not-nvme', '(ep->hdr.value >> 16 & 0x7fu) != 0u) return W_EP_NOT_NVME;',
        '(ep->hdr.value >> 16 & 0xffu) != 0u) return W_EP_NOT_NVME;', 'gates'),
    sub('an-unread-bar-is-not-noticed', 'if (ep->bar0.state != RS_VALUE || ep->bar1.state != RS_VALUE) return W_EP_NOT_READ;',
        'if (ep->bar0.state != RS_VALUE) return W_EP_NOT_READ;', 'gates'),
    sub('the-primary-bus-is-not-checked', '(rp->buses.value & 0xffu) != RP_BUS || ', '', 'gates'),
    sub('the-secondary-bus-is-not-checked', '(rp->buses.value >> 8 & 0xffu) != EP_BUS || ', '', 'gates'),
    sub('the-subordinate-bus-is-not-checked', ' || (rp->buses.value >> 16 & 0xffu) < EP_BUS) return W_BUSES;', ') return W_BUSES;', 'gates'),
    sub('a-subordinate-bus-equal-to-the-secondary-is-refused', '(rp->buses.value >> 16 & 0xffu) < EP_BUS) return W_BUSES;',
        '(rp->buses.value >> 16 & 0xffu) <= EP_BUS) return W_BUSES;', 'unit'),
    # -- the second gate
    sub('a-skipped-capability-group-is-not-noticed', '    if (!s->caps_run) return W_CAPS_NOT_RUN;\n', '', 'counter'),
    sub('an-unread-root-port-list-is-fine', 'if (s->rp_caps.walk != RS_VALUE || s->ep_caps.walk != RS_VALUE) return W_CAPS_NOT_READ;',
        'if (s->ep_caps.walk != RS_VALUE) return W_CAPS_NOT_READ;', 'gates'),
    sub('an-unread-endpoint-list-is-fine', 'if (s->rp_caps.walk != RS_VALUE || s->ep_caps.walk != RS_VALUE) return W_CAPS_NOT_READ;',
        'if (s->rp_caps.walk != RS_VALUE) return W_CAPS_NOT_READ;', 'gates'),
    sub('an-unread-power-register-is-fine', 'if (s->ep_caps.pm_at && s->ep_caps.pm_csr.state != RS_VALUE) return W_CAPS_NOT_READ;', '', 'gates'),
    sub('a-port-with-a-capability-and-no-link-is-no-capability', 'return s->rp_caps.pcie_at ? W_CAPS_NOT_READ : W_NO_LINK_CAP;',
        'return s->rp_caps.pcie_at ? W_NO_LINK_CAP : W_CAPS_NOT_READ;', 'gates'),
    sub('an-unproven-link-is-accepted', 'if (link == L_UNPROVEN) return W_LINK_UNPROVEN;', '', 'gates'),
    sub('a-down-link-is-accepted', '    if (link == L_DOWN) return W_LINK_DOWN;\n', '', 'gates'),
    sub('a-training-link-is-accepted', '    if (s->rp_caps.link_sta.value >> 27 & 1u) return W_LINK_TRAINING;\n', '', 'gates'),
    sub('the-training-bit-is-bit-26', 'if (s->rp_caps.link_sta.value >> 27 & 1u) return W_LINK_TRAINING;', 'if (s->rp_caps.link_sta.value >> 26 & 1u) return W_LINK_TRAINING;',
        'gates'),
    sub('the-link-capability-bit-is-bit-21', 'if (!(k->link_cap.value >> 20 & 1u)) return L_UNPROVEN;', 'if (!(k->link_cap.value >> 21 & 1u)) return L_UNPROVEN;', 'gates unit'),
    sub('the-active-bit-is-bit-28', 'if (!(k->link_sta.value >> 29 & 1u)) return L_DOWN;', 'if (!(k->link_sta.value >> 28 & 1u)) return L_DOWN;', 'gates unit'),
    sub('memory-space-off-is-accepted', '    if (!(ep->cmd.value >> 1 & 1u)) return W_MEM_OFF;\n', '', 'gates'),
    sub('the-memory-space-bit-is-bit-0', 'if (!(ep->cmd.value >> 1 & 1u)) return W_MEM_OFF;', 'if (!(ep->cmd.value >> 0 & 1u)) return W_MEM_OFF;', 'gates unit'),
    sub('d1-and-d2-are-accepted', 'if (s->ep_caps.pm_at && (s->ep_caps.pm_csr.value & 3u)) return W_NOT_D0;', 'if (s->ep_caps.pm_at && (s->ep_caps.pm_csr.value & 3u) == 3u) return W_NOT_D0;',
        'gates'),
    sub('a-power-state-above-d0-is-accepted', '    if (s->ep_caps.pm_at && (s->ep_caps.pm_csr.value & 3u)) return W_NOT_D0;\n', '', 'gates'),
    sub('an-io-bar-is-a-register-window', 'if (ep->bar0.state != RS_VALUE || (type & 1u)) return 0;', 'if (ep->bar0.state != RS_VALUE) return 0;', 'gates'),
    sub('the-high-word-of-a-64-bit-bar-is-ignored', 'base |= ep->bar1.value << 32;', '', 'gates'),
    sub('a-reserved-bar-type-is-a-32-bit-bar', '    } else if ((type >> 1 & 3u) != 0u) {\n        return 0;', '    } else if (0) {\n        return 0;', 'gates'),
    sub('a-64-bit-bar-is-recognized-by-bit-1', 'if ((type >> 1 & 3u) == 2u) {', 'if ((type >> 1 & 3u) != 0u) {', 'gates'),
    sub('an-unaligned-bar-is-accepted', '    if (address & BAR_PAGE_MASK) return W_BAR0_UNALIGNED;\n', '', 'gates'),
    sub('the-bar-alignment-is-one-kib', '#define BAR_PAGE_MASK UINT64_C(0xfff)', '#define BAR_PAGE_MASK UINT64_C(0x3ff)', 'gates'),
    sub('a-bar-below-the-platform-window-is-accepted', 'address < PCIE_MEM_BASE || ', '', 'gates'),
    sub('a-bar-above-the-platform-window-is-accepted', ' || address > PCIE_MEM_END - NVME_READ_END) return W_BAR0_PLATFORM;', ') return W_BAR0_PLATFORM;', 'gates'),
    sub('the-first-page-of-the-platform-window-is-refused', 'address < PCIE_MEM_BASE || ', 'address <= PCIE_MEM_BASE || ', 'unit'),
    sub('the-platform-window-ends-a-page-early', '#define PCIE_MEM_END UINT64_C(0x74000000)', '#define PCIE_MEM_END UINT64_C(0x73fff000)', 'gates'),
    sub('the-platform-window-starts-elsewhere', '#define PCIE_MEM_BASE UINT64_C(0x70300000)', '#define PCIE_MEM_BASE UINT64_C(0x70400000)', 'unit gates'),
    sub('the-bridge-window-base-shift', 'base = (rp->memwin.value & 0xfff0u) << 16;', 'base = (rp->memwin.value & 0xfff0u) << 12;', 'unit gates'),
    sub('the-bridge-window-limit-has-no-fill', 'limit = (rp->memwin.value & 0xfff00000u) | 0xfffffu;', 'limit = (rp->memwin.value & 0xfff00000u);', 'gates unit'),
    sub('the-bridge-window-limit-is-from-the-base-field', 'limit = (rp->memwin.value & 0xfff00000u) | 0xfffffu;', 'limit = ((rp->memwin.value & 0xfff0u) << 16) | 0xfffffu;', 'gates unit'),
    sub('the-bridge-window-is-not-checked', 'if (base > limit || address < base || address > limit - NVME_READ_END + 1u) return W_BAR0_BRIDGE;', '', 'gates'),
    sub('a-bar-below-the-bridge-window-is-accepted', 'if (base > limit || address < base || address > limit - NVME_READ_END + 1u) return W_BAR0_BRIDGE;',
        'if (base > limit || address > limit - NVME_READ_END + 1u) return W_BAR0_BRIDGE;', 'gates'),
    sub('a-bar-above-the-bridge-window-is-accepted', 'if (base > limit || address < base || address > limit - NVME_READ_END + 1u) return W_BAR0_BRIDGE;',
        'if (base > limit || address < base) return W_BAR0_BRIDGE;', 'gates'),
    sub('a-bar-in-ram-is-accepted', 'why = overlap < 0 ? W_MAP_UNREADABLE : overlap ? W_BAR0_RAM : W_NONE;', 'why = overlap < 0 ? W_MAP_UNREADABLE : W_NONE;', 'gatemap'),
    sub('an-unreadable-map-is-no-reason-to-refuse', 'why = overlap < 0 ? W_MAP_UNREADABLE : overlap ? W_BAR0_RAM : W_NONE;', 'why = overlap > 0 ? W_BAR0_RAM : W_NONE;',
        'gates gatemap'),
    sub('an-unreadable-map-is-ram', 'why = overlap < 0 ? W_MAP_UNREADABLE : overlap ? W_BAR0_RAM : W_NONE;', 'why = overlap ? W_BAR0_RAM : W_NONE;', 'gates gatemap'),
    sub('the-memory-map-is-not-asked-about-the-bar', 'int overlap = ram_overlap(a, bar, NVME_READ_END);', 'int overlap = 0;', 'gatemap'),
    sub('a-descriptor-just-before-the-bar-overlaps', '        if (!pl_desc_read(a, i, &d) || addr >= d.end || addr + bytes <= d.start) continue;\n        if (usable_type((int)d.type)) return 1;',
        '        if (!pl_desc_read(a, i, &d) || addr > d.end || addr + bytes <= d.start) continue;\n        if (usable_type((int)d.type)) return 1;', 'gatemap'),
    sub('any-descriptor-over-the-bar-is-ram', '        if (usable_type((int)d.type)) return 1;\n    }\n    return 0;', '        return 1;\n    }\n    return 0;', 'gatemap'),
    sub('an-unreadable-memory-map-is-scanned', 'if (pl_map_check(a) != PL_MAP_OK) return -1;', '', 'gates gatemap queues'),
    # -- the memory map: which RAM is read at all
    sub('reserved-memory-is-readable', 'return (type >= 1 && type <= 7) || type == 9;', 'return (type >= 0 && type <= 7) || type == 9;', 'queues gatemap'),
    sub('unusable-memory-is-readable', 'return (type >= 1 && type <= 7) || type == 9;', 'return (type >= 1 && type <= 8) || type == 9;', 'queues gatemap'),
    sub('mmio-is-readable', 'return (type >= 1 && type <= 7) || type == 9;', 'return (type >= 1 && type <= 7) || type == 9 || type == 11;', 'queues gatemap'),
    sub('acpi-nvs-is-readable', 'return (type >= 1 && type <= 7) || type == 9;', 'return (type >= 1 && type <= 7) || type == 9 || type == 10;', 'queues gatemap'),
    sub('acpi-reclaim-is-not-readable', 'return (type >= 1 && type <= 7) || type == 9;', 'return type >= 1 && type <= 7;', 'queues gatemap'),
    sub('loader-code-is-not-readable', 'return (type >= 1 && type <= 7) || type == 9;', 'return (type >= 2 && type <= 7) || type == 9;', 'queues gatemap'),
    sub('conventional-memory-is-not-readable', 'return (type >= 1 && type <= 7) || type == 9;', 'return (type >= 1 && type <= 6) || type == 9;', 'queues gatemap'),
    sub('every-type-is-approved', '    if (!usable_type(*type)) return 0;\n    c->ram_lo = addr;', '    c->ram_lo = addr;', 'queues'),
    sub('another-type-overlapping-is-ignored', 'if (!usable_type((int)d.type)) return (int)d.type;', 'if (!usable_type((int)d.type)) continue;', 'queues'),
    sub('a-descriptor-just-before-the-queue-overlaps', 'if (!pl_desc_read(a, i, &d) || addr >= d.end || addr + bytes <= d.start) continue;\n        if (!usable_type',
        'if (!pl_desc_read(a, i, &d) || addr > d.end || addr + bytes <= d.start) continue;\n        if (!usable_type', 'queues'),
    sub('a-map-stride-below-40-is-accepted', 'if (stride < PL_DESC_BYTES_MIN) return PL_MAP_STRIDE_BELOW_40;', '', 'gates', None, HEADER),
    sub('a-partial-descriptor-is-accepted', 'if (!size || size % stride) return PL_MAP_SIZE;', 'if (!size) return PL_MAP_SIZE;', 'queues gatemap', None, HEADER),
    sub('a-huge-count-is-accepted', 'if (size / stride > PL_DESCRIPTORS_MAX) return PL_MAP_TOO_MANY;', '', 'queues gatemap', None, HEADER),
    sub('an-unaligned-descriptor-is-used', '(d->start & (PL_PAGE_BYTES - 1)) || ', '', 'queues gatemap', None, HEADER),
    # -- the controller registers
    sub('the-first-register-is-the-second', '{"CAP", 0x00, 1}', '{"CAP", 0x08, 1}', 'unit nvfaults'),
    sub('vs-is-at-the-wrong-offset', '{"VS", 0x08, 0}', '{"VS", 0x04, 0}', 'unit'),
    sub('cc-is-at-the-wrong-offset', '{"CC", 0x14, 0}', '{"CC", 0x10, 0}', 'unit'),
    sub('csts-is-at-the-wrong-offset', '{"CSTS", 0x1c, 0}', '{"CSTS", 0x18, 0}', 'unit'),
    sub('aqa-is-at-the-wrong-offset', '{"AQA", 0x24, 0}', '{"AQA", 0x20, 0}', 'unit'),
    sub('asq-is-a-single-word', '{"ASQ", 0x28, 1}', '{"ASQ", 0x28, 0}', 'unit'),
    sub('cap-is-a-single-word', '{"CAP", 0x00, 1}', '{"CAP", 0x00, 0}', 'unit'),
    sub('the-registers-tried-are-not-counted', '            v->made++;\n', '', 'unit nvfaults'),
    sub('the-registers-are-read-in-the-reverse-order', 'for (unsigned i = first; i < last; i++) {\n        if (!stopped) {', 'for (unsigned i = last; i-- > first;) {\n        if (!stopped) {',
        'unit nvfaults'),
    sub('a-stopped-register-is-printed-as-a-value', '        add_reading(a, c, nvme_regs[i].name, v->reg[i]);', '        add_reading(a, c, nvme_regs[i].name, v->reg[i].state == RS_FAULT ? (struct reading){0, RS_VALUE, 0} : v->reg[i]);',
        'nvfaults'),
    sub('the-controller-registers-are-read-without-the-gate', '    if (why == W_NONE) {\n        c.bar0 = bar;', '    if (1) {\n        c.bar0 = bar;', 'gates'),
    sub('the-wait-before-the-registers-is-not-made', 'if (!announce(a, PG(&c), freq, "NVME_REGS")) {', 'if (0) {', 'unit counter'),
    sub('the-wait-before-the-second-block-is-not-made', 'if (!announce(a, PG(&c), freq, "NVME_AQ")) {', 'if (0) {', 'unit counter'),
    sub('the-wait-before-the-capabilities-is-not-made', 'if (why == W_NONE && announce(a, PG(&c), freq, "CAPS")) {', 'if (why == W_NONE) {', 'unit counter'),
    sub('the-capabilities-are-read-although-the-header-gate-said-no', 'if (why == W_NONE && announce(a, PG(&c), freq, "CAPS")) {', 'if (announce(a, PG(&c), freq, "CAPS")) {',
        'gates'),
    sub('a-failed-register-in-a-block-is-no-reason', 'if (v->reg[i].state == RS_FAULT || v->reg[i].state == RS_REFUSED) return first ? W_AQ_NOT_READ : W_NO_REGISTERS;',
        'if (0) return first ? W_AQ_NOT_READ : W_NO_REGISTERS;', 'nvfaults'),
    sub('the-two-blocks-swap-their-reasons', 'return first ? W_AQ_NOT_READ : W_NO_REGISTERS;', 'return first ? W_NO_REGISTERS : W_AQ_NOT_READ;', 'nvfaults faults'),
    sub('a-register-never-tried-is-a-failed-read', 'v->reg[i].state == RS_FAULT || v->reg[i].state == RS_REFUSED) return', 'v->reg[i].state != RS_VALUE) return', 'ctrl'),
    sub('a-failed-read-says-the-controller-answers-with-ones', 'return first ? W_AQ_NOT_READ : W_NO_REGISTERS;', 'return W_ALL_ONES;', 'nvfaults faults'),
    sub('a-skipped-register-group-has-no-reason', '        if (!announce(a, PG(&c), freq, "NVME_REGS")) {\n            why = W_GROUP_SKIPPED;\n        } else {',
        '        if (!announce(a, PG(&c), freq, "NVME_REGS")) {\n        } else {', 'counter'),
    sub('a-skipped-second-block-has-no-reason', '        if (!announce(a, PG(&c), freq, "NVME_AQ")) {\n            why = W_GROUP_SKIPPED;\n        } else {',
        '        if (!announce(a, PG(&c), freq, "NVME_AQ")) {\n        } else {', 'counter'),
    sub('the-register-group-is-never-said-to-have-run', '            ran = 1;\n', '', 'unit'),
    # -- what the registers say
    sub('mqes-is-eight-bits', 'pl_add_dec(a, PG(c), "MQES", cap->value & 0xffffu);', 'pl_add_dec(a, PG(c), "MQES", cap->value & 0xffu);', 'ctrl unit'),
    sub('cqr-is-bit-17', 'pl_add_dec(a, PG(c), "CQR", cap->value >> 16 & 1u);', 'pl_add_dec(a, PG(c), "CQR", cap->value >> 17 & 1u);', 'ctrl unit'),
    sub('to-is-from-the-wrong-bits', 'pl_add_dec(a, PG(c), "TO", cap->value >> 24 & 0xffu);', 'pl_add_dec(a, PG(c), "TO", cap->value >> 23 & 0xffu);', 'ctrl unit'),
    sub('dstrd-is-from-the-wrong-bits', 'pl_add_dec(a, PG(c), "DSTRD", cap->value >> 32 & 15u);', 'pl_add_dec(a, PG(c), "DSTRD", cap->value >> 31 & 15u);', 'ctrl unit'),
    sub('nssrs-is-bit-37', 'pl_add_dec(a, PG(c), "NSSRS", cap->value >> 36 & 1u);', 'pl_add_dec(a, PG(c), "NSSRS", cap->value >> 37 & 1u);', 'ctrl unit'),
    sub('css-is-from-the-wrong-bits', 'pl_add_hex(a, PG(c), "CSS", cap->value >> 37 & 0xffu);', 'pl_add_hex(a, PG(c), "CSS", cap->value >> 36 & 0xffu);', 'ctrl unit'),
    sub('mpsmin-is-from-the-wrong-bits', 'pl_add_dec(a, PG(c), "MPSMIN", cap->value >> 48 & 15u);', 'pl_add_dec(a, PG(c), "MPSMIN", cap->value >> 47 & 15u);', 'ctrl unit'),
    sub('mpsmax-is-from-the-wrong-bits', 'pl_add_dec(a, PG(c), "MPSMAX", cap->value >> 52 & 15u);', 'pl_add_dec(a, PG(c), "MPSMAX", cap->value >> 51 & 15u);', 'ctrl unit'),
    sub('pmrs-is-bit-57', 'pl_add_dec(a, PG(c), "PMRS", cap->value >> 56 & 1u);', 'pl_add_dec(a, PG(c), "PMRS", cap->value >> 57 & 1u);', 'ctrl'),
    sub('cmbs-is-bit-56', 'pl_add_dec(a, PG(c), "CMBS", cap->value >> 57 & 1u);', 'pl_add_dec(a, PG(c), "CMBS", cap->value >> 56 & 1u);', 'ctrl'),
    sub('the-major-version-is-eight-bits', 'pl_dec(&item, vs->value >> 16 & 0xffffu);', 'pl_dec(&item, vs->value >> 16 & 0xffu);', 'ctrl'),
    sub('the-minor-version-is-from-the-wrong-bits', 'pl_dec(&item, vs->value >> 8 & 0xffu);', 'pl_dec(&item, vs->value >> 7 & 0xffu);', 'ctrl unit'),
    sub('the-tertiary-version-is-from-the-wrong-bits', 'pl_dec(&item, vs->value & 0xffu);\n        pl_page_add', 'pl_dec(&item, vs->value & 0xfu);\n        pl_page_add', 'ctrl'),
    sub('shst-is-one-bit', 'pl_add_dec(a, PG(c), "SHST", csts->value >> 2 & 3u);', 'pl_add_dec(a, PG(c), "SHST", csts->value >> 2 & 1u);', 'ctrl'),
    sub('cfs-is-bit-2', 'pl_add_dec(a, PG(c), "CFS", csts->value >> 1 & 1u);', 'pl_add_dec(a, PG(c), "CFS", csts->value >> 2 & 1u);', 'ctrl unit'),
    sub('css-of-cc-is-from-the-wrong-bits', 'pl_add_dec(a, PG(c), "CSS", cc->value >> 4 & 7u);', 'pl_add_dec(a, PG(c), "CSS", cc->value >> 5 & 7u);', 'ctrl'),
    sub('mps-is-three-bits', 'pl_add_dec(a, PG(c), "MPS", cc->value >> 7 & 15u);', 'pl_add_dec(a, PG(c), "MPS", cc->value >> 7 & 7u);', 'ctrl'),
    sub('ams-of-cc-is-from-the-wrong-bits', 'pl_add_dec(a, PG(c), "AMS", cc->value >> 11 & 7u);', 'pl_add_dec(a, PG(c), "AMS", cc->value >> 12 & 7u);', 'ctrl'),
    sub('shn-is-from-the-wrong-bits', 'pl_add_dec(a, PG(c), "SHN", cc->value >> 14 & 3u);', 'pl_add_dec(a, PG(c), "SHN", cc->value >> 13 & 3u);', 'ctrl'),
    sub('iosqes-is-from-the-wrong-bits', 'pl_add_dec(a, PG(c), "IOSQES", cc->value >> 16 & 15u);', 'pl_add_dec(a, PG(c), "IOSQES", cc->value >> 17 & 15u);', 'ctrl unit'),
    sub('iocqes-is-three-bits', 'pl_add_dec(a, PG(c), "IOCQES", cc->value >> 20 & 15u);', 'pl_add_dec(a, PG(c), "IOCQES", cc->value >> 20 & 7u);', 'ctrl'),
    sub('asqs-is-eleven-bits', 'out->sq_entries = (aqa->value & 0xfffu) + 1u;', 'out->sq_entries = (aqa->value & 0x7ffu) + 1u;', 'ctrl worst'),
    sub('acqs-is-from-the-wrong-bits', 'out->cq_entries = (aqa->value >> 16 & 0xfffu) + 1u;', 'out->cq_entries = (aqa->value >> 15 & 0xfffu) + 1u;', 'ctrl unit'),
    sub('aqa-is-not-one-based', 'out->sq_entries = (aqa->value & 0xfffu) + 1u;', 'out->sq_entries = (aqa->value & 0xfffu);', 'ctrl unit'),
    sub('a-fatal-controller-is-running', '    if (csts >> 1 & 1u) return C_FATAL;\n', '', 'ctrl'),
    sub('a-controller-in-shutdown-is-running', '    if (csts >> 2 & 3u) return C_SHUTDOWN;\n', '', 'ctrl'),
    sub('a-controller-that-is-enabled-and-not-ready-is-running', 'if ((cc & 1u) && (csts & 1u)) return C_RUNNING;', 'if (cc & 1u) return C_RUNNING;', 'ctrl'),
    sub('a-controller-that-is-ready-and-not-enabled-is-disabled', 'if (!(cc & 1u) && !(csts & 1u)) return C_DISABLED;', 'if (!(cc & 1u)) return C_DISABLED;', 'ctrl'),
    sub('an-unread-cc-is-a-state', 'if (v->reg[NR_CC].state != RS_VALUE || v->reg[NR_CSTS].state != RS_VALUE) return C_UNKNOWN;',
        'if (v->reg[NR_CSTS].state != RS_VALUE) return C_UNKNOWN;', 'nvfaults'),
    # -- the admin queues (read_queues is called only when both blocks of registers were read: the guards on an unknown state and on an unread queue
    # register cannot be reached from payload_entry, and a seeded bug that removes one is equivalent to the unmutated payload)
    sub('the-queues-of-a-disabled-controller-are-read', '    if (k->state != C_RUNNING) return Q_NOT_ENABLED;\n', '', 'ctrl queues'),
    sub('a-queue-of-one-entry-is-read', 'if (k->sq_entries < 2u || k->cq_entries < 2u ||', 'if (k->sq_entries < 1u || k->cq_entries < 1u ||', 'ctrl queues'),
    sub('only-the-submission-queue-size-is-checked', 'if (k->sq_entries < 2u || k->cq_entries < 2u ||', 'if (k->sq_entries < 2u ||', 'ctrl queues'),
    sub('a-queue-of-4096-entries-is-refused', 'k->sq_entries > QUEUE_ENTRIES_MAX || k->cq_entries > QUEUE_ENTRIES_MAX', 'k->sq_entries >= QUEUE_ENTRIES_MAX || k->cq_entries > QUEUE_ENTRIES_MAX',
        'worst ctrl'),
    sub('a-queue-at-address-zero-is-read', 'return at && !(at & BAR_PAGE_MASK)', 'return !(at & BAR_PAGE_MASK)', 'queues'),
    sub('an-unaligned-queue-is-read', 'return at && !(at & BAR_PAGE_MASK) &&', 'return at &&', 'queues'),
    sub('a-queue-beyond-48-bits-is-read', 'at < (UINT64_C(1) << ADDR_BITS_MAX)', '1', 'queues'),
    sub('a-queue-below-2-to-the-48-is-refused', 'at < (UINT64_C(1) << ADDR_BITS_MAX)', 'at < (UINT64_C(1) << 47)', 'queues'),
    sub('two-queues-in-one-page-are-read', 'if (!queue_address_ok(asq) || !queue_address_ok(acq) || asq == acq) return Q_BAD_ADDRESS;',
        'if (!queue_address_ok(asq) || !queue_address_ok(acq)) return Q_BAD_ADDRESS;', 'queues'),
    sub('the-queues-are-not-announced', '    pl_say(a, PG(c), "NEXT", "ADMIN_QUEUES", 1);\n', '', 'unit queues'),
    sub('the-submission-queue-is-not-read', '    sq = read_queue(a, c, "ASQ", "SQ", asq, k->sq_entries, SQE_BYTES, sqe_words, 6u);',
        '    sq = Q_NOT_READ;', 'unit'),
    sub('three-slots-are-read', '#define PEEK_ENTRIES 2u', '#define PEEK_ENTRIES 3u', 'unit queues'),
    sub('one-slot-is-read', '#define PEEK_ENTRIES 2u', '#define PEEK_ENTRIES 1u', 'unit queues'),
    sub('a-submission-entry-is-128-bytes', '#define SQE_BYTES 64u', '#define SQE_BYTES 128u', 'unit queues'),
    sub('a-completion-entry-is-32-bytes', '#define CQE_BYTES 16u', '#define CQE_BYTES 32u', 'unit queues'),
    sub('the-submission-words-are-the-wrong-ones', 'static const uint8_t sqe_words[6] = {0, 6, 7, 1, 10, 11};', 'static const uint8_t sqe_words[6] = {0, 6, 7, 1, 10, 12};',
        'unit queues'),
    sub('the-completion-words-are-the-wrong-ones', 'static const uint8_t cqe_words[3] = {3, 2, 0};', 'static const uint8_t cqe_words[3] = {3, 1, 0};', 'unit queues'),
    sub('the-prp1-is-the-low-word-only', 'pl_add_hex(a, PG(c), "PRP1", w[1].value | w[2].value << 32);', 'pl_add_hex(a, PG(c), "PRP1", w[1].value);', 'unit queues'),
    sub('the-opcode-is-sixteen-bits', 'pl_add_hex(a, PG(c), "OPC", w[0].value & 0xffu);', 'pl_add_hex(a, PG(c), "OPC", w[0].value & 0xffffu);', 'unit queues'),
    sub('the-command-id-is-from-the-wrong-bits', 'pl_add_hex(a, PG(c), "CID", w[0].value >> 16 & 0xffffu);', 'pl_add_hex(a, PG(c), "CID", w[0].value >> 8 & 0xffffu);', 'unit queues'),
    sub('the-phase-is-bit-17', 'pl_add_dec(a, PG(c), "P", w[0].value >> 16 & 1u);', 'pl_add_dec(a, PG(c), "P", w[0].value >> 17 & 1u);', 'unit queues'),
    sub('the-status-code-is-from-the-wrong-bits', 'pl_add_hex(a, PG(c), "SC", w[0].value >> 17 & 0xffu);', 'pl_add_hex(a, PG(c), "SC", w[0].value >> 16 & 0xffu);', 'queues'),
    sub('the-status-type-is-from-the-wrong-bits', 'pl_add_dec(a, PG(c), "SCT", w[0].value >> 25 & 7u);', 'pl_add_dec(a, PG(c), "SCT", w[0].value >> 24 & 7u);', 'queues'),
    sub('the-queue-head-is-from-the-wrong-bits', 'pl_add_hex(a, PG(c), "SQHD", w[1].value & 0xffffu);', 'pl_add_hex(a, PG(c), "SQHD", w[1].value & 0xffu);', 'unit queues'),
    sub('the-queue-id-is-from-the-wrong-bits', 'pl_add_hex(a, PG(c), "SQID", w[1].value >> 16 & 0xffffu);', 'pl_add_hex(a, PG(c), "SQID", w[1].value >> 15 & 0xffffu);', 'unit queues'),
    sub('a-queue-that-was-not-read-says-read', 'return sq != Q_READ ? sq : cq;', 'return Q_READ;', 'queues'),
    sub('the-completion-queue-reason-is-lost', 'return sq != Q_READ ? sq : cq;', 'return sq;', 'queues'),
    # -- the waits and the guards of the entry
    sub('the-wait-is-nothing', '#define WAIT_BEFORE_READ_S 8u', '#define WAIT_BEFORE_READ_S 0u', 'unit counter'),
    sub('the-wait-is-eighty-seconds', '#define WAIT_BEFORE_READ_S 8u', '#define WAIT_BEFORE_READ_S 80u', 'unit counter'),
    sub('the-wait-is-not-made', 'if (waited != WAIT_MADE) {', 'if (0) {', 'unit counter'),
    sub('a-counter-going-back-ends-the-wait', '        if (now < start) return WAIT_DEAD;\n', '', 'counter'),
    sub('a-stuck-counter-counts-as-a-wait-made', 'if (++same >= COUNTER_STUCK_READS) return WAIT_DEAD;', 'if (++same >= COUNTER_STUCK_READS) return WAIT_MADE;', 'counter'),
    sub('a-stuck-counter-has-no-limit', '#define COUNTER_STUCK_READS 2000000u', '#define COUNTER_STUCK_READS 0xffffffffu', 'counter'),
    sub('the-counter-op-is-not-checked', 'if (!a->ops.counter) {', 'if (0) {', 'counter'),
    sub('a-frequency-of-zero-is-used', 'if (freq < COUNTER_HZ_MIN || freq > COUNTER_HZ_MAX) freq = COUNTER_HZ_DEFAULT;', '', 'counter'),
    sub('the-lowest-frequency-is-refused', 'if (freq < COUNTER_HZ_MIN ||', 'if (freq <= COUNTER_HZ_MIN ||', 'counter'),
    sub('the-highest-frequency-is-refused', 'freq > COUNTER_HZ_MAX)', 'freq >= COUNTER_HZ_MAX)', 'counter'),
    sub('it-runs-below-el2', 'if ((current_el >> 2 & 3) != 2) {', 'if (0) {', 'el'),
    sub('el3-is-taken-for-el2', 'if ((current_el >> 2 & 3) != 2) {', 'if ((current_el >> 2 & 3) < 2) {', 'el'),
    sub('el1-is-taken-for-el2', 'if ((current_el >> 2 & 3) != 2) {', 'if ((current_el >> 2 & 3) > 2) {', 'el'),
    sub('the-arguments-are-not-checked', '    if (!pl_args_ok(a)) return Q1N1_PAYLOAD_RET_BAD_ARGS;\n', '', 'el'),
    sub('a-missing-load-op-is-not-noticed', 'if (!a->ops.load32) {', 'if (0) {', 'el'),
    # -- where the functions and the controller are
    sub('the-ecam-is-elsewhere', '#define ECAM_BASE UINT64_C(0x70000000)', '#define ECAM_BASE UINT64_C(0x70100000)', 'unit'),
    sub('the-endpoint-is-on-bus-2', '#define EP_BUS 1u', '#define EP_BUS 2u', 'unit'),
    sub('the-root-port-is-on-bus-1', '#define RP_BUS 0u', '#define RP_BUS 1u', 'unit'),
    sub('the-start-line-names-the-wrong-window', 'pl_add_hex(a, PG(&c), "WINDOW", PCIE_MEM_BASE);', 'pl_add_hex(a, PG(&c), "WINDOW", PCIE_MEM_END);', 'unit'),
    sub('the-page-prefix-is-in-lower-case', '#define PL_PAGE_PREFIX "PAYLOAD NVMESNAP "', '#define PL_PAGE_PREFIX "payload nvmesnap "', 'unit'),
    sub('a-register-that-was-not-tried-is-in-lower-case', 'pl_text(&item, "NOT_ATTEMPTED");', 'pl_text(&item, "not_attempted");', 'nvfaults'),
    sub('the-last-line-is-in-lower-case', 'pl_page_add(a, PG(&c), ran ? "NVME_GROUP_RAN" : "NVME_GROUP_SKIPPED");', 'pl_page_add(a, PG(&c), ran ? "nvme_group_ran" : "NVME_GROUP_SKIPPED");',
        'unit'),
    # -- the page: what may be dropped and what may not
    sub('next-lines-may-be-dropped', NEXT_CAPS, 'pl_say(a, p, "NEXT", text.buf, 0);', 'budget', None, flags=PAGE14),
    sub('the-queue-next-line-may-be-dropped', 'pl_say(a, PG(c), "NEXT", "ADMIN_QUEUES", 1);', 'pl_say(a, PG(c), "NEXT", "ADMIN_QUEUES", 0);', 'budget', None, flags=PAGE14),
    sub('the-last-line-may-be-dropped', 'pl_page_open(PG(&c), "DONE", 1);', 'pl_page_open(PG(&c), "DONE", 0);', 'budget', None, flags=PAGE14),
    sub('the-verdict-may-be-dropped', 'pl_page_open(PG(c), "VERDICT", 1);', 'pl_page_open(PG(c), "VERDICT", 0);', 'budget', None, flags=PAGE14),
    sub('nothing-is-reserved', '#define ESSENTIAL_LINES 6u', '#define ESSENTIAL_LINES 0u', 'budget', None, flags=PAGE14),
    sub('dropped-lines-are-not-counted', '        p->suppressed++;\n', '', 'budget', None, PAGE, PAGE14),
    sub('the-suppressed-count-is-not-printed', '    if (c.page.suppressed) pl_add_dec(a, PG(&c), "SUPPRESSED", c.page.suppressed);\n', '', 'budget', None, flags=PAGE14),
    sub('an-essential-line-does-not-use-its-reserve', '        if (p->essential_left) p->essential_left--;\n', '', 'budget', None, PAGE, PAGE14),
    sub('the-cap-refusal-is-called-a-fault', 'r.state = rc == Q1N1_PAYLOAD_LOAD_E_FAULT ? RS_FAULT : RS_REFUSED;', 'r.state = RS_FAULT;', 'budget', None, flags=CAP20),
    sub('the-cap-refusal-is-called-a-fault-in-the-header', 'r.state = rc == Q1N1_PAYLOAD_LOAD_E_FAULT ? RS_FAULT : RS_REFUSED;', 'r.state = RS_FAULT;', 'budget', None,
        flags=CAP10),
    sub('the-cap-refusal-hides-its-code', 'pl_text(&item, "REFUSED:");\n        pl_dec(&item, r.code);', 'pl_text(&item, "REFUSED:");', 'budget', None, flags=CAP10),
    sub('the-header-cap-is-one-more', 'if (c->loads >= LOAD_CAP) {', 'if (c->loads > LOAD_CAP) {', 'budget', None, flags=CAP10),
    sub('the-header-cap-is-ignored', 'if (c->loads >= LOAD_CAP) {', 'if (0) {', 'budget', None, flags=CAP10),
]
import sp11_payload_nvmesnap_mutants_more as _more  # noqa: E402  (it imports names back from this module: every one it needs is bound above)
MUTANTS += _more.MORE
REASONS.update(_more.REASONS_MORE)
SOURCES = {FILE: Path(__file__).resolve().parents[1] / FILE, HEADER: Path(__file__).resolve().parents[1] / HEADER, PAGE: Path(__file__).resolve().parents[1] / PAGE}


def stale(mutant):
    """The edits whose needle does not occur exactly once in the file they name (empty for a good mutant)."""
    name, file, edits = mutant[0], mutant[1], mutant[2]
    text = SOURCES[file].read_text(encoding='utf-8')
    return [(name, needle[:60], text.count(needle)) for needle, _ in edits if text.count(needle) != 1]


def interesting(output):
    """The words of the host program that say why it failed: its FAIL lines, the sanitizers' reports, a signal."""
    kept = [line for line in output.splitlines() if line.startswith(('FAIL', 'stray load', 'load ', 'line ')) or re.search(r'runtime error|Sanitizer', line)]
    return ' | '.join(kept)[:4000]


def evaluate(native, mutant, work, root):
    """(status, detail, failed) of one seeded bug: 'caught' (a named suite failed, for the reason REASONS gives), 'wrong-reason', 'survived', 'stale' or 'broken';
    `failed` is {suite: the words of its failure}."""
    name, file, edits, suites, _, flags = mutant
    reason = REASONS.get(name)
    bad = stale(mutant)
    if bad:
        return 'stale', f'target not found exactly once: {bad}', {}
    directory = work / name
    native.copy_tree(directory)
    for path in (directory / file,):
        text = path.read_text(encoding='utf-8')
        for needle, replacement in edits:
            text = text.replace(needle, replacement, 1)
        path.write_text(text, encoding='utf-8')
    binary = directory / 'bin' / 'test-nvmesnap'
    binary.parent.mkdir(parents=True, exist_ok=True)
    cmd = ['clang'] + native.SANITIZE + native.RELAXED + native.GATES + ['-I', str(directory / 'uefi'), '-I', str(directory / 'payloads'),
                                                                         '-DQ1N1_PAYLOAD_HOST_TEST=1'] + list(flags) + [
        str(root / 'tools' / 'test-q1n1-sp11-payload-nvmesnap.c'), str(directory / 'uefi' / 'sp11-payload-text.c'), str(directory / 'payloads' / 'nvmesnap.c'),
        '-o', str(binary)]
    done = native.run(cmd)
    if done.returncode:
        return 'broken', f'does not build: {done.stderr[-400:]}', {}
    failed = {}
    if any(flag.startswith('-DTEST_LOAD_CAP') for flag in flags):
        run_suites = ('budget',)
    elif any(flag.startswith('-DTEST_SPIN_MAX') for flag in flags):
        run_suites = ('counter',)
    elif flags:
        run_suites = ('budget', 'worst', 'fuzz')
    else:
        run_suites = SUITES
    for suite in run_suites:
        code, output = native.run_program(binary, suite)
        if code != 0:
            failed[suite] = 'HANG' if code is None else interesting(output) or f'exit {code}'
    if not failed:
        return 'survived', 'every suite still passed', failed
    summary = ' ## '.join(f'{s}: {t[:140]}' for s, t in failed.items())
    named = [s for s in suites if s in failed]
    if not named:
        return 'wrong-reason', f'none of {suites} failed; failed: {summary}', failed
    if not reason:
        return 'wrong-reason', f'no reason is given for {name}; failed: {summary}', failed
    if not any(re.search(reason, failed[s]) for s in named):
        return 'wrong-reason', f'{reason!r} not in {[failed[s][:200] for s in named]}', failed
    return 'caught', f'failed: {",".join(failed)} ## {summary}', failed
