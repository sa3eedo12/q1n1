#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""The seeded bugs of payloads/el1trap.c, for tools/test-q1n1-sp11-payload-el1trap.py (kept apart so that neither file passes the 50 KiB
limit): MUTANTS are edits of the C that the host program (tools/test-q1n1-sp11-payload-el1trap.c) must reject, ASM_MUTANTS are edits of
the assembly, which no host program runs, that the audit of the disassembly (the driver's `asm_problems`) must reject. Each needle must
occur exactly once in the source; a needle that does not is a stale mutant and the driver fails. Nothing here runs on hardware."""

FILE = 'payloads/el1trap.c'
WRITES = ('    write_vbar_el1(r->wanted[R_VBAR1]);\n    write_sctlr_el1(r->wanted[R_SCTLR]);\n    write_cnthctl_el2(r->wanted[R_CNTHCTL]);\n'
          '    write_hcr_el2(r->wanted[R_HCR]);\n    isb();\n')
RESTORE = ('    for (unsigned i = 0; i <= R_VBAR1; i++) write_register(i, r->saved[i]);    /* HCR_EL2 first: the reverse of the order it was set in */\n'
           '    isb();\n')
RETRY = '        write_register(i, r->saved[i]);\n        isb();\n        w->restored[i] = read_register(i);\n        w->retried |= 1u << i;\n'
PROBE = '    prepare(&r, &w.probe, MODE_PROBE);\n    RUN(&w.probe, EL1_STUB);\n    w.probe_done = 1;\n'
VBAR2_RETRY = ('    if (w.restored[R_VBAR2] != r.saved[R_VBAR2]) {      /* el1trap_run puts it back; one more write if that did not hold */\n'
               '        write_register(R_VBAR2, r.saved[R_VBAR2]);\n        isb();\n        w.restored[R_VBAR2] = read_register(R_VBAR2);\n'
               '        w.retried |= 1u << R_VBAR2;\n    }\n')
NEXT_AFTER = '    say(&r.out, "NEXT EL1 EXCURSION AFTER 8 S");\n'
WAIT = '    if (!wait_seconds(a, r.hz, WAIT_BEFORE_EXCURSION_S)) {\n        say(&r.out, "REFUSED=COUNTER_STUCK");\n        return 0;\n    }\n'
NEXT = '    say(&r.out, "NEXT EL1 EXCURSION");\n'
CLEAN = '    for (uint64_t at = start & ~(uint64_t)(CACHE_STEP - 1); at < start + bytes; at += CACHE_STEP) dc_civac(at);\n'
INVALIDATE = '    for (uint64_t at = start & ~(uint64_t)(CACHE_STEP - 1); at < start + bytes; at += CACHE_STEP) ic_ivau(at);\n'
HCR_CHECKED = '#define HCR_BITS_CHECKED ((UINT64_C(1) << 31) | (UINT64_C(1) << 34) | (UINT64_C(1) << 27) | (UINT64_C(1) << 29) | UINT64_C(1) | \\\n'
SCTLR_CHECKED = ('#define SCTLR_EL1_BITS_CHECKED (UINT64_C(0x1) | UINT64_C(0x2) | UINT64_C(0x4) | UINT64_C(0x1000) | UINT64_C(0x80000) | '
                 'UINT64_C(0x1000000) | \\\n')
COPY_SPSR = ("        w->e.caller_spsr = w->probe.caller_spsr;        /* what the probe's HVC #2 saw of the caller: "
             "the last ERET returns five bits of it */\n")
LAYOUT_ALIGNED = 'if ((el2 & 2047) || (el1 & 2047) || (stub & 3)) return 0;'


def sub(name, old, new):
    return ('el1trap-' + name, FILE, [(old, new)], ['el1trap'], None)


def drop(name, statement):
    return sub(name, statement, '')


def hcr_bit(name, old):
    return sub(f'hcr-check-misses-{name}', HCR_CHECKED, HCR_CHECKED.replace(old, '', 1))


def sctlr_bit(name, old):
    return sub(f'sctlr-check-misses-{name}', SCTLR_CHECKED, SCTLR_CHECKED.replace(old, '', 1))


MUTANTS = [
    # -- the values the excursion writes
    sub('hcr-also-sets-tge', '#define HCR_EXCURSION (UINT64_C(1) << 31)', '#define HCR_EXCURSION ((UINT64_C(1) << 31) | (UINT64_C(1) << 27))'),
    sub('hcr-also-sets-imo', '#define HCR_EXCURSION (UINT64_C(1) << 31)', '#define HCR_EXCURSION ((UINT64_C(1) << 31) | (UINT64_C(1) << 4))'),
    sub('hcr-also-sets-hcd', '#define HCR_EXCURSION (UINT64_C(1) << 31)', '#define HCR_EXCURSION ((UINT64_C(1) << 31) | (UINT64_C(1) << 29))'),
    sub('hcr-also-sets-e2h', '#define HCR_EXCURSION (UINT64_C(1) << 31)', '#define HCR_EXCURSION ((UINT64_C(1) << 31) | (UINT64_C(1) << 34))'),
    sub('hcr-also-sets-dc', '#define HCR_EXCURSION (UINT64_C(1) << 31)', '#define HCR_EXCURSION ((UINT64_C(1) << 31) | (UINT64_C(1) << 12))'),
    sub('hcr-without-rw', '#define HCR_EXCURSION (UINT64_C(1) << 31)', '#define HCR_EXCURSION UINT64_C(0)'),
    sub('sctlr-sets-the-mmu', 'UINT64_C(0x30500800)', 'UINT64_C(0x30500801)'),
    sub('sctlr-sets-the-data-cache', 'UINT64_C(0x30500800)', 'UINT64_C(0x30500804)'),
    sub('sctlr-sets-the-instruction-cache', 'UINT64_C(0x30500800)', 'UINT64_C(0x30501800)'),
    sub('sctlr-sets-span-as-well', 'UINT64_C(0x30500800)', 'UINT64_C(0x30D00800)'),
    sub('cnthctl-keeps-the-el1-physical-bits', '(cnthctl & ~EL1_PHYSICAL_BITS) | EL1TVCT_BIT | EL1TVT_BIT;', 'cnthctl | EL1TVCT_BIT | EL1TVT_BIT;'),
    sub('cnthctl-clears-only-bit-0', '#define EL1_PHYSICAL_BITS UINT64_C(3)', '#define EL1_PHYSICAL_BITS UINT64_C(1)'),
    sub('cnthctl-sets-ecv-as-well', '(cnthctl & ~EL1_PHYSICAL_BITS) | EL1TVCT_BIT | EL1TVT_BIT;', '(cnthctl & ~EL1_PHYSICAL_BITS) | EL1TVCT_BIT | EL1TVT_BIT | ECV_BIT;'),
    sub('cnthctl-sets-only-bit-14', '(cnthctl & ~EL1_PHYSICAL_BITS) | EL1TVCT_BIT | EL1TVT_BIT;', '(cnthctl & ~EL1_PHYSICAL_BITS) | EL1TVCT_BIT;'),
    sub('cnthctl-sets-only-bit-13', '(cnthctl & ~EL1_PHYSICAL_BITS) | EL1TVCT_BIT | EL1TVT_BIT;', '(cnthctl & ~EL1_PHYSICAL_BITS) | EL1TVT_BIT;'),
    sub('cnthctl-bit-13-is-bit-15', '#define EL1TVT_BIT (UINT64_C(1) << 13)', '#define EL1TVT_BIT (UINT64_C(1) << 15)'),
    sub('vbar-el1-is-the-el2-table', '    r.wanted[R_VBAR1] = EL1_VECTORS;\n', '    r.wanted[R_VBAR1] = EL2_VECTORS;\n'),
    # -- the order of the writes, the barriers, the read-back, the put-back
    sub('hcr-is-written-first', WRITES, '    write_hcr_el2(r->wanted[R_HCR]);\n    write_vbar_el1(r->wanted[R_VBAR1]);\n    write_sctlr_el1(r->wanted[R_SCTLR]);\n'
                                        '    write_cnthctl_el2(r->wanted[R_CNTHCTL]);\n    isb();\n'),
    sub('cnthctl-is-written-before-sctlr', WRITES, '    write_vbar_el1(r->wanted[R_VBAR1]);\n    write_cnthctl_el2(r->wanted[R_CNTHCTL]);\n'
                                                   '    write_sctlr_el1(r->wanted[R_SCTLR]);\n    write_hcr_el2(r->wanted[R_HCR]);\n    isb();\n'),
    sub('no-isb-before-the-read-back', WRITES, WRITES.replace('    isb();\n', '')),
    sub('no-isb-after-the-put-back', RESTORE, RESTORE.replace('    isb();\n', '')),
    sub('puts-back-in-the-order-set', RESTORE, '    for (unsigned i = R_VBAR1 + 1; i > 0; i--) write_register(i - 1, r->saved[i - 1]);\n    isb();\n'),
    sub('never-puts-vbar-el1-back', RESTORE, RESTORE.replace('i <= R_VBAR1', 'i < R_VBAR1')),
    sub('never-retries', '        if (w->restored[i] == r->saved[i]) continue;\n        write_register(i, r->saved[i]);\n',
        '        if (1) continue;\n        write_register(i, r->saved[i]);\n'),
    sub('always-retries', '        if (w->restored[i] == r->saved[i]) continue;\n        write_register(i, r->saved[i]);\n',
        '        if (0) continue;\n        write_register(i, r->saved[i]);\n'),
    sub('retries-without-an-isb', RETRY, RETRY.replace('        isb();\n', '')),
    sub('retries-with-the-value-under-test', RETRY, RETRY.replace('write_register(i, r->saved[i]);', 'write_register(i, r->wanted[i % 4]);')),
    sub('does-not-read-after-the-retry', RETRY, RETRY.replace('        w->restored[i] = read_register(i);\n', '')),
    sub('runs-without-checking-the-writes', '    w->held = (uint32_t)writes_held(r, w->readback);\n', '    w->held = 1;\n'),
    sub('never-runs', '    if (w->held) {\n', '    if (0) {\n'),
    sub('reads-the-registers-back-before-writing', WRITES + '    for (unsigned i = 0; i < R_VBAR2; i++) w->readback[i] = read_register(i);\n',
        '    for (unsigned i = 0; i < R_VBAR2; i++) w->readback[i] = read_register(i);\n' + WRITES),
    sub('reads-another-register-inside-the-window', '    w->held = (uint32_t)writes_held(r, w->readback);\n',
        '    w->held = (uint32_t)writes_held(r, w->readback);\n    (void)SYSREG(esr_el2);\n'),
    drop('does-not-pass-the-probes-view-of-the-caller-to-the-excursion', COPY_SPSR),
    # -- the held check: each bit that decides whether EL1 can be entered
    sub('ignores-hcr-in-the-held-check', '    return (readback[R_HCR] & HCR_BITS_CHECKED) == (r->wanted[R_HCR] & HCR_BITS_CHECKED) &&\n', '    return 1 &&\n'),
    sub('ignores-sctlr-in-the-held-check', '           (readback[R_SCTLR] & SCTLR_EL1_BITS_CHECKED) == (r->wanted[R_SCTLR] & SCTLR_EL1_BITS_CHECKED) &&\n', '           1 &&\n'),
    sub('ignores-vbar-in-the-held-check', '           readback[R_VBAR1] == r->wanted[R_VBAR1] && !(readback[R_CNTHCTL] & ECV_BIT);', '           !(readback[R_CNTHCTL] & ECV_BIT);'),
    sub('ignores-ecv-in-the-held-check', '           readback[R_VBAR1] == r->wanted[R_VBAR1] && !(readback[R_CNTHCTL] & ECV_BIT);', '           readback[R_VBAR1] == r->wanted[R_VBAR1];'),
    sub('hcr-check-misses-rw', HCR_CHECKED, HCR_CHECKED.replace('((UINT64_C(1) << 31) | ', '(', 1)),
    hcr_bit('e2h', '(UINT64_C(1) << 34) | '),
    hcr_bit('tge', '(UINT64_C(1) << 27) | '),
    hcr_bit('hcd', '(UINT64_C(1) << 29) | '),
    hcr_bit('vm', 'UINT64_C(1) | \\\n'),
    sub('hcr-check-misses-dc', '(UINT64_C(1) << 12) | (UINT64_C(7) << 3))        /* RW, E2H', '(UINT64_C(7) << 3))        /* RW, E2H'),
    sub('hcr-check-misses-fmo', '(UINT64_C(7) << 3))        /* RW, E2H', '(UINT64_C(6) << 3))        /* RW, E2H'),
    sub('hcr-check-misses-imo', '(UINT64_C(7) << 3))        /* RW, E2H', '(UINT64_C(5) << 3))        /* RW, E2H'),
    sub('hcr-check-misses-amo', '(UINT64_C(7) << 3))        /* RW, E2H', '(UINT64_C(3) << 3))        /* RW, E2H'),
    sctlr_bit('m', 'UINT64_C(0x1) | '),
    sctlr_bit('a', 'UINT64_C(0x2) | '),
    sctlr_bit('c', 'UINT64_C(0x4) | '),
    sctlr_bit('i', 'UINT64_C(0x1000) | '),
    sctlr_bit('wxn', 'UINT64_C(0x80000) | '),
    sctlr_bit('e0e', 'UINT64_C(0x1000000) | \\\n'),
    sub('sctlr-check-misses-ee', '| \\\n                                UINT64_C(0x2000000))', ')'),
    # -- the probe
    drop('never-probes', PROBE),
    sub('probe-is-an-excursion', 'prepare(&r, &w.probe, MODE_PROBE);', 'prepare(&r, &w.probe, MODE_EXCURSION);'),
    sub('ignores-a-failed-probe', '    if (!w.probe.probe_ok || w.probe.reason || w.restored[R_VBAR2] != r.saved[R_VBAR2]) {\n', '    if (0) {\n'),
    sub('ignores-vbar-el2-that-is-not-back', ' || w.restored[R_VBAR2] != r.saved[R_VBAR2]) {\n        row(&line);\n        word(&line, "HVC_AT_EL2=FAILED");', ') {\n        row(&line);\n        word(&line, "HVC_AT_EL2=FAILED");'),
    drop('does-not-put-vbar-el2-back-after-the-probe', VBAR2_RETRY),
    sub('probe-failure-says-restored-without-looking', '        for (unsigned i = 0; i < R_VBAR2; i++) w.restored[i] = r.saved[i];     /* nothing but VBAR_EL2 was ever changed */\n',
        '        for (unsigned i = 0; i < R_COUNT; i++) w.restored[i] = r.saved[i];\n'),
    # -- announce, wait, then the work
    drop('never-announces-the-wait', NEXT_AFTER),
    drop('never-announces-the-excursion', NEXT),
    sub('announces-the-excursion-after-the-window', NEXT + '\n    excursion_window(&r, &w);\n', '\n    excursion_window(&r, &w);\n' + NEXT),
    sub('waits-before-announcing', NEXT_AFTER + WAIT, WAIT + NEXT_AFTER),
    sub('does-not-wait', WAIT, '    if (0) {\n        say(&r.out, "REFUSED=COUNTER_STUCK");\n        return 0;\n    }\n'),
    sub('goes-on-with-a-stuck-counter', WAIT, '    wait_seconds(a, r.hz, WAIT_BEFORE_EXCURSION_S);\n'),
    sub('waits-one-second-not-eight', '#define WAIT_BEFORE_EXCURSION_S 8u', '#define WAIT_BEFORE_EXCURSION_S 1u'),
    sub('waits-eighty-seconds', '#define WAIT_BEFORE_EXCURSION_S 8u', '#define WAIT_BEFORE_EXCURSION_S 80u'),
    sub('waits-at-a-fixed-19-2-mhz', 'if (now - start >= hz * seconds) return 1;', 'if (now - start >= 19200000u * seconds) return 1;'),
    sub('does-not-bound-the-frequency', 'r.hz = cntfrq >= COUNTER_HZ_MIN && cntfrq <= COUNTER_HZ_MAX ? cntfrq : COUNTER_HZ_DEFAULT;', 'r.hz = cntfrq;'),
    sub('frequency-lower-bound-is-one-too-high', '#define COUNTER_HZ_MIN 1000000u', '#define COUNTER_HZ_MIN 1000001u'),
    sub('frequency-upper-bound-excludes-one-ghz', 'cntfrq <= COUNTER_HZ_MAX ?', 'cntfrq < COUNTER_HZ_MAX ?'),
    sub('waits-one-read-too-long', 'if (now - start >= hz * seconds) return 1;', 'if (now - start > hz * seconds) return 1;'),
    sub('counts-from-zero-not-from-the-first-read', 'if (now - start >= hz * seconds) return 1;', 'if (now >= hz * seconds) return 1;'),
    sub('gives-up-on-a-slow-counter', '#define COUNTER_STUCK_READS 2000000u', '#define COUNTER_STUCK_READS 20u'),
    drop('wait-does-not-refuse-a-counter-that-goes-back', '        if (now < start) return 0;\n'),
    sub('wait-takes-a-read-at-the-start-for-a-read-below-it', '        if (now < start) return 0;\n', '        if (now <= start) return 0;\n'),
    sub('deadline-is-zero-seconds', '#define DEADLINE_S 1u', '#define DEADLINE_S 0u'),
    sub('deadline-ignores-the-frequency', '    e->deadline = r->a->ops.counter() + r->hz * DEADLINE_S;\n', '    e->deadline = r->a->ops.counter() + DEADLINE_S;\n'),
    # -- the image is made visible to a core that fetches without its caches
    drop('does-not-clean-the-image', CLEAN),
    drop('does-not-invalidate-the-instruction-cache', INVALIDATE),
    sub('no-barrier-between-clean-and-invalidate', '    dsb_sy();\n' + INVALIDATE, INVALIDATE),
    sub('no-barrier-after-the-invalidate', 'ic_ivau(at);\n    dsb_sy();\n    isb();\n', 'ic_ivau(at);\n    isb();\n'),
    sub('no-isb-after-the-cache-work', '    dsb_sy();\n    isb();\n}\n', '    dsb_sy();\n}\n'),
    sub('cache-step-is-32', '#define CACHE_STEP 16u', '#define CACHE_STEP 32u'),
    sub('cleans-all_but_the_last_line', 'at < start + bytes; at += CACHE_STEP) dc_civac(at);', 'at + CACHE_STEP < start + bytes; at += CACHE_STEP) dc_civac(at);'),
    sub('cleans-from-the-unaligned-start', CLEAN, CLEAN.replace('start & ~(uint64_t)(CACHE_STEP - 1)', 'start')),
    # -- what it refuses
    drop('does-not-check-the-arguments', '    if (!pl_args_ok(a)) return Q1N1_PAYLOAD_RET_BAD_ARGS;\n'),
    sub('runs-at-any-el', '    if ((current_el >> 2 & 3) != 2) {\n', '    if (0) {\n'),
    sub('takes-el3-for-el2', '    if ((current_el >> 2 & 3) != 2) {\n', '    if ((current_el >> 2 & 3) < 2) {\n'),
    sub('does-not-check-for-the-counter-op', '    if (!a->ops.counter) {\n', '    if (0) {\n'),
    sub('does-not-check-the-layout', '    if (!layout_ok(a)) {\n', '    if (0) {\n'),
    sub('layout-ignores-the-start-of-the-image', 'if (el2 < base || el2 + 2048 > end', 'if (el2 + 2048 > end'),
    sub('layout-ignores-the-end-of-the-stub', 'stub + EL1_STUB_BYTES > end', 'stub + 4 > end'),
    sub('layout-ignores-a-huge-image', 'if (a->payload_size >= (UINT64_C(1) << 32) || end < base) return 0;', 'if (end < base) return 0;'),
    sub('layout-aligns-the-tables-to-1-kib', LAYOUT_ALIGNED, 'if ((el2 & 1023) || (el1 & 1023) || (stub & 3)) return 0;'),
    sub('layout-aligns-the-stub-to-2-bytes', LAYOUT_ALIGNED, 'if ((el2 & 2047) || (el1 & 2047) || (stub & 1)) return 0;'),
    sub('layout-does-not-align-the-el2-table', LAYOUT_ALIGNED, 'if ((el1 & 2047) || (stub & 3)) return 0;'),
    sub('layout-does-not-align-the-el1-table', LAYOUT_ALIGNED, 'if ((el2 & 2047) || (stub & 3)) return 0;'),
    sub('layout-does-not-align-the-stub', LAYOUT_ALIGNED, 'if ((el2 & 2047) || (el1 & 2047)) return 0;'),
    drop('does-not-refuse-e2h', '    if (hcr >> 34 & 1) return "REFUSED=E2H";\n'),
    sub('e2h-is-bit-33', '    if (hcr >> 34 & 1) return "REFUSED=E2H";\n', '    if (hcr >> 33 & 1) return "REFUSED=E2H";\n'),
    drop('does-not-refuse-a-core-without-aarch64-el1', '    if ((pfr0 >> 4 & 15) == 0) return "REFUSED=NO_EL1_AARCH64";\n'),
    sub('el1-field-is-bits-11-to-8', '    if ((pfr0 >> 4 & 15) == 0) return "REFUSED=NO_EL1_AARCH64";\n', '    if ((pfr0 >> 8 & 15) == 0) return "REFUSED=NO_EL1_AARCH64";\n'),
    drop('does-not-refuse-unmasked-interrupts', '    if ((daif & DAIF_MASKED) != DAIF_MASKED) return "REFUSED=DAIF_NOT_MASKED";\n'),
    sub('refuses-only-when-all-of-daif-is-unmasked', '(daif & DAIF_MASKED) != DAIF_MASKED', '!(daif & DAIF_MASKED)'),
    drop('does-not-refuse-sp0', '    if (!(spsel & 1)) return "REFUSED=SPSEL_NOT_EL2H";\n'),
    drop('does-not-refuse-an-old-with-bits-set', '    if (cnthctl & OLD_REFUSED_BITS) return "REFUSED=OLD_HAS_BITS_12_TO_14";\n'),
    sub('refuses-only-an-old-with-ecv-set', '#define OLD_REFUSED_BITS (ECV_BIT | EL1TVT_BIT | EL1TVCT_BIT)', '#define OLD_REFUSED_BITS (ECV_BIT)'),
    sub('refuses-an-old-with-bit-15-set', '#define OLD_REFUSED_BITS (ECV_BIT | EL1TVT_BIT | EL1TVCT_BIT)', '#define OLD_REFUSED_BITS (ECV_BIT | EL1TVT_BIT | EL1TVCT_BIT | (UINT64_C(1) << 15))'),
    sub('does-not-check-the-stack', 'if (sp < r->a->stack_base + STACK_KEPT_BYTES || sp > r->a->stack_base + r->a->stack_size) return "REFUSED=STACK";',
        'if (0) return "REFUSED=STACK";'),
    sub('stack-low-bound-is-off-by-one', 'sp < r->a->stack_base + STACK_KEPT_BYTES', 'sp <= r->a->stack_base + STACK_KEPT_BYTES'),
    sub('stack-high-bound-is-off-by-one', 'sp > r->a->stack_base + r->a->stack_size', 'sp >= r->a->stack_base + r->a->stack_size'),
    sub('keeps-only-8-kib-of-stack', '#define STACK_KEPT_BYTES (16u * 1024u)', '#define STACK_KEPT_BYTES (8u * 1024u)'),
    # -- the page and the verdict
    sub('effective-when-either-ecv-read-traps', 'trapped[ACCESS_VCT] && trapped[ACCESS_VTIMER] ? "TRAPS_EFFECTIVE"', 'trapped[ACCESS_VCT] || trapped[ACCESS_VTIMER] ? "TRAPS_EFFECTIVE"'),
    sub('inert-when-either-ecv-read-does-not-trap', '!trapped[ACCESS_VCT] && !trapped[ACCESS_VTIMER] ? "TRAPS_INERT"', '!trapped[ACCESS_VCT] || !trapped[ACCESS_VTIMER] ? "TRAPS_INERT"'),
    sub('verdict-ignores-the-control', '!trapped[ACCESS_CONTROL] ? "CONTROL_NOT_TRAPPED"', '0 ? "CONTROL_NOT_TRAPPED"'),
    drop('does-not-say-when-cntfrq-trapped', '        if (trapped[ACCESS_FRQ]) word(&line, "CNTFRQ_EL0_TRAPPED");\n'),
    sub('bits-yes-when-either-sticks', 'bits == 2 ? "BITS13_14_IN_READBACK=YES"', 'bits >= 1 ? "BITS13_14_IN_READBACK=YES"'),
    sub('bits-from-nothing', 'unsigned bits = (unsigned)(readback_cnthctl >> 13 & 1) + (unsigned)(readback_cnthctl >> 14 & 1);', 'unsigned bits = 2;'),
    sub('does-not-check-the-iss', '(t->esr & ISS_MASK) == expected_iss(i) ? "ISS_OK=YES"', '1 ? "ISS_OK=YES"'),
    sub('does-not-check-the-class', '(t->esr >> 26 & 63) == EC_TRAPPED_SYSREG &&', '1 &&'),
    sub('expected-iss-has-no-rt', '((uint64_t)i << 5) |', '((uint64_t)0 << 5) |'),
    sub('expected-iss-op2-in-the-wrong-place', '((uint64_t)e[4] << 17)', '((uint64_t)e[4] << 16)'),
    sub('matches-traps-by-order-not-by-elr', 'if (e->trap[k].elr == at) return &e->trap[k];', 'if (k == i) return &e->trap[k];'),
    sub('names-a-reason-wrongly', '"NONE", "OK", "BUDGET"', '"NONE", "BUDGET"'),
    sub('prints-no-trap-records-of-an-end', 'k < TRAPS_MAX; k++) {\n        row(&line);\n        word(&line, "TRAP");', 'k < 0; k++) {\n        row(&line);\n        word(&line, "TRAP");'),
    sub('does-not-print-what-an-el1-vector-reported', '    if (e->reason == END_EL1_EXCEPTION) {\n', '    if (0) {\n'),
    sub('reports-an-end-as-ok', '    } else if (w.e.reason == END_HVC) {\n', '    } else if (1) {\n'),
    sub('prints-the-vbar-address-not-the-offset', 'w.readback[R_VBAR1] - a->payload_base, "SCTLR_EL1", "VBAR_EL1_OFFSET"', 'w.readback[R_VBAR1], "SCTLR_EL1", "VBAR_EL1_OFFSET"'),
    sub('says-restored-without-looking', '    if (!bad) {\n        say(&r->out, "RESTORED=YES");', '    if (1) {\n        say(&r->out, "RESTORED=YES");'),
    sub('does-not-compare-vbar-el2', '    for (unsigned i = 0; i < R_COUNT; i++) bad += w->restored[i] != r->saved[i];\n', '    for (unsigned i = 0; i < R_VBAR2; i++) bad += w->restored[i] != r->saved[i];\n'),
    drop('does-not-shout-that-it-could-not-restore', '    say(&r->out, "POWER_CYCLE_BEFORE_ANY_OTHER_PAYLOAD");\n'),
    sub('returns-0-when-it-could-not-restore', '    if (!report_restore(&r, &w)) return RET_NOT_RESTORED;\n    return w.held', '    report_restore(&r, &w);\n    return w.held'),
    sub('returns-0-when-the-excursion-did-not-end-well', 'return w.held && w.e.reason == END_HVC ? 0 : RET_NOT_OK;', 'return 0;'),
    sub('returns-2-when-it-did-not-restore', '#define RET_NOT_RESTORED 3u', '#define RET_NOT_RESTORED 2u'),
    # -- registers that must not be touched
    sub('reads-cntpoff-el2', '    current_el = SYSREG(CurrentEL);\n', '    current_el = SYSREG(CurrentEL);\n    (void)SYSREG(S3_4_C14_C0_6);\n'),
    sub('reads-cntvoff-el2', '    current_el = SYSREG(CurrentEL);\n', '    current_el = SYSREG(CurrentEL);\n    (void)SYSREG(S3_4_C14_C0_3);\n'),
]

# Edits of the assembly: (name, [(needle, replacement)]). Each must make asm_problems() of the driver say something. The needles are
# the lines of the C string as written in the source, backslash-n and all.
ASM_MUTANTS = [
    ('restore-swaps-spsr-and-elr', [('"    msr spsr_el2, x2\\n"\n    "    msr elr_el2, x3\\n"', '"    msr spsr_el2, x3\\n"\n    "    msr elr_el2, x2\\n"')]),
    ('save-swaps-spsr-and-elr', [('"    mrs x2, spsr_el2\\n"\n    "    mrs x3, elr_el2\\n"', '"    mrs x2, elr_el2\\n"\n    "    mrs x3, spsr_el2\\n"')]),
    ('isb-before-the-install-of-vbar-el2', [('"    msr vbar_el2, x2\\n"\n    "    isb\\n"\n    "    ldr x2, [x0, #" STR(E_MODE)',
                                           '"    isb\\n"\n    "    msr vbar_el2, x2\\n"\n    "    ldr x2, [x0, #" STR(E_MODE)')]),
    ('isb-before-the-put-back-of-vbar-el2', [('"    msr vbar_el2, x2\\n"\n    "    isb\\n"\n    "    ldp x2, x3',
                                             '"    isb\\n"\n    "    msr vbar_el2, x2\\n"\n    "    ldp x2, x3')]),
    ('no-isb-in-the-fatal-path', [('"    msr vbar_el2, x27\\n"\n    "    isb\\n"', '"    msr vbar_el2, x27\\n"')]),
    ('the-stub-registers-are-reported-as-zero', [('"    stp x0, x1, [x11, #" STR(E_X0) "]\\n"', '"    stp xzr, xzr, [x11, #" STR(E_X0) "]\\n"')]),
    ('the-first-two-stub-registers-are-swapped', [('"    stp x0, x1, [x11, #" STR(E_X0) "]\\n"', '"    stp x1, x0, [x11, #" STR(E_X0) "]\\n"')]),
    ('the-class-is-taken-with-a-shift', [('"    ubfx x13, x9, #26, #6\\n"', '"    lsr x13, x9, #26\\n"')]),
    ('the-end-returns-the-constant', [('    "    ldr x13, [x11, #" STR(E_CALLER_SPSR) "]\\n"\n    "    mov x14, #" STR(SPSR_KEPT_LOW) "\\n"\n'
                                       '    "    movk x14, #" STR(SPSR_KEPT_HIGH) ", lsl #16\\n"\n    "    and x13, x13, x14\\n"\n'
                                       '    "    mov x14, #" STR(SPSR_EL2H_MASKED) "\\n"\n    "    orr x13, x13, x14\\n"\n',
                                       '    "    mov x13, #" STR(SPSR_EL2H_MASKED) "\\n"\n')]),
    ('the-end-keeps-one-bit-too-few', [('"    movk x14, #" STR(SPSR_KEPT_HIGH) ", lsl #16\\n"', '"    movk x14, #0x1c0, lsl #16\\n"')]),
    ('the-probe-does-not-save-the-callers-spsr', [('    "    mrs x14, spsr_el2\\n"                        /* this entry saved the caller\'s PSTATE here; '
                                                   'the end of an excursion gives five bits back */\n    "    str x14, [x11, #" STR(E_CALLER_SPSR) "]\\n"\n', '')]),
]
