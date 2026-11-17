/* SPDX-License-Identifier: MIT */
/* Payload "xhci" (stage S1 of the Surface Pro 11 stick study, authorisation point A1; docs/SP11-PAYLOAD-XHCI.md): the first writes to an xHC
 * at EL2, to learn whether the xHC can DMA into RAM of ours. One controller per build (XHCI_S1_CONTROLLER 0: usb_1_ss0, 1: usb_1_ss1; the
 * Makefile builds xhci0.bin and xhci1.bin from this file and the parts xhci-priv.h lists). EXPERIMENTAL; hardware NOT RUN.
 *
 * (1) Reads only: the controller's identity, state and ports, the other controller's ports, the SMMU stream and fault registers (the
 * BEFORE values); it refuses by name, with nothing written, on anything unexpected, among it a doorbell or interrupter offset that is not
 * aligned or that would put a store of the record at 0xc100 or above (the DWC3 global registers). (2) A read-only plug watch of 30 s over
 * both controllers' PORTSC. (3) Up to four attempts, one per arena in a fixed order, each a complete reset, program, run, No Op and halt,
 * each write group of each attempt after its own NEXT line and eight seconds; the first that gets its Command Completion Event ends the
 * run, and so does a bad completion (a wrong code, pointer or cycle, or a REDIRECT: the controller says it posted an event that is not in the
 * ring), while a silence or a bus error moves on to the next arena. (4) The controller halted but still programmed (its DCBAAP, CRCR, ERSTBA
 * and ERDP keep pointing into the arena, which is zero again: no store beyond the thirteen undoes it), a VERDICT line, return 0.
 *
 * It writes only USBCMD (RS and HCRST), CONFIG, DCBAAP, CRCR, interrupter 0 IMAN (IP, write 1 to clear), ERSTSZ, ERSTBA, ERDP, doorbell 0
 * and the words of one arena (the authorisation record lists exactly these; tools/test-q1n1-sp11-payload-xhci.py holds the source to
 * them). Every store is made by mmio_store32 or ram_store32 (xhci-io.c) behind a gate (xhc_store, ram_put) that knows the registers and the
 * arena, and a write group is open only after its NEXT line and eight seconds on the runner's counter.
 *
 * The sequence is xHCI 1.2 section 4.2 and q1n1's platform/uefi/xhci.c: halt, HCRST, wait for HCRST and CNR to clear, CONFIG, DCBAAP, CRCR,
 * ERSTSZ, ERDP, ERSTBA (last: it makes the xHC load the segment table), then R/S; the scratchpad array goes in DCBAA[0] when HCSPARAMS2 asks
 * for buffers (section 4.20). A 64-bit register is two 32-bit stores, low first. Whether the xHC is coherent with the CPU caches is UNKNOWN,
 * so the payload cleans (DC CVAC, DSB SY) what the CPU wrote for the xHC and cleans and invalidates (DC CIVAC) the event TRB it reads; a
 * step of 16 bytes reaches every line whatever the line size is. */
#include "xhci-priv.h"

/* ---- Pre-flight ---------------------------------------------------------------------------------------------------------------------- */

/* VERDICT REFUSED=<name> and one value: nothing was written. The register that failed to read is named when there is no value. */
OUT_OF_LINE void refuse(struct ctx *c, const char *name, const char *key, uint64_t value)
{
    c->closing = 1;
    if (key) say(c, "VERDICT REFUSED=%s %s=%x", name, key, value);
    else if (c->failed) say(c, "VERDICT REFUSED=%s AT=%s", name, c->failed);
    else say(c, "VERDICT REFUSED=%s", name);
}

/* The identity and state of controller `win`. `full` is the target: the DWC3 id, the capability words, the offsets (all inside the window and
 * past the operational registers) and the operational registers. The other controller is only checked to look like an xHC with ports, for
 * the plug watch. Returns a refusal name, or 0; `*detail` is the value that was wrong. */
OUT_OF_LINE const char *read_xhc(struct ctx *c, unsigned win, int full, uint64_t *detail)
{
    struct xhc *x = &c->x[win];
    uint64_t op_end;
    *detail = 0;
    if (rd32(c, win, CAP_CAP0, &x->cap0, "CAP0") || rd32(c, win, CAP_HCSPARAMS1, &x->hcs1, "HCSPARAMS1")) return "READ_FAULT";
    if (!x->cap0 || x->cap0 == 0xffffffffu) {
        *detail = x->cap0;
        return "NOT_XHCI";
    }
    x->caplen = x->cap0 & 0xff;
    x->slots = x->hcs1 & 0xff;
    x->intrs = x->hcs1 >> 8 & 0x7ff;
    x->ports = x->hcs1 >> 24;
    x->op = x->caplen;
    if (!full) return x->caplen >= 0x1c && !(x->caplen & 3) && x->ports ? 0 : "NOT_XHCI";
    if (x->caplen != XHCI_S1_CAPLENGTH) {
        *detail = x->caplen;
        return "CAPLENGTH";
    }
    if ((x->cap0 >> 16) != XHCI_S1_HCIVERSION) {
        *detail = x->cap0 >> 16;
        return "HCIVERSION";
    }
    if (XHCI_S1_DWC3_ID) {
        if (rd32(c, win, DWC3_GSNPSID, &x->dwc3_id, "GSNPSID")) return "READ_FAULT";
        if (x->dwc3_id != XHCI_S1_DWC3_ID) {
            *detail = x->dwc3_id;
            return "DWC3_ID";
        }
    }
    if (rd32(c, win, CAP_HCSPARAMS2, &x->hcs2, "HCSPARAMS2") || rd32(c, win, CAP_HCCPARAMS1, &x->hcc1, "HCCPARAMS1") ||
        rd32(c, win, CAP_DBOFF, &x->dboff, "DBOFF") || rd32(c, win, CAP_RTSOFF, &x->rtsoff, "RTSOFF"))
        return "READ_FAULT";
    x->scratch = (x->hcs2 >> 21 & 0x1f) << 5 | x->hcs2 >> 27;
    x->ac64 = x->hcc1 & 1u;
    x->csz = x->hcc1 >> 2 & 1u ? 64u : 32u;
    x->db = x->dboff;                   /* DBOFF and RTSOFF are used as they are printed: a value with reserved bits set is refused below, never masked */
    x->ir0 = (uint64_t)x->rtsoff + IR0;
    if (!x->slots || !x->intrs || !x->ports || x->slots > SLOTS_FIT) return "NOT_XHCI";
    op_end = x->op + 0x400u + 0x10u * x->ports;
    if ((x->dboff & 3u) || (x->rtsoff & 0x1fu)) {       /* DBOFF is dword aligned and RTSOFF 32-byte aligned: their low bits are reserved */
        *detail = x->dboff & 3u ? x->dboff : x->rtsoff;
        return "OFFSET";
    }
    if (op_end > windows[win].size || x->db < op_end || x->db + 4 > windows[win].size || x->ir0 < op_end || x->ir0 + 0x20 > windows[win].size) {
        *detail = x->db;
        return "OFFSET";
    }
    /* Every register the payload may store to lies below the DWC3 global registers: DBOFF and RTSOFF are the controller's word, and a doorbell or an
     * interrupter placed at 0xc100 or above would make a store of the record a store to the DWC3 core. */
    for (unsigned reg = 0; reg < SR_COUNT; reg++) {
        if (reg_offset(x, reg) > store_limit() - 4u) {
            *detail = reg_offset(x, reg);
            return "OFFSET";
        }
    }
    if (rd32(c, win, x->op + OP_USBCMD, &x->cmd, "USBCMD") || rd32(c, win, x->op + OP_USBSTS, &x->sts, "USBSTS") ||
        rd64(c, win, x->op + OP_CRCR, &x->crcr, "CRCR") || rd64(c, win, x->op + OP_DCBAAP, &x->dcbaap, "DCBAAP") ||
        rd32(c, win, x->op + OP_CONFIG, &x->cfg, "CONFIG") || rd32(c, win, x->op + OP_PAGESIZE, &x->pagesize, "PAGESIZE"))
        return "READ_FAULT";
    for (uint32_t p = 0; p < PORTS_WATCHED && p < x->ports; p++)
        if (rd32(c, win, x->op + OP_PORTSC(p + 1), &x->portsc[p], "PORTSC")) return "READ_FAULT";
    return 0;
}

/* The pre-flight of the target, after its words were read and printed: a refusal name, or 0. */
OUT_OF_LINE const char *check_state(struct ctx *c, uint64_t *detail, const char **key)
{
    struct xhc *x = &c->x[TARGET];
    uint32_t sts = x->sts;
    *key = "STS";
    *detail = sts;
    if (sts == 0xffffffffu) return "NOT_XHCI";
    if (sts & STS_HCE) return "HCE";
    if (sts & STS_HSE) return "HSE";
    if (sts & STS_CNR) {
        if (poll_xhc(c, x->op + OP_USBSTS, "USBSTS", STS_CNR, 0, T_CNR_US, &sts)) {
            *detail = sts;
            return "CNR";
        }
        x->sts = sts;
    }
    if ((x->cmd & CMD_RS) || !(x->sts & STS_HCH)) {
        *key = "CMD";
        *detail = x->cmd;
        return "RUNNING";
    }
    if (!(x->pagesize & 1u)) {
        *key = "VALUE";
        *detail = x->pagesize;
        return "PAGESIZE";
    }
    return 0;
}

/* ---- The entry ------------------------------------------------------------------------------------------------------------------------ */

OUT_OF_LINE void say_attempt(struct ctx *c, unsigned k, const struct result *r, const char *smmu)
{
    struct pl_line line, tail;
    pl_begin(&line);
    pl_text(&line, PREFIX);
    line_to(c, &line, "R%d ARENA=%d %s STAGE=%s", U(k), U(c->arena.id), verdict_name[r->verdict], stage_name[r->stage]);
    if (r->why) line_to(c, &line, " WHY=%s", why_name[r->why]);
    if (r->cc) line_to(c, &line, " CC=%d", U(r->cc));
    pl_begin(&tail);
    line_to(c, &tail, " STS=%S EV=%d", U(r->sts), U(r->events));
    if (r->psc) line_to(c, &tail, " PSC=%d", U(r->psc));
    line_to(c, &tail, " SMMU=%s", smmu);
    if (line.len + tail.len >= Q1N1_PAYLOAD_LINE_MAX) {
        emit(c, &line);
        pl_begin(&line);
        pl_text(&line, PREFIX);
        line_to(c, &line, "R%d", U(k));
    }
    pl_text(&line, tail.buf);
    emit(c, &line);
}

OUT_OF_LINE void say_preflight(struct ctx *c)
{
    const struct xhc *x = &c->x[TARGET];
    const char *name = TARGET ? "U1" : "U0";
    if (x->dwc3_id)
        say(c, "%s ID=%x CAPL=%x VER=%x HCS1=%x HCS2=%x HCC1=%x", name, U(x->dwc3_id), U(x->caplen), U(x->cap0 >> 16), U(x->hcs1), U(x->hcs2), U(x->hcc1));
    else
        say(c, "%s CAPL=%x VER=%x HCS1=%x HCS2=%x HCC1=%x", name, U(x->caplen), U(x->cap0 >> 16), U(x->hcs1), U(x->hcs2), U(x->hcc1));
    say(c, "%s SCRATCH=%d PAGESZ=%x AC64=%d CSZ=%d DBOFF=%x RTSOFF=%x", name, U(x->scratch), U(x->pagesize), U(x->ac64), U(x->csz), U(x->dboff),
        U(x->rtsoff));
    say(c, "%s CMD=%x STS=%S CRCR=%x DCBAAP=%x CFG=%x", name, U(x->cmd), U(x->sts), x->crcr, x->dcbaap, U(x->cfg));
}

uint64_t payload_entry(const struct q1n1_payload_args *a);
uint64_t payload_entry(const struct q1n1_payload_args *a)
{
    struct ctx c;
    struct arena arenas[ARENAS + 1];
    struct result r;
    struct faults now;
    const char *bad, *key = 0;
    uint64_t cntfrq, detail = 0;
    uint32_t pages, attempts = 0, eligible = 0, reason[ARENAS + 1];
    unsigned k;

    if (!pl_args_ok(a)) return Q1N1_PAYLOAD_RET_BAD_ARGS;
    for (size_t i = 0; i < sizeof c; i++) ((volatile uint8_t *)&c)[i] = 0;
    c.a = a;
    if ((SYSREG(CurrentEL) >> 2 & 3) != 2) {
        say(&c, "SKIPPED_NOT_AT_EL2");
        return 0;
    }
    if (!a->ops.counter || !a->ops.load32) {
        refuse(&c, a->ops.counter ? "NO_LOAD32" : "NO_COUNTER", 0, 0);
        return 0;
    }
    cntfrq = SYSREG(cntfrq_el0);
    c.hz = cntfrq >= COUNTER_HZ_MIN && cntfrq <= COUNTER_HZ_MAX ? cntfrq : COUNTER_HZ_DEFAULT;
    if (!delay_ticks(&c, c.hz / 1000u)) {
        refuse(&c, "COUNTER_STUCK", 0, 0);
        return 0;
    }
    map_init(&c);

    /* Pre-flight: reads only. The words are printed before a refusal, so that the page shows what was refused. */
    bad = read_xhc(&c, TARGET, 1, &detail);
    if (bad) {
        refuse(&c, bad, detail ? "VALUE" : 0, detail);
        return 0;
    }
    say_preflight(&c);
    bad = check_state(&c, &detail, &key);
    if (bad) {
        refuse(&c, bad, key, detail);
        return 0;
    }
    if (read_xhc(&c, OTHER, 0, &detail) || rd32(&c, OTHER, c.x[OTHER].op + OP_PORTSC(1), &c.x[OTHER].portsc[0], "PORTSC") ||
        (c.x[OTHER].ports > 1 && rd32(&c, OTHER, c.x[OTHER].op + OP_PORTSC(2), &c.x[OTHER].portsc[1], "PORTSC")))
        c.x[OTHER].ports = 0;
    c.failed = 0;
    if (smmu_scan(&c, &c.smmu) || fault_regs(&c, &c.before)) {
        refuse(&c, "SMMU_UNREADABLE", 0, 0);
        return 0;
    }
    if (c.smmu.ok) {
        if (c.smmu.matched)
            say(&c, "SMMU STREAM=%x SMR=%d %s CB=%d NCB=%x", U(XHCI_S1_STREAM_ID), U(c.smmu.matched - 1u),
                c.smmu.type == 0 ? "TRANS" : c.smmu.type == 1 ? "BYPASS" : "FAULT", U(c.smmu.cb), U(c.smmu.numcb));
        else
            say(&c, "SMMU STREAM=%x MATCH=NONE NCB=%x", U(XHCI_S1_STREAM_ID), U(c.smmu.numcb));
    }
    say_faults(&c, "SMMU0", 0, &c.before);

    /* The arenas that can be tried, decided before the watch so that a run with none ends before anything is written. */
    pages = 1u + (c.x[TARGET].scratch > SCRATCH_MAX ? SCRATCH_MAX + 1u : c.x[TARGET].scratch);
    for (k = 1; k <= ARENAS; k++) {
        reason[k] = (uint32_t)arena_for(&c, k, pages, &arenas[k]);
        eligible += reason[k] == AR_OK;
    }
    {
        struct pl_line line;
        pl_begin(&line);
        pl_text(&line, PREFIX "ARENAS");
        for (k = 1; k <= ARENAS; k++) {
            if (reason[k] == AR_NOT_APPLICABLE) continue;
            pl_text(&line, " ");
            put_dec(&line, k);
            pl_text(&line, "=");
            pl_text(&line, arena_why[reason[k]]);
        }
        emit(&c, &line);
    }
    if (c.x[TARGET].scratch > SCRATCH_MAX || !eligible) {
        refuse(&c, c.x[TARGET].scratch > SCRATCH_MAX ? "SCRATCHPADS" : "NO_ARENA", c.x[TARGET].scratch > SCRATCH_MAX ? "VALUE" : 0, c.x[TARGET].scratch);
        return 0;
    }
    /* The page has LINE_CAP lines. Every eligible attempt keeps ATTEMPT_LINES_MIN of them, and the watch's own lines, the SMMU reports of earlier attempts and the
     * lines of the attempts that cannot run (a bad completion or a refused store ends the run) may not take them: the watch keeps those of every eligible attempt, its
     * last line and the closing two; an SMMU report is printed only if the attempts still to come keep theirs. An attempt that does not fit is not started. */
    watch_run(&c, eligible * ATTEMPT_LINES_MIN + 1u + CLOSING_LINES);

    /* The attempts, in the order of the arenas, until one completes its No Op or one cannot be recovered from. */
    r.verdict = V_NONE;
    r.fatal = 0;
    r.halted = 1;
    for (k = 1; k <= ARENAS && !r.fatal && r.verdict != V_OK; k++) {
        const char *smmu = "SAME";
        if (reason[k] != AR_OK) continue;
        if (attempts && !room(&c, ATTEMPT_LINES_MIN + CLOSING_LINES - 1u)) {
            c.cuts++;
            break;
        }
        attempt(&c, &arenas[k], &r);
        attempts++;
        if (fault_regs(&c, &now)) {
            smmu = "UNREAD";
        } else {
            if (!faults_same(&c.before, &now)) smmu = "CHANGED";
            c.before = now;                 /* the next attempt is compared with this one's end, not with the start of the run */
        }
        say_attempt(&c, attempts, &r, smmu);
        if (smmu[0] == 'C') {
            unsigned later = 0;
            for (unsigned j = k + 1; j <= ARENAS && !r.fatal && r.verdict != V_OK; j++) later += reason[j] == AR_OK;
            if (room(&c, faults_lines(&c, &now) - 1u + later * ATTEMPT_LINES_MIN + CLOSING_LINES)) say_faults(&c, "SMMU1", attempts, &now);
            else c.cuts++;
        }
        if (c.store_refusal || c.ram_refusal) break;
    }
    c.closing = 1;
    if (r.verdict == V_OK) say(&c, "VERDICT NOOP_OK ARENA=%d", U(c.arena.id));
    else if (r.why) say(&c, "VERDICT %s STAGE=%s WHY=%s", verdict_name[r.verdict], stage_name[r.stage], why_name[r.why]);
    else say(&c, "VERDICT %s STAGE=%s", verdict_name[r.verdict], stage_name[r.stage]);
    say(&c, "END HALTED=%s WRITES=%d LOADS=%d%s%s", r.halted == 1 ? "YES" : r.halted == 0 ? "NO" : "UNKNOWN", U(c.stores), U(c.loads),
        c.store_refusal || c.ram_refusal ? " STORE_REFUSED" : "", c.cuts ? " LINES_CUT" : "");
    return 0;
}
