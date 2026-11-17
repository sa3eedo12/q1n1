/* SPDX-License-Identifier: MIT */
/* Payload "xhci", the SMMU and the DWC3 error address (docs/SP11-PAYLOAD-XHCI.md; xhci-priv.h lists the parts): reads only. Which context
 * bank the controller's stream translates into, and the fault registers that say whether a DMA of the controller was refused: sGFSR, the
 * context bank's FSR, and the address the DWC3 latched when its bus master got an error. This file contains no store. */
#include "xhci-priv.h"

/* ---- The SMMU and the DWC3 error address: reads only ------------------------------------------------------------------------------- */

/* ID0 and ID1, then a scan of the stream match registers for this controller's stream, then that entry's S2CR: which context bank the stream
 * translates into. Nothing else. A stream that matches nothing is printed, not refused: it is an answer. */
int smmu_scan(struct ctx *c, struct smmu *s)
{
    uint32_t id0 = 0, id1 = 0, smr = 0, s2cr = 0;
    s->ok = s->matched = s->have_cb = 0;
    if (!windows[WIN_SMMU].base) return 0;
    if (rd32(c, WIN_SMMU, SMMU_ID0, &id0, "SMMU_ID0") || rd32(c, WIN_SMMU, SMMU_ID1, &id1, "SMMU_ID1")) return 1;
    if (!id0 || id0 == 0xffffffffu || !id1 || id1 == 0xffffffffu) return 1;
    s->numcb = id1 & 0xff;
    s->pagesize = id1 >> 31 ? 0x10000u : 0x1000u;
    s->numpage = 1u << ((id1 >> 28 & 7) + 1);
    for (uint32_t n = 0; n < (id0 & 0xff) && n < SMR_SCANNED_MAX; n++) {
        if (rd32(c, WIN_SMMU, SMMU_SMR(n), &smr, "SMMU_SMR")) return 1;
        if (!(smr >> 31) || ((XHCI_S1_STREAM_ID ^ smr) & 0x7fffu & ~(smr >> 16 & 0x7fffu))) continue;
        if (rd32(c, WIN_SMMU, SMMU_S2CR(n), &s2cr, "SMMU_S2CR")) return 1;
        s->matched = n + 1;
        s->type = s2cr >> 16 & 3;
        s->cb = s2cr & 0xff;
        s->have_cb = s->type == 0 && s->cb < s->numcb;
        break;
    }
    s->ok = 1;
    return 0;
}

/* sGFSR (and sGFAR, sGFSYNR0 when it is not zero), the stream's context bank FSR (and FAR, FSYNR0 when it is not zero), and the DWC3's latched
 * bus error address. Non-zero if any read failed. */
int fault_regs(struct ctx *c, struct faults *f)
{
    uint32_t gsts = 0, lo = 0, hi = 0;
    uint64_t cb = (uint64_t)(c->smmu.numpage + c->smmu.cb) * c->smmu.pagesize;
    f->gfsr = f->gfsynr0 = f->fsr = f->fsynr0 = f->berr_valid = 0;
    f->gfar = f->far = f->berr = 0;
    if (c->smmu.ok) {
        if (rd32(c, WIN_SMMU, SMMU_GFSR, &f->gfsr, "SMMU_GFSR")) return 1;
        if (f->gfsr && (rd64(c, WIN_SMMU, SMMU_GFAR, &f->gfar, "SMMU_GFAR") || rd32(c, WIN_SMMU, SMMU_GFSYNR0, &f->gfsynr0, "SMMU_GFSYNR0"))) return 1;
        if (c->smmu.have_cb) {
            if (cb + CB_FSYNR0 + 4 > windows[WIN_SMMU].size || rd32(c, WIN_SMMU, cb + CB_FSR, &f->fsr, "CB_FSR")) return 1;
            if (f->fsr && (rd64(c, WIN_SMMU, cb + CB_FAR, &f->far, "CB_FAR") || rd32(c, WIN_SMMU, cb + CB_FSYNR0, &f->fsynr0, "CB_FSYNR0"))) return 1;
        }
    }
    if (c->x[TARGET].dwc3_id) {
        if (rd32(c, TARGET, DWC3_GSTS, &gsts, "GSTS") || rd32(c, TARGET, DWC3_GBUSERRADDR0, &lo, "GBUSERRADDR0") ||
            rd32(c, TARGET, DWC3_GBUSERRADDR1, &hi, "GBUSERRADDR1"))
            return 1;
        f->berr = (uint64_t)hi << 32 | lo;
        f->berr_valid = gsts >> 4 & 1u;
    }
    return 0;
}

int faults_same(const struct faults *a, const struct faults *b)
{
    return a->gfsr == b->gfsr && a->gfsynr0 == b->gfsynr0 && a->gfar == b->gfar && a->fsr == b->fsr && a->far == b->far && a->fsynr0 == b->fsynr0 &&
           a->berr == b->berr && a->berr_valid == b->berr_valid;
}

/* GFSR= FSR= FAR= FSYNR0= BERR=: the fields that carry a value. `attempt` is the number of the attempt (R<k>, as on its own line) that the registers were
 * read after, and 0 for the reading before any attempt, which has no R field: with it, a line of the page says which attempt it is about. The global and the
 * context bank halves are two lines when the global one carries a value: together they would not fit in a line. */
unsigned faults_lines(const struct ctx *c, const struct faults *f)
{
    return f->gfsr && (c->smmu.have_cb || f->berr_valid || f->berr) ? 2u : 1u;
}

void say_faults(struct ctx *c, const char *head, unsigned attempt, const struct faults *f)
{
    struct pl_line line;
    pl_begin(&line);
    pl_text(&line, PREFIX);
    line_to(c, &line, "%s", head);
    if (attempt) line_to(c, &line, " R%d", U(attempt));
    line_to(c, &line, " GFSR=%x", U(f->gfsr));
    if (f->gfsr) {
        line_to(c, &line, " GFAR=%x GFSYNR0=%x", f->gfar, U(f->gfsynr0));
        if (faults_lines(c, f) == 2) {
            emit(c, &line);
            pl_begin(&line);
            pl_text(&line, PREFIX);
            line_to(c, &line, "%s", head);
            if (attempt) line_to(c, &line, " R%d", U(attempt));
        }
    }
    if (c->smmu.have_cb) line_to(c, &line, " FSR=%x", U(f->fsr));
    if (c->smmu.have_cb && f->fsr) line_to(c, &line, " FAR=%x FSYNR0=%x", f->far, U(f->fsynr0));
    if (f->berr_valid || f->berr) line_to(c, &line, " BERR=%x", f->berr);
    emit(c, &line);
}
