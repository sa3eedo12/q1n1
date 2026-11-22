/* SPDX-License-Identifier: MIT */
/* Payload "gpus1": stage S1 of the first-contact plan for the Adreno X1-85 of the Surface Pro 11 (the design, the evidence and what is unknown are in docs/SP11-GPU-S1-DESIGN.md;
 * the framework is docs/SP11-PAYLOAD-WTAB.md). It brings the CX power domain up from the state boot 30 found it in, checks the clocks that the domain's power is meant to bring up,
 * and returns the domain to the state it was found in before it ends.
 *
 * It is the first payload with a write table (docs/SP11-PAYLOAD-WTAB.md): it has no store to a device word anywhere in its code. The only device word that changes is the one row of its table
 * that says so, and only the runner stores it, one row at a time, after reading the word back against the row's `found` bits, with the read-back and the undo the row names. The code asks for
 * each row by a literal index, in table order, and ends the run on any answer but zero: the runner has by then undone what it did and printed why. The table has no window: what lies behind
 * the domain (CX_MISC, the GMU, the RSCC) is not read by this payload. Every word it reads is a literal address in the GCC or GPUCC window the table allows (the audit of
 * tools/sp11_payload_wtab_audit.py holds it to that).
 *
 * Three snapshots of eight words of the always-readable GCC and GPUCC blocks: BEFORE (after the checks of step 0 have proved the register path), ON (after every row) and AFTER (after the unwind).
 * The payload says whether AFTER is BEFORE: the claim "the domain is back as found" rests on that comparison and on the runner's own verified undo, not on the payload's say-so.
 *
 * `GPUS1_DRY` (payloads/gpus1d.c) builds the same code over the table with no write: the first run, which exercises the machinery on the unit and changes nothing. A table whose
 * name ends -DRAFT is a draft: the runner refuses it at open unless it was built to take one, and the payload stops after printing that it is one unless GPUS1_ALLOW_DRAFT is
 * defined, which only the host model of the draft does. */
#include "payload-wtab.h"
#ifdef GPUS1_DRY
#include "gpus1d-table.h"
#define ON_LABEL "DURING"                               /* the dry table never powers the domain */
#else
#include "gpus1-table.h"
#define ON_LABEL "ON"
#endif

#define PREFIX "PAYLOAD GPUS1 "
#define INLINE static inline __attribute__((always_inline))
#define OUT_OF_LINE static __attribute__((noinline))

/* Text is appended through these three bodies and never inlined: expanded in place, every constant string became straight-line byte stores and the payload was 30 KiB.
 * Their arguments are the line on the payload's stack and a literal, never the runner's arguments, which the audit allows no call to take. */
OUT_OF_LINE void text(struct pl_line *line, const char *s)
{
    pl_text(line, s);
}

OUT_OF_LINE void head(struct pl_line *line, const char *label)
{
    pl_begin(line);
    pl_text(line, PREFIX);
    pl_text(line, label);
}

OUT_OF_LINE void field_name(struct pl_line *line, const char *name)
{
    pl_text(line, " ");
    pl_text(line, name);
    pl_text(line, "=");
}

/* The table the payload opens: the constant of its own image. The host tests point this at a page-aligned copy they load as the image. */
#ifndef WTAB_TABLE_ADDRESS
#define WTAB_TABLE_ADDRESS ((const struct q1n1_wtab_header *)&WTAB_TABLE_SYMBOL)
#endif

/* The words of the snapshots: name and address. Offsets are from the pinned Linux sources named in the table's rows (GCC: gcc-x1e80100.c; GPUCC: gpucc-x1e80100.c). */
#define SNAP_LIST(X) \
    X(CFGA, 0x00171004u) X(MNOC, 0x00171010u) X(AXI, 0x0017115cu) X(GRF, 0x03d9931cu) X(HRF, 0x03d993f0u) X(CXGD, 0x03d99108u) X(CXST, 0x03d9953cu) X(AHB, 0x03d9911cu)
enum {
#define X(name, address) S_##name,
    SNAP_LIST(X)
#undef X
    S_COUNT
};
_Static_assert(S_COUNT <= 16, "the fault mask of a snapshot is 16 bits");

struct snap {
    uint32_t v[S_COUNT];
    uint32_t bad;                                       /* bit n: word n faulted and is not in `v` */
};

INLINE void snapshot(const struct q1n1_payload_args *a, struct snap *s)
{
    s->bad = 0;
#define X(name, address) \
    if (a->ops.load32((address), &s->v[S_##name])) { s->v[S_##name] = 0; s->bad |= 1u << S_##name; }
    SNAP_LIST(X)
#undef X
}

INLINE void put_word(const struct q1n1_payload_args *a, struct pl_line *line, const char *name, uint32_t value)
{
    field_name(line, name);
    pl_hex(a, line, value);
}

INLINE void put_snap_word(const struct q1n1_payload_args *a, struct pl_line *line, const struct snap *s, unsigned index, const char *name)
{
    if (s->bad & (1u << index)) {
        field_name(line, name);
        text(line, "FAULT");
    } else {
        put_word(a, line, name, s->v[index]);
    }
}

/* Three lines: GCC, GPUCC clock roots (the configuration words, which gpusnap prints as GRF and HRF) and the CX domain control, the CX status and the AHB branch. */
INLINE void print_snap(const struct q1n1_payload_args *a, const char *label, const struct snap *s)
{
    struct pl_line line;
    head(&line, label);
    put_snap_word(a, &line, s, S_CFGA, "CFGA");
    put_snap_word(a, &line, s, S_MNOC, "MNOC");
    put_snap_word(a, &line, s, S_AXI, "AXI");
    pl_emit(a, &line);
    head(&line, label);
    put_snap_word(a, &line, s, S_GRF, "GRF");
    put_snap_word(a, &line, s, S_HRF, "HRF");
    put_snap_word(a, &line, s, S_CXGD, "CXGD");
    pl_emit(a, &line);
    head(&line, label);
    put_snap_word(a, &line, s, S_CXST, "CXST");
    put_snap_word(a, &line, s, S_AHB, "AHB");
    pl_emit(a, &line);
}

INLINE void say(const struct q1n1_payload_args *a, const char *message)
{
    struct pl_line line;
    head(&line, message);
    pl_emit(a, &line);
}

#if WTAB_DRAFT && !defined(GPUS1_ALLOW_DRAFT)
/* The draft check the runner makes at open (the table's name ends -DRAFT), made here too from the name in the payload's own image. The name is read through a volatile so that it
 * is read at run time: a compiler that knew it was a draft would drop the code behind the refusal, and the binary the policy audits would no longer be the payload. */
OUT_OF_LINE int table_is_named_a_draft(void)
{
    const volatile char *name = ((const volatile struct q1n1_wtab_header *)WTAB_TABLE_ADDRESS)->name;
    unsigned n = 0;
    while (n < Q1N1_WTAB_NAME_BYTES && name[n]) n++;
    return n >= 6 && name[n - 6] == '-' && name[n - 5] == 'D' && name[n - 4] == 'R' && name[n - 3] == 'A' && name[n - 2] == 'F' && name[n - 1] == 'T';
}
#endif

uint64_t payload_entry(const struct q1n1_payload_args *a)
{
    struct snap before, on, after;
    if (!pl_args_ok(a)) return Q1N1_PAYLOAD_RET_BAD_ARGS;
    if (!a->ops.load32 || !a->ops.counter) return Q1N1_PAYLOAD_RET_BAD_ARGS;
    const struct q1n1_payload_wtab_ops *wtab = pl_wtab_ops(a);
    if (!wtab) {
        say(a, "REFUSED=NO_WTAB_RUNNER");
        return 2;
    }
    if (wtab->open(WTAB_TABLE_ADDRESS)) {
        say(a, "REFUSED=OPEN");
        return 3;
    }
#if WTAB_DRAFT
    say(a, "TABLE IS A DRAFT");
#ifndef GPUS1_ALLOW_DRAFT
    if (table_is_named_a_draft()) return 5;
#endif
#endif

    /* Step 0: the register path and the clock roots, checked and never written. */
    if (wtab->row(WROW_GCCAHB) || wtab->row(WROW_GMURCG) || wtab->row(WROW_HUBRCG)) {
        say(a, "STOPPED=STEP0");
        return 1;
    }
    snapshot(a, &before);
    print_snap(a, "BEFORE", &before);

    /* Step 1: the one write of the table, then the checks of the clocks that the domain's power is meant to bring up. */
    if (wtab->row(WROW_CXGDSC)) {
        say(a, "STOPPED=STEP1");
        return 1;
    }
#ifndef GPUS1_DRY
    if (wtab->row(WROW_AHB) || wtab->row(WROW_CXGMU) || wtab->row(WROW_CXO) || wtab->row(WROW_AXI) || wtab->row(WROW_MEMNOC) || wtab->row(WROW_HUBCX) ||
        wtab->row(WROW_DEMET)) {
        say(a, "STOPPED=STEP2");
        return 1;
    }
#endif
    snapshot(a, &on);
    print_snap(a, ON_LABEL, &on);

    if (wtab->unwind()) {
        say(a, "UNDO FAILED");
        return 1;
    }
    snapshot(a, &after);
    uint32_t changed = 0;
    for (unsigned i = 0; i < S_COUNT; i++) changed |= (before.v[i] != after.v[i]) ? 1u << i : 0;
    struct pl_line line;
    head(&line, "STATE");
    if (before.bad | after.bad) {
        text(&line, " RESTORED=UNKNOWN BAD=");
        pl_hex(a, &line, before.bad | after.bad);
        pl_emit(a, &line);
        say(a, "END");
        return 4;
    }
    if (!changed) {
        text(&line, " RESTORED=YES WORDS=");
        pl_hex(a, &line, S_COUNT);
        pl_emit(a, &line);
        say(a, "END");
        return 0;
    }
    text(&line, " RESTORED=NO CHANGED=");
    pl_hex(a, &line, changed);
    pl_emit(a, &line);
    print_snap(a, "AFTER", &after);
    say(a, "END");
    return 4;
}
