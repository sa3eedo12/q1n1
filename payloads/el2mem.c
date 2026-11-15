/* SPDX-License-Identifier: MIT */
/* Payload "el2mem": what EL2's own stage-1 map reaches, asked of the MMU, and the registers a monitor reads when it starts
 * (docs/SP11-PAYLOAD-EL2MEM.md). READ ONLY: MRS, one AT S1E2R, ISB, plain loads of its own stack, of the arguments and of the final
 * memory map, and the runner's guarded load32. No MSR, no DC, no IC, no TLBI, no SMC, no store but to its own stack (the tests
 * disassemble the binary and prove it, tools/sp11_payload_memcheck.py). EXPERIMENTAL; hardware NOT RUN.
 *
 * Why. The monitor port (Snapintosh docs/SP11-MONITOR-PORT.md, work item 2) runs on whatever EL2 stage-1 map UEFI and slbounce left,
 * and nothing says that map reaches the 30 GiB bank (U1) or with which attributes. AT S1E2R answers that without touching the memory
 * at the address: the MMU walks EL2's tables and reports in PAR_EL1. It also reads the registers the monitor reads at launch and
 * nothing showed (U5): ID_AA64DFR1_EL1, ID_AA64ISAR2_EL1, ID_AA64MMFR1_EL1 (its PAN field was never read cleanly), OSLSR_EL1,
 * MDCR_EL2 and ICC_SRE_EL2.
 *
 * Order, so that a hang names itself. CurrentEL first: not at EL2 it prints one line and does nothing else (AT S1E2R and MDCR_EL2 are
 * UNDEFINED below EL2). Then everything that cannot trap: the map summary, the mapping scan, the four guarded loads, the ID
 * registers. Last the reads that MAY trap to EL3 (MDSCR_EL1 and OSLSR_EL1 through MDCR_EL3, ICC_SRE_EL2 through ICC_SRE_EL3.Enable;
 * INFERRED from the architecture, none of them was ever tried on this unit), each behind a NEXT line and eight seconds of counter, so
 * that a reset leaves a photographed page that names the register. CNTPOFF_EL2 and CNTVOFF_EL2 are never read (a read of
 * CNTPOFF_EL2 never returned on this unit).
 *
 * The scan. Every Conventional (type 7) extent of the final map, merged and in address order, is asked about at its first page, every
 * 2 MiB boundary inside it and its last page; a hole narrower than the stride that is not at an edge is missed. The answers fold into
 * keys (attribute, shareability, NS, identity or a fault code) and runs; a run of the commonest key is not listed, any other run is.
 * The 30 GiB bank 0x880000000..0x1000000000 gets its own line whatever the map merges. As controls the first descriptor of each type
 * 1 to 6, the payload's own first page and its stack: memory that is certainly in use must read as mapped, or the method is doubtful.
 * A load (ops.load32) is made only at the first and last word of the bank's and of the largest low extent's conventional memory, and
 * only if an AT of that very page said mapped. Nothing is made from a descriptor's address but AT and those four loads.
 *
 * Reading discipline, checked in the binary: the map is read in place through the pointer in the arguments, reloaded for every
 * descriptor and never kept anywhere else; every other read of RAM or a device is the guarded op. A map that cannot be read safely
 * (a stride below 40 or not a multiple of 8, a size that is not whole descriptors, a buffer outside the 48-bit space) is refused
 * before one byte of it is read; a descriptor that is unaligned, empty or beyond 48 bits is counted and ignored.
 *
 * Lines: at most 26 (the page is shared: the runner's own lines and the other payloads' take the rest of its 60), each at most 100
 * characters. The last four are reserved for the three NEXT lines and the DONE line; a dropped line is counted as SUPPRESSED. */
#define PL_PAGE_PREFIX "PAYLOAD EL2MEM "
#ifndef PL_PAGE_LINES
#define PL_PAGE_LINES 26u       /* a test may build a smaller page to see the budget work; the shipped binary never does */
#endif
#include "payload-page.h"
#include "payload-mmu.h"

#ifdef Q1N1_PAYLOAD_HOST_TEST
uint64_t pl_host_sysreg(const char *name);
#define SYSREG(name) pl_host_sysreg(#name)
#else
#define SYSREG(name) ({ uint64_t value_; __asm__ volatile("mrs %0, " #name : "=r"(value_)); value_; })
#endif

#define OUT_OF_LINE static __attribute__((noinline))

#define ESSENTIAL_LINES 4u              /* the three NEXT lines and the DONE line */
#define BLOCK_2M (UINT64_C(2) << 20)
#define MIB (UINT64_C(1) << 20)
#define LOW_LIMIT (UINT64_C(1) << 32)
/* The 30 GiB bank of boot 6's map (OBSERVED): its own line, and the candidate region of the monitor. */
#define BANK_BASE UINT64_C(0x880000000)
#define BANK_END UINT64_C(0x1000000000)

#define EXTENTS_MAX 64u
#define KEYS_MAX 3u
#define RUNS_MAX 12u
#define OUTLIERS_MAX 5u

#define WAIT_BEFORE_READ_S 8u
#define COUNTER_HZ_DEFAULT 19200000u
#define COUNTER_HZ_MIN 1000000u
#define COUNTER_HZ_MAX 1000000000u
/* A running counter changes within a few dozen reads at any plausible frequency: this many equal reads in a row mean it does not
 * run and no wait can be made. */
#define COUNTER_STUCK_READS 2000000u

/* ---- Entries of the open line that show a result of the MMU ------------------------------------------------------------------ */

OUT_OF_LINE void add_walk(const struct q1n1_payload_args *a, struct pl_page *p, const char *key, const struct pl_walk *w)
{
    struct pl_line item;
    pl_begin(&item);
    pl_text(&item, key);
    pl_text(&item, "=");
    pl_put_walk(a, &item, w);
    pl_page_add(a, p, item.buf);
}

/* "T3=WB.IS": a key made of a letter and a number, so that no pointer to a stack-made string is needed. */
OUT_OF_LINE void add_walk_numbered(const struct q1n1_payload_args *a, struct pl_page *p, const char *letter, unsigned number,
                                   const struct pl_walk *w)
{
    struct pl_line item;
    pl_begin(&item);
    pl_text(&item, letter);
    pl_dec(&item, number);
    pl_text(&item, "=");
    pl_put_walk(a, &item, w);
    pl_page_add(a, p, item.buf);
}

OUT_OF_LINE void add_absent_numbered(const struct q1n1_payload_args *a, struct pl_page *p, const char *letter, unsigned number)
{
    struct pl_line item;
    pl_begin(&item);
    pl_text(&item, letter);
    pl_dec(&item, number);
    pl_text(&item, "=ABSENT");
    pl_page_add(a, p, item.buf);
}

/* ---- The final memory map (payload-mmu.h reads it in place) ------------------------------------------------------------------ */

/* 1 when the map may be read; otherwise 0 after a MAP_REFUSED line that names why. Reads nothing of the map. */
OUT_OF_LINE int map_usable(const struct q1n1_payload_args *a, struct pl_page *p)
{
    struct pl_line reason;
    unsigned code = pl_map_check(a);
    if (code == PL_MAP_OK) return 1;
    pl_begin(&reason);
    pl_put_map_refusal(&reason, code);
    pl_say(a, p, "MAP_REFUSED", reason.buf, 0);
    return 0;
}

struct extent {
    uint64_t start, end;
};

/* The merged run of Conventional descriptors that begins lowest at or above `from` (a descriptor that straddles `from` is cut there),
 * or 0 when there is none. The map need not be sorted: this asks for the lowest start again after each extent. */
OUT_OF_LINE int extent_next(const struct q1n1_payload_args *a, uint64_t count, uint64_t from, struct extent *e)
{
    struct pl_desc d;
    uint64_t start = UINT64_MAX, end = 0;
    for (uint64_t i = 0; i < count; i++) {
        if (!pl_desc_read(a, i, &d) || d.type != PL_EFI_CONVENTIONAL || d.end <= from) continue;
        uint64_t s = d.start < from ? from : d.start;
        if (s < start || (s == start && d.end > end)) {
            start = s;
            end = d.end;
        }
    }
    if (start == UINT64_MAX) return 0;
    for (int grew = 1; grew;) {
        grew = 0;
        for (uint64_t i = 0; i < count; i++) {
            if (pl_desc_read(a, i, &d) && d.type == PL_EFI_CONVENTIONAL && d.start <= end && d.end > end) {
                end = d.end;
                grew = 1;
            }
        }
    }
    e->start = start;
    e->end = end;
    return 1;
}

/* ---- What the scan learns ---------------------------------------------------------------------------------------------------- */

struct run_record {
    struct pl_walk walk;            /* the first probe of the run */
    uint64_t first, last, probes;
};

struct scan {
    uint64_t descriptors, bad, extents, extents_scanned, conv_bytes;
    struct extent extent[EXTENTS_MAX];
    uint64_t type_start[7];         /* the first usable descriptor of each type 1..6, in map order; type_seen says it exists */
    uint8_t type_seen[7];
    struct extent low;              /* the largest conventional extent below 4 GiB, clipped there */
    struct extent bank_span;        /* the lowest and highest conventional address inside the bank */
    uint64_t bank_bytes;
    uint64_t probes, mapped, faults;
    uint32_t nkeys;
    uint32_t key[KEYS_MAX];
    struct pl_walk key_walk[KEYS_MAX];
    uint64_t key_probes[KEYS_MAX], key_first[KEYS_MAX], key_last[KEYS_MAX], key_untracked;
    uint64_t runs, runs_kept;
    struct run_record run[RUNS_MAX];
    uint32_t cur_key;
    struct run_record cur;
    uint8_t cur_open;
    uint64_t bank_probes, bank_same, bank_faults, bank_fault_first;
    uint32_t bank_key;
    struct pl_walk bank_walk, bank_fault_walk;
};

/* Pass 1, no AT: the usable descriptors, the conventional extents in address order, the first descriptor of each type 1..6, the
 * largest low extent and the part of the bank that is conventional. */
OUT_OF_LINE void map_survey(const struct q1n1_payload_args *a, struct scan *s)
{
    struct pl_desc d;
    uint64_t count = a->map_size / a->map_stride, from = 0;
    struct extent e;
    s->descriptors = count;
    for (uint64_t i = 0; i < count; i++) {
        if (!pl_desc_read(a, i, &d)) {
            s->bad++;
        } else if (d.type >= 1 && d.type <= 6 && !s->type_seen[d.type]) {
            s->type_seen[d.type] = 1;
            s->type_start[d.type] = d.start;
        }
    }
    while (extent_next(a, count, from, &e)) {
        from = e.end;
        s->conv_bytes += e.end - e.start;
        if (s->extents < EXTENTS_MAX) s->extent[s->extents_scanned++] = e;
        s->extents++;
        if (e.start < LOW_LIMIT) {
            uint64_t clipped = e.end < LOW_LIMIT ? e.end : LOW_LIMIT;
            if (clipped - e.start > s->low.end - s->low.start) {
                s->low.start = e.start;
                s->low.end = clipped;
            }
        }
        if (e.start < BANK_END && e.end > BANK_BASE) {
            uint64_t lo = e.start < BANK_BASE ? BANK_BASE : e.start, hi = e.end > BANK_END ? BANK_END : e.end;
            if (!s->bank_bytes || lo < s->bank_span.start) s->bank_span.start = lo;
            if (!s->bank_bytes || hi > s->bank_span.end) s->bank_span.end = hi;
            s->bank_bytes += hi - lo;
        }
    }
}

/* Closes the open run into the record when there is room; the commonest key's runs are dropped from the page later, not here. */
OUT_OF_LINE void run_close(struct scan *s)
{
    if (!s->cur_open) return;
    s->runs++;
    if (s->runs_kept < RUNS_MAX) s->run[s->runs_kept++] = s->cur;
    s->cur_open = 0;
}

/* One AT S1E2R and what it adds to the folds. */
OUT_OF_LINE void probe(struct scan *s, uint64_t va)
{
    struct pl_walk w;
    pl_walk_page(va, &w);
    uint32_t key = pl_walk_key(&w);
    unsigned k = 0;
    s->probes++;
    if (w.mapped) s->mapped++;
    else s->faults++;
    while (k < s->nkeys && s->key[k] != key) k++;
    if (k == s->nkeys && s->nkeys < KEYS_MAX) {
        s->key[k] = key;
        s->key_walk[k] = w;
        s->key_first[k] = va;
        s->nkeys++;
    }
    if (k < s->nkeys) {
        s->key_probes[k]++;
        s->key_last[k] = va;
    } else {
        s->key_untracked++;
    }
    if (s->cur_open && s->cur_key == key) {
        s->cur.last = va;
        s->cur.probes++;
    } else {
        run_close(s);
        s->cur_open = 1;
        s->cur_key = key;
        s->cur.walk = w;
        s->cur.first = s->cur.last = va;
        s->cur.probes = 1;
    }
    if (va >= BANK_BASE && va < BANK_END) {
        if (!s->bank_probes) {
            s->bank_key = key;
            s->bank_walk = w;
        }
        s->bank_probes++;
        if (key == s->bank_key) s->bank_same++;
        if (!w.mapped) {
            if (!s->bank_faults) {
                s->bank_fault_first = va;
                s->bank_fault_walk = w;
            }
            s->bank_faults++;
        }
    }
}

/* The first page, every 2 MiB boundary above it, and the last page of an extent. */
OUT_OF_LINE void scan_extent(struct scan *s, const struct extent *e)
{
    uint64_t last = e->end - PL_PAGE_BYTES, at = e->start;
    for (;;) {
        probe(s, at);
        if (at >= last) break;
        at = (at & ~(BLOCK_2M - 1)) + BLOCK_2M;
        if (at >= last) at = last;
    }
}

OUT_OF_LINE void scan_all(struct scan *s)
{
    for (uint64_t i = 0; i < s->extents_scanned; i++) scan_extent(s, &s->extent[i]);
    run_close(s);
}

/* ---- Reports ----------------------------------------------------------------------------------------------------------------- */

OUT_OF_LINE void report_map(const struct q1n1_payload_args *a, struct pl_page *p, const struct scan *s)
{
    pl_page_open(p, "MAP", 0);
    pl_add_dec(a, p, "DESC", s->descriptors);
    pl_add_dec(a, p, "STRIDE", a->map_stride);
    pl_add_dec(a, p, "CONV_EXTENTS", s->extents);
    pl_add_dec(a, p, "CONV_MIB", s->conv_bytes / MIB);
    if (s->bad) pl_add_dec(a, p, "IGNORED", s->bad);
    if (s->extents > s->extents_scanned) pl_add_dec(a, p, "NOT_SCANNED", s->extents - s->extents_scanned);
    pl_page_flush(a, p);
}

OUT_OF_LINE void report_scan(const struct q1n1_payload_args *a, struct pl_page *p, const struct scan *s)
{
    struct pl_line item;
    unsigned dominant = 0;
    uint64_t listed = 0, outliers = 0;
    if (!s->probes) {
        pl_say(a, p, "SCAN", "NO_PROBES", 0);
        return;
    }
    for (unsigned k = 1; k < s->nkeys; k++)
        if (s->key_probes[k] > s->key_probes[dominant]) dominant = k;
    for (unsigned k = 0; k < s->nkeys; k++) {
        pl_page_open(p, "KEY", 0);
        add_walk(a, p, "RESULT", &s->key_walk[k]);
        pl_add_dec(a, p, "PROBES", s->key_probes[k]);
        pl_add_hex(a, p, "FIRST", s->key_first[k]);
        pl_add_hex(a, p, "LAST", s->key_last[k]);
        pl_page_flush(a, p);
    }
    for (uint64_t r = 0; r < s->runs_kept; r++) {
        if (pl_walk_key(&s->run[r].walk) == s->key[dominant]) continue;
        outliers++;
        if (listed == OUTLIERS_MAX) continue;
        listed++;
        pl_page_open(p, "OUTLIER", 0);
        add_walk(a, p, "RESULT", &s->run[r].walk);
        pl_add_hex(a, p, "FROM", s->run[r].first);
        pl_add_hex(a, p, "TO", s->run[r].last);
        pl_add_dec(a, p, "PROBES", s->run[r].probes);
        pl_page_flush(a, p);
    }
    pl_page_open(p, "SCAN", 0);
    pl_add_dec(a, p, "EXTENTS", s->extents_scanned);
    pl_add_dec(a, p, "PROBES", s->probes);
    if (s->nkeys == 1 && !s->key_untracked && s->mapped) {
        pl_page_add(a, p, "ALL=MAPPED");
        pl_begin(&item);
        pl_text(&item, "ATTR=");
        pl_put_attr(a, &item, s->key_walk[0].attr);
        pl_page_add(a, p, item.buf);
        pl_begin(&item);
        pl_text(&item, "SH=");
        pl_put_sh(&item, s->key_walk[0].sh);
        pl_page_add(a, p, item.buf);
        if (s->key_walk[0].ns) pl_page_add(a, p, "NS=1");
        if (!s->key_walk[0].ident) pl_page_add(a, p, "NONIDENT");
    } else {
        pl_add_dec(a, p, "MAPPED", s->mapped);
        pl_add_dec(a, p, "FAULT", s->faults);
        pl_add_dec(a, p, "KEYS", s->nkeys + (s->key_untracked ? 1 : 0));
        pl_add_dec(a, p, "RUNS", s->runs);
        if (outliers > listed) pl_add_dec(a, p, "OUTLIERS_NOT_LISTED", outliers - listed);
        if (s->runs > s->runs_kept) pl_add_dec(a, p, "RUNS_NOT_RECORDED", s->runs - s->runs_kept);
    }
    pl_page_flush(a, p);
}

/* The bank on its own line, whatever the scan folded. */
OUT_OF_LINE void report_bank(const struct q1n1_payload_args *a, struct pl_page *p, const struct scan *s)
{
    struct pl_line item;
    pl_page_open(p, "BANK", 0);
    if (!s->bank_bytes) {
        pl_page_add(a, p, "NOT_CONVENTIONAL_IN_THE_MAP");
        pl_page_flush(a, p);
        return;
    }
    pl_add_dec(a, p, "CONV_MIB", s->bank_bytes / MIB);
    pl_add_dec(a, p, "PROBES", s->bank_probes);
    if (!s->bank_faults && s->bank_same == s->bank_probes) {
        pl_page_add(a, p, "ALL=MAPPED");
        pl_begin(&item);
        pl_text(&item, "RESULT=");
        pl_put_walk(a, &item, &s->bank_walk);
        pl_page_add(a, p, item.buf);
    } else {
        pl_add_dec(a, p, "FAULT", s->bank_faults);
        pl_add_dec(a, p, "SAME_AS_FIRST", s->bank_same);
        if (s->bank_faults) {
            pl_add_hex(a, p, "FIRST_FAULT", s->bank_fault_first);
            add_walk(a, p, "AT", &s->bank_fault_walk);
        }
    }
    pl_page_flush(a, p);
}

/* One page of each of the six firmware types, the payload's own first page and its stack. */
OUT_OF_LINE void report_control(const struct q1n1_payload_args *a, struct pl_page *p, const struct scan *s)
{
    struct pl_walk w;
    pl_page_open(p, "CONTROL", 0);
    for (unsigned t = 1; t <= 6; t++) {
        if (!s->type_seen[t]) {
            add_absent_numbered(a, p, "T", t);
            continue;
        }
        pl_walk_page(s->type_start[t], &w);
        add_walk_numbered(a, p, "T", t, &w);
    }
    pl_walk_page(a->payload_base, &w);
    add_walk(a, p, "CODE", &w);
    pl_walk_page(a->stack_base, &w);
    add_walk(a, p, "STACK", &w);
    pl_page_flush(a, p);
}

/* ---- Four guarded loads ------------------------------------------------------------------------------------------------------ */

/* One word, only if an AT of its page says mapped; an error code of the op is shown as ERR<n>. Returns 1 when the word was read. */
OUT_OF_LINE int load_word(const struct q1n1_payload_args *a, struct pl_page *p, const char *name, uint64_t va)
{
    struct pl_walk w;
    struct pl_line item;
    uint32_t value = 0;
    int32_t rc;
    int ok = 0;
    pl_begin(&item);
    pl_text(&item, name);
    pl_text(&item, "(");
    pl_hex(a, &item, va);
    pl_text(&item, ")=");
    pl_walk_page(va, &w);
    if (!w.mapped) {
        pl_text(&item, "SKIPPED_NOT_MAPPED");
    } else if (!a->ops.load32) {
        pl_text(&item, "SKIPPED_NO_LOAD32");
    } else {
        rc = a->ops.load32(va, &value);
        if (rc) {
            pl_text(&item, "ERR");
            pl_dec(&item, (uint64_t)(uint32_t)rc);
        } else {
            pl_hex(a, &item, value);
            ok = 1;
        }
    }
    pl_page_add(a, p, item.buf);
    return ok;
}

OUT_OF_LINE unsigned report_loads(const struct q1n1_payload_args *a, struct pl_page *p, const struct scan *s, unsigned *tried)
{
    unsigned ok = 0;
    pl_page_open(p, "LOAD", 0);
    if (s->bank_bytes) {
        ok += load_word(a, p, "BANK_FIRST", s->bank_span.start);
        ok += load_word(a, p, "BANK_LAST", s->bank_span.end - 4u);
        *tried += 2;
    } else {
        pl_page_add(a, p, "BANK=SKIPPED_NOT_CONVENTIONAL");
    }
    if (s->low.end > s->low.start) {
        ok += load_word(a, p, "LOW_FIRST", s->low.start);
        ok += load_word(a, p, "LOW_LAST", s->low.end - 4u);
        *tried += 2;
    } else {
        pl_page_add(a, p, "LOW=SKIPPED_NO_EXTENT");
    }
    pl_page_flush(a, p);
    return ok;
}

/* ---- Registers --------------------------------------------------------------------------------------------------------------- */

OUT_OF_LINE void report_ids(const struct q1n1_payload_args *a, struct pl_page *p)
{
    uint64_t mmfr1 = SYSREG(id_aa64mmfr1_el1);
    pl_page_open(p, "ID", 0);
    pl_add_hex(a, p, "DFR1", SYSREG(S3_0_C0_C5_1));
    pl_add_hex(a, p, "ISAR2", SYSREG(S3_0_C0_C6_2));
    pl_add_hex(a, p, "MMFR1", mmfr1);
    pl_add_dec(a, p, "PAN", mmfr1 >> 20 & 15);
    pl_add_dec(a, p, "VH", mmfr1 >> 8 & 15);
    pl_add_dec(a, p, "HAFDBS", mmfr1 & 15);
    pl_add_hex(a, p, "PFR2", SYSREG(S3_0_C0_C4_2));
    pl_add_hex(a, p, "AIDR", SYSREG(aidr_el1));
    pl_add_hex(a, p, "REVIDR", SYSREG(revidr_el1));
    pl_add_hex(a, p, "MDCR_EL2", SYSREG(mdcr_el2));
    pl_page_flush(a, p);
}

/* Waits `seconds` of the counter; 0 if the counter does not run, or runs backwards (a wait that cannot be measured is not made). */
OUT_OF_LINE int wait_seconds(const struct q1n1_payload_args *a, uint64_t freq, unsigned seconds)
{
    uint64_t start = a->ops.counter(), last = start, now;
    uint32_t same = 0;
    for (;;) {
        now = a->ops.counter();
        if (now < start) return 0;
        if (now - start >= seconds * freq) return 1;
        if (now == last) {
            if (++same >= COUNTER_STUCK_READS) return 0;
        } else {
            last = now;
            same = 0;
        }
    }
}

/* "NEXT <name> AFTER 8 S" and the wait; 0, and a line saying so, when the wait cannot be made (the read is then never made). */
OUT_OF_LINE int announce(const struct q1n1_payload_args *a, struct pl_page *p, uint64_t freq, const char *name)
{
    struct pl_line text;
    pl_begin(&text);
    pl_text(&text, name);
    pl_text(&text, " AFTER ");
    pl_dec(&text, WAIT_BEFORE_READ_S);
    pl_text(&text, " S");
    pl_say(a, p, "NEXT", text.buf, 1);
    if (!a->ops.counter) {
        pl_say(a, p, name, "SKIPPED=NO_COUNTER", 0);
        return 0;
    }
    if (!wait_seconds(a, freq, WAIT_BEFORE_READ_S)) {
        pl_say(a, p, name, "SKIPPED=COUNTER_STUCK", 0);
        return 0;
    }
    return 1;
}

/* The three reads that may go to EL3: MDSCR_EL1, then OSLSR_EL1 and ICC_SRE_EL2 last. Returns how many were made. */
OUT_OF_LINE unsigned report_hazards(const struct q1n1_payload_args *a, struct pl_page *p, uint64_t freq)
{
    unsigned made = 0;
    uint64_t value;
    if (!announce(a, p, freq, "MDSCR_EL1")) return made;
    value = SYSREG(mdscr_el1);
    pl_page_open(p, "MDSCR_EL1", 0);
    pl_add_hex(a, p, "RAW", value);
    pl_page_flush(a, p);
    made++;
    if (!announce(a, p, freq, "OSLSR_EL1")) return made;
    value = SYSREG(oslsr_el1);
    pl_page_open(p, "OSLSR_EL1", 0);
    pl_add_hex(a, p, "RAW", value);
    pl_add_dec(a, p, "OSLK", value >> 1 & 1);
    pl_page_flush(a, p);
    made++;
    if (!announce(a, p, freq, "ICC_SRE_EL2")) return made;
    value = SYSREG(icc_sre_el2);
    pl_page_open(p, "ICC_SRE_EL2", 0);
    pl_add_hex(a, p, "RAW", value);
    pl_add_dec(a, p, "SRE", value & 1);
    pl_add_dec(a, p, "ENABLE", value >> 3 & 1);
    pl_page_flush(a, p);
    made++;
    return made;
}

uint64_t payload_entry(const struct q1n1_payload_args *a);
uint64_t payload_entry(const struct q1n1_payload_args *a)
{
    struct pl_page p;
    struct scan s;
    uint64_t current_el, freq, rc = 0;
    unsigned loads_ok = 0, loads_tried = 0, hazards = 0, refused;
    if (!pl_args_ok(a)) return Q1N1_PAYLOAD_RET_BAD_ARGS;
    pl_page_init(&p, ESSENTIAL_LINES);
    pl_zero(&s, sizeof s);
    current_el = SYSREG(CurrentEL);
    freq = SYSREG(CNTFRQ_EL0);
    if (freq < COUNTER_HZ_MIN || freq > COUNTER_HZ_MAX) freq = COUNTER_HZ_DEFAULT;
    pl_page_open(&p, "START", 0);
    pl_add_hex(a, &p, "CURRENTEL", current_el);
    pl_add_dec(a, &p, "FREQ", freq);
    pl_page_flush(a, &p);
    if ((current_el >> 2 & 3) != 2) {
        pl_say(a, &p, "REFUSED", "NOT_AT_EL2", 1);
        return 2;
    }

    refused = !map_usable(a, &p);
    if (refused) {
        rc = 3;
    } else {
        map_survey(a, &s);
        report_map(a, &p, &s);
        if (s.extents_scanned) {
            scan_all(&s);
            report_scan(a, &p, &s);
            report_bank(a, &p, &s);
            report_control(a, &p, &s);
            loads_ok = report_loads(a, &p, &s, &loads_tried);
        } else {
            pl_say(a, &p, "SCAN", "SKIPPED_NO_CONVENTIONAL_EXTENT", 0);
        }
    }
    report_ids(a, &p);
    hazards = report_hazards(a, &p, freq);

    pl_page_open(&p, "DONE", 1);
    pl_page_add(a, &p, refused ? "MAP_REFUSED" : s.faults ? "SCAN_HAS_FAULTS" : s.probes ? "SCAN_ALL_MAPPED" : "SCAN_NOT_RUN");
    pl_add_dec(a, &p, "LOADS_OK", loads_ok);
    pl_add_dec(a, &p, "OF", loads_tried);
    pl_add_dec(a, &p, "HAZARD_READS", hazards);
    if (p.suppressed) pl_add_dec(a, &p, "SUPPRESSED", p.suppressed);
    pl_page_flush(a, &p);
    return rc;
}
