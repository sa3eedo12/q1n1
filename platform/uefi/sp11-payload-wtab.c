/* SPDX-License-Identifier: MIT */
/* The runner's write table (sp11-payload-wtab.h, docs/SP11-PAYLOAD-WTAB.md). One run is a state machine over a validated copy of the
 * payload's table:
 *
 *   open    the table is validated (the same rules as tools/sp11_wtab.py), copied into the runner's own memory and hashed; the platform is asked for what the
 *           table needs, and the mapping of every row's page is printed (a write needs Device memory)
 *   row k   k must be the next row. poll for an SError, read, check what was found, journal the row, store once through the guarded path, poll again, poll the read-back
 *   stop    any failure at all: no further store, every changed row undone in reverse and proven, the reason printed, END printed
 *   end     at the payload's return the rows still in force are undone too when the table says so
 *
 * Through these ops the payload cannot name an address or a value, so a bug in it can at worst call row() with the wrong index, which is refused. (Its own stores
 * are another matter: the policy tooling checks their base, and its bytes are reviewed and pinned by the manifest.) The journal and the table copy are in the runner's
 * own memory, outside everything the ops let a payload reach. What this cannot do: recover from a
 * hang. A store or a read that never completes keeps the core, and the last line printed (the W line, printed before the store) names the
 * row; a hang after the C line of row n is in row n + 1 (the ATTR lines were printed at open); the operator's rules for that are in the document. */
#include "sp11-payload-wtab.h"
#include "sha256.h"

#if Q1N1_SP11_PAYLOAD && Q1N1_SP11_WTAB

#define HEADER_INDEX 0xffffffffu
#define BLOB_BYTES Q1N1_WTAB_TABLE_BYTES(Q1N1_WTAB_ROWS_MAX, Q1N1_WTAB_WINDOWS_MAX)

static const char *const reason_names[] = {
#define X(name) #name,
    Q1N1_WTAB_REASONS(X)
#undef X
};

const char *q1n1_wtab_reason_name(int reason)
{
    return reason >= 0 && reason < Q1N1_WTAB_REASON_COUNT ? reason_names[reason] : "UNKNOWN";
}

/* ---- Validation: pure ------------------------------------------------------------------------------------------------------ */

static int font_ok(char c)
{
    return (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == ' ' || c == ':' || c == '-' || c == '.' || c == '/' || c == '=' ||
           c == '?' || c == '(' || c == ')' || c == '_';
}

/* Page-font characters up to the first NUL (or `cap`), then zeros only: a text that is printed is canonical, so that two tables
 * that print the same are the same bytes. `need_nul`: the text must end inside the field. */
static int text_ok(const char *s, unsigned cap, int need_nul)
{
    unsigned n = 0;
    while (n < cap && s[n]) {
        if (!font_ok(s[n])) return 0;
        n++;
    }
    if (n == 0 || (need_nul && n == cap)) return 0;
    for (unsigned i = n; i < cap; i++) {
        if (s[i]) return 0;
    }
    return 1;
}

static int in_window(const struct q1n1_wtab_window *w, uint32_t addr)
{
    return addr >= w->base && (uint64_t)addr < (uint64_t)w->base + w->size;
}

static int row_reason(const struct q1n1_wtab_header *h, const struct q1n1_wtab_row *r, const struct q1n1_wtab_row *prev)
{
    int check = r->mask == 0;
    if (!r->addr || (r->addr & 3)) return Q1N1_WTAB_ROW_ADDR;
    if (r->value & ~r->mask) return Q1N1_WTAB_ROW_MASK_VALUE;
    if (check && (r->value || r->undo_kind || r->undo_value || r->undo_rb_addr || r->undo_rb_mask || r->undo_rb_value ||
                  r->undo_timeout_us || r->undo_after_us || (!r->found_mask && !r->rb_mask)))
        return Q1N1_WTAB_ROW_CHECK;
    if (r->found_value & ~r->found_mask) return Q1N1_WTAB_ROW_FOUND;
    /* A row that writes must say what the bits it writes hold when it is found: a blind read-modify-write is refused. */
    if (!check && (r->found_mask & r->mask) != r->mask) return Q1N1_WTAB_ROW_NO_FOUND;
    if (!check && (r->found_mask & r->mask) == r->mask && (r->found_value & r->mask) == r->value) return Q1N1_WTAB_ROW_NEVER_WRITES;
    if (!check && !r->rb_mask) return Q1N1_WTAB_ROW_NO_READBACK;
    if (r->rb_mask ? (!r->rb_addr || (r->rb_addr & 3) || (r->rb_value & ~r->rb_mask))
                   : (r->rb_addr || r->rb_value || r->rb_timeout_us))
        return Q1N1_WTAB_ROW_RB;
    if (r->rb_mask && r->rb_addr == r->addr && !check && ((r->rb_value ^ r->value) & r->rb_mask & r->mask))
        return Q1N1_WTAB_ROW_RB_CONTRADICTS;
    if (r->rb_timeout_us > Q1N1_WTAB_POLL_MAX_US || r->settle_us > Q1N1_WTAB_DELAY_MAX_US || r->after_us > Q1N1_WTAB_DELAY_MAX_US ||
        r->undo_after_us > Q1N1_WTAB_DELAY_MAX_US)
        return Q1N1_WTAB_ROW_TIMES;
    if (!check) {
        if (r->undo_kind > Q1N1_WTAB_UNDO_VALUE) return Q1N1_WTAB_ROW_UNDO;
        if (r->undo_kind == Q1N1_WTAB_UNDO_NONE &&
            (!(h->flags & Q1N1_WTAB_F_ALLOW_IRREVERSIBLE) || r->undo_value || r->undo_rb_addr || r->undo_rb_mask || r->undo_rb_value ||
             r->undo_timeout_us || r->undo_after_us))
            return Q1N1_WTAB_ROW_UNDO;
        if (r->undo_kind == Q1N1_WTAB_UNDO_RESTORE && r->undo_value) return Q1N1_WTAB_ROW_UNDO;
        if (r->undo_kind == Q1N1_WTAB_UNDO_VALUE && ((r->undo_value & ~r->mask) || r->undo_value == r->value)) return Q1N1_WTAB_ROW_UNDO;
        if (r->undo_kind != Q1N1_WTAB_UNDO_NONE &&
            (r->undo_rb_mask ? (!r->undo_rb_addr || (r->undo_rb_addr & 3) || (r->undo_rb_value & ~r->undo_rb_mask))
                             : (r->undo_rb_addr || r->undo_rb_value)))
            return Q1N1_WTAB_ROW_UNDO_RB;
    }
    if (prev ? (r->step != prev->step && r->step != prev->step + 1u) : r->step != 0) return Q1N1_WTAB_ROW_STEP;
    if (r->step >= Q1N1_WTAB_STEPS_MAX) return Q1N1_WTAB_ROW_STEP;
    if (r->flags || r->reserved8[0] || r->reserved8[1] || r->reserved8[2] || r->reserved[0] || r->reserved[1] || r->reserved[2])
        return Q1N1_WTAB_ROW_RESERVED;
    if (!text_ok(r->tag, Q1N1_WTAB_TAG_BYTES, 0)) return Q1N1_WTAB_ROW_TAG;
    return 0;
}

unsigned q1n1_wtab_line_cost(const struct q1n1_wtab_header *header, const struct q1n1_wtab_row *rows)
{
    unsigned cost = 1u + header->rows, step_writes = 0;      /* the open line, and an ATTR line for each row */
    for (uint32_t i = 0; i < header->rows; i++) {
        cost += rows[i].mask ? 2u : 1u;
        if (rows[i].mask && rows[i].step < 32) step_writes |= 1u << rows[i].step;
    }
    for (; step_writes; step_writes &= step_writes - 1) cost++;     /* a NEXT line for each step that writes */
    return cost;
}

unsigned q1n1_wtab_line_reserve(const struct q1n1_wtab_header *header, const struct q1n1_wtab_row *rows)
{
    unsigned writes = 0;
    for (uint32_t i = 0; i < header->rows; i++) writes += rows[i].mask != 0;
    /* the STOP (or AUTO_UNWIND) line and the END line, a U line and at most one U FAIL line for the undo of each write row, and the lines that refuse a read of a window */
    return 2u + 2u * writes + (header->windows ? Q1N1_WTAB_REFUSED_LINES : 0u);
}

/* The author's own label for a table whose expectations nobody has observed (tools/sp11_wtab.py: the name ends -DRAFT exactly when the table has a draft list). */
static int draft_named(const struct q1n1_wtab_header *h)
{
    static const char suffix[] = "-DRAFT";
    unsigned n = 0;
    while (n < Q1N1_WTAB_NAME_BYTES && h->name[n]) n++;
    if (n < sizeof suffix - 1) return 0;
    for (unsigned i = 0; i < sizeof suffix - 1; i++) {
        if (h->name[n - (sizeof suffix - 1) + i] != suffix[i]) return 0;
    }
    return 1;
}

int q1n1_wtab_validate(const void *blob, uint64_t avail, struct q1n1_wtab_diag *diag)
{
    if (diag) diag->index = HEADER_INDEX;
    if (avail < sizeof(struct q1n1_wtab_header)) return Q1N1_WTAB_SIZE_SHORT;
    const struct q1n1_wtab_header *h = blob;
    if (h->magic != Q1N1_WTAB_TABLE_MAGIC) return Q1N1_WTAB_MAGIC;
    if (h->version != Q1N1_WTAB_TABLE_VERSION) return Q1N1_WTAB_VERSION;
    if (h->reserved[0] || h->reserved[1] || h->reserved[2]) return Q1N1_WTAB_HEADER_RESERVED;
    if (!h->rows || h->rows > Q1N1_WTAB_ROWS_MAX || h->windows > Q1N1_WTAB_WINDOWS_MAX || !h->steps || h->steps > Q1N1_WTAB_STEPS_MAX)
        return Q1N1_WTAB_COUNTS;
    if (h->bytes != Q1N1_WTAB_TABLE_BYTES(h->rows, h->windows) || h->bytes > avail) return Q1N1_WTAB_BYTES;
    if (h->flags & ~Q1N1_WTAB_F_KNOWN) return Q1N1_WTAB_FLAGS;
    if (h->pause_s > Q1N1_WTAB_PAUSE_MAX_S) return Q1N1_WTAB_PAUSE;
    if (!text_ok(h->name, Q1N1_WTAB_NAME_BYTES, 1)) return Q1N1_WTAB_NAME;
    const struct q1n1_wtab_row *rows = (const struct q1n1_wtab_row *)(h + 1);
    const struct q1n1_wtab_window *win = (const struct q1n1_wtab_window *)(rows + h->rows);
    for (uint32_t i = 0; i < h->rows; i++) {
        int reason = row_reason(h, &rows[i], i ? &rows[i - 1] : 0);
        if (reason) {
            if (diag) diag->index = i;
            return reason;
        }
    }
    for (uint32_t j = 0; j < h->windows; j++) {
        const struct q1n1_wtab_window *w = &win[j];
        if (diag) diag->index = j;
        if (!w->size || (w->base & 3) || (w->size & 3) || (uint64_t)w->base + w->size > UINT64_C(0x100000000) || w->reserved)
            return Q1N1_WTAB_WIN_RANGE;
        if (w->after_row >= h->rows) return Q1N1_WTAB_WIN_AFTER;
        for (uint32_t k = 0; k < j; k++) {
            if ((uint64_t)w->base < (uint64_t)win[k].base + win[k].size && (uint64_t)win[k].base < (uint64_t)w->base + w->size)
                return Q1N1_WTAB_WIN_OVERLAP;
        }
        for (uint32_t i = 0; i <= w->after_row; i++) {
            const struct q1n1_wtab_row *r = &rows[i];
            if (in_window(w, r->addr) || (r->rb_mask && in_window(w, r->rb_addr)) ||
                (r->undo_kind && r->undo_rb_mask && in_window(w, r->undo_rb_addr)))
                return Q1N1_WTAB_WIN_ROW_READS;
        }
    }
    if (diag) diag->index = HEADER_INDEX;
    if (h->steps != rows[h->rows - 1].step + 1u) return Q1N1_WTAB_STEPS;
    if (q1n1_wtab_line_cost(h, rows) + q1n1_wtab_line_reserve(h, rows) > Q1N1_WTAB_LINES_MAX) return Q1N1_WTAB_LINES;
    if (!Q1N1_WTAB_ALLOW_DRAFT && draft_named(h)) return Q1N1_WTAB_DRAFT;
    return Q1N1_WTAB_OK;
}

static uint64_t le_bytes(const uint8_t *p, unsigned n)
{
    uint64_t v = 0;
    for (unsigned i = 0; i < n; i++) v |= (uint64_t)p[i] << (8 * i);
    return v;
}

/* UEFI types 11 and 12 are memory-mapped I/O. A device word is in no descriptor or in one of those; reserved, loader, boot-services,
 * runtime, conventional, ACPI and persistent memory are all places a table must not write. */
int q1n1_wtab_map_allows(const struct q1n1_wtab_machine *m, uint32_t addr)
{
    if (!m->map_base || m->map_stride < 40 || (m->map_stride & 7) || !m->map_size || m->map_size % m->map_stride ||
        m->map_size / m->map_stride > 4096)
        return 0;
    const uint8_t *map = (const uint8_t *)(uintptr_t)m->map_base;
    for (uint64_t off = 0; off < m->map_size; off += m->map_stride) {
        uint64_t type = le_bytes(map + off, 4), start = le_bytes(map + off + 8, 8), pages = le_bytes(map + off + 24, 8);
        uint64_t end = pages > (UINT64_MAX - start) / 4096 ? UINT64_MAX : start + pages * 4096;
        if (start < (uint64_t)addr + 4 && (uint64_t)addr < end && type != 11 && type != 12) return 0;
    }
    return 1;
}

/* ---- One run ------------------------------------------------------------------------------------------------------------- */

enum { J_NONE, J_CHECKED, J_SKIPPED, J_STORED, J_UNDONE };

static struct {
    const struct q1n1_wtab_env *env;
    struct q1n1_wtab_machine machine;
    uint64_t blob64[(BLOB_BYTES + 7) / 8];      /* the validated copy: the run never reads the payload's own */
    const struct q1n1_wtab_header *hdr;
    const struct q1n1_wtab_row *rows;
    const struct q1n1_wtab_window *win;
    uint8_t step_writes[Q1N1_WTAB_STEPS_MAX];
    struct { uint32_t old; uint8_t state; } journal[Q1N1_WTAB_ROWS_MAX];
    uint32_t next, announced;
    int opened, stopped, finished, ended, in_undo, serror_seen, refused_not_open;
    int reason;
    uint32_t stop_row;
    unsigned stores, undos, undo_ok, undo_failed, undo_needed, irreversible, window_reads, window_refusals, lines, dropped, ordinary_limit;
    struct q1n1_wtab_result last;
} S;

static void zero(void *p, size_t n)
{
    uint8_t *b = p;
    for (size_t i = 0; i < n; i++) b[i] = 0;
}

/* A line of the table's own budget. Critical lines (the stop, the undo, the end, the refusals of a window read) may use all of Q1N1_WTAB_LINES_MAX; the others
 * stop at the limit that leaves the table's reserve (q1n1_wtab_line_reserve, set at open) untouched. Returns 1 when the line was printed. */
static int put(const struct q1n1_payload_line *line, int critical)
{
    if (!S.env || !S.env->emit || S.lines >= (critical ? Q1N1_WTAB_LINES_MAX : S.ordinary_limit)) {
        S.dropped++;
        return 0;
    }
    S.lines++;
    S.env->emit(line->buf);
    return 1;
}

static void tag_text(const struct q1n1_wtab_row *r, char *out)
{
    unsigned n = 0;
    while (n < Q1N1_WTAB_TAG_BYTES && r->tag[n]) {
        out[n] = r->tag[n];
        n++;
    }
    out[n] = 0;
}

static void row_head(struct q1n1_payload_line *line, const char *kind, uint32_t index)
{
    char text[24], tag[Q1N1_WTAB_TAG_BYTES + 1];
    q1n1_payload_fmt_dec(text, sizeof text, index);
    tag_text(&S.rows[index], tag);
    q1n1_payload_line_begin(line, kind);
    q1n1_payload_line_word(line, text);
    q1n1_payload_line_word(line, tag);
    q1n1_payload_line_hex(line, "A", S.rows[index].addr);
}

/* ---- Time ----------------------------------------------------------------------------------------------------------------- */

static int counter_usable(void)
{
    return S.env->counter && S.env->counter_hz >= Q1N1_WTAB_COUNTER_HZ_MIN && S.env->counter_hz <= Q1N1_WTAB_COUNTER_HZ_MAX;
}

/* Waits `us` microseconds on the counter. A counter that stands still, runs backwards or does not get there in 2^32 - 1 reads is
 * not a clock: that is a stop, never a wait skipped. */
static int wait_us(uint64_t us)
{
    if (!us) return 0;
    if (!counter_usable()) return Q1N1_WTAB_COUNTER;
    uint64_t ticks = us * S.env->counter_hz / 1000000u, start = S.env->counter(), last = start;
    unsigned same = 0;
    for (uint64_t spins = 0; spins < Q1N1_WTAB_SPIN_MAX; spins++) {
        uint64_t now = S.env->counter();
        if (now < last) return Q1N1_WTAB_COUNTER;
        same = now == last ? same + 1 : 0;
        if (same > Q1N1_WTAB_STUCK_READS) return Q1N1_WTAB_COUNTER;
        last = now;
        if (now - start >= ticks) return 0;
    }
    return Q1N1_WTAB_COUNTER;
}

/* Reads `addr` until (value & mask) == want or `timeout_us` has passed, always at least once and once more at the end of the time (the
 * deadline is checked after a read, so a slow read never turns a good value into a timeout). */
static int poll_match(uint32_t addr, uint32_t mask, uint32_t want, uint32_t timeout_us, uint32_t *got, uint32_t *elapsed_us)
{
    uint64_t hz = S.env->counter_hz;
    if (timeout_us && !counter_usable()) return Q1N1_WTAB_COUNTER;
    uint64_t start = timeout_us ? S.env->counter() : 0, last = start, ticks = (uint64_t)timeout_us * hz / 1000000u;
    unsigned same = 0, reads = 0;
    *elapsed_us = 0;
    for (;;) {
        if (S.env->read32(addr, got)) return Q1N1_WTAB_FAULT;
        if ((*got & mask) == want) return 0;
        if (!timeout_us) return Q1N1_WTAB_READBACK;
        uint64_t now = S.env->counter();
        if (now < last) return Q1N1_WTAB_COUNTER;
        same = now == last ? same + 1 : 0;
        if (same > Q1N1_WTAB_STUCK_READS || ++reads >= Q1N1_WTAB_POLL_READS_MAX) return Q1N1_WTAB_COUNTER;
        last = now;
        *elapsed_us = (uint32_t)((now - start) * 1000000u / hz);
        if (now - start >= ticks) return Q1N1_WTAB_READBACK;
    }
}

/* ---- Undo, stop, end ------------------------------------------------------------------------------------------------------ */

static void end_line(const char *result)
{
    struct q1n1_payload_line line;
    char text[24];
    q1n1_payload_line_begin(&line, "WTAB END RESULT=");
    q1n1_payload_line_raw(&line, result);
    q1n1_payload_line_raw(&line, " WHY=");
    q1n1_payload_line_raw(&line, q1n1_wtab_reason_name(S.reason));
    q1n1_payload_fmt_dec(text, sizeof text, S.next);
    q1n1_payload_line_raw(&line, " ROWS=");
    q1n1_payload_line_raw(&line, text);
    q1n1_payload_line_dec(&line, "STORES", S.stores);
    q1n1_payload_line_dec(&line, "UNDOS", S.undos);
    q1n1_payload_line_dec(&line, "RESTORED", S.undo_ok);
    q1n1_payload_line_dec(&line, "OF", S.undo_needed);
    put(&line, 1);
    S.ended = 1;
}

static void undo_failure(uint32_t index, const char *why)
{
    struct q1n1_payload_line line;
    q1n1_payload_line_begin(&line, "U");
    char text[24];
    q1n1_payload_fmt_dec(text, sizeof text, index);
    q1n1_payload_line_word(&line, text);
    q1n1_payload_line_word(&line, "FAIL");
    q1n1_payload_line_word(&line, why);
    put(&line, 1);
    S.undo_failed++;
}

/* Puts one row back: reads the word, writes the masked bits to what the row says, proves them and then proves the row's own undo
 * read-back. An error response (SError) ends the undo of every row that is left: the bus is not to be trusted with more. */
static void undo_row(uint32_t index, int *abort_all)
{
    const struct q1n1_wtab_row *r = &S.rows[index];
    uint32_t target = (r->undo_kind == Q1N1_WTAB_UNDO_RESTORE ? S.journal[index].old : r->undo_value) & r->mask, now = 0, got = 0, us = 0;
    S.undos++;
    if (S.env->read32(r->addr, &now)) {
        undo_failure(index, "FAULT");
        return;
    }
    uint32_t next = (now & ~r->mask) | target;
    struct q1n1_payload_line line;
    row_head(&line, "U", index);
    q1n1_payload_line_hex(&line, "NOW", now);
    q1n1_payload_line_hex(&line, "NEW", next);
    put(&line, 1);
    if (next != now) {
        if (S.env->store32(r->addr, next)) {
            undo_failure(index, "FAULT");
            return;
        }
        if (S.env->serror_poll && S.env->serror_poll()) {
            S.serror_seen = 1;
            *abort_all = 1;
            undo_failure(index, "SERROR");
            return;
        }
    }
    if (wait_us(r->undo_after_us)) {
        undo_failure(index, "COUNTER");
        return;
    }
    int rc = poll_match(r->addr, r->mask, target, r->undo_timeout_us, &got, &us);
    if (!rc && r->undo_rb_mask) rc = poll_match(r->undo_rb_addr, r->undo_rb_mask, r->undo_rb_value, r->undo_timeout_us, &got, &us);
    if (S.env->serror_poll && S.env->serror_poll()) {
        S.serror_seen = 1;
        *abort_all = 1;
        undo_failure(index, "SERROR");
        return;
    }
    if (rc) {
        undo_failure(index, rc == Q1N1_WTAB_FAULT ? "FAULT" : rc == Q1N1_WTAB_COUNTER ? "COUNTER" : "VERIFY");
        return;
    }
    S.undo_ok++;
    S.journal[index].state = J_UNDONE;
}

static void unwind_all(void)
{
    if (S.finished) return;
    int abort_all = 0;
    S.in_undo = 1;
    for (uint32_t i = 0; i < S.hdr->rows; i++) {
        if (S.journal[i].state != J_STORED) continue;
        /* A row the table declared irreversible stays as it is: it is counted, never "undone" by writing a guess. */
        if (S.rows[i].undo_kind == Q1N1_WTAB_UNDO_NONE) S.irreversible++;
        else S.undo_needed++;
    }
    for (uint32_t i = S.hdr->rows; i-- > 0;) {
        if (S.journal[i].state != J_STORED || S.rows[i].undo_kind == Q1N1_WTAB_UNDO_NONE) continue;
        if (abort_all) {
            undo_failure(i, "NOT_TRIED");
            continue;
        }
        undo_row(i, &abort_all);
    }
    S.in_undo = 0;
    S.finished = 1;
}

static const char *result_name(void)
{
    return S.undo_failed ? "UNDO_FAILED" : S.irreversible ? "PARTIAL" : "RESTORED";
}

/* The one place a run stops. Prints why before it undoes anything, so that a hang in the undo still leaves the reason on the page. */
static int stop(int reason, uint32_t row, uint32_t addr, uint32_t got, uint32_t want, uint32_t mask)
{
    if (S.stopped) return reason;
    struct q1n1_payload_line line;
    char text[24];
    S.stopped = 1;
    S.reason = reason;
    S.stop_row = row;
    q1n1_payload_line_begin(&line, "WTAB STOP WHY=");
    q1n1_payload_line_raw(&line, q1n1_wtab_reason_name(reason));
    q1n1_payload_fmt_dec(text, sizeof text, row);
    q1n1_payload_line_raw(&line, " ROW=");
    q1n1_payload_line_raw(&line, text);
    q1n1_payload_line_hex(&line, "A", addr);
    q1n1_payload_line_hex(&line, "GOT", got);
    q1n1_payload_line_hex(&line, "WANT", want);
    q1n1_payload_line_hex(&line, "MASK", mask);
    put(&line, 1);
    unwind_all();
    end_line(result_name());
    return reason;
}

/* ---- The ops -------------------------------------------------------------------------------------------------------------- */

static void refused_line(int reason, const struct q1n1_wtab_diag *diag)
{
    struct q1n1_payload_line line;
    q1n1_payload_line_begin(&line, "WTAB REFUSED=");
    q1n1_payload_line_raw(&line, q1n1_wtab_reason_name(reason));
    if (diag && diag->index != HEADER_INDEX) q1n1_payload_line_dec(&line, "AT", diag->index);
    put(&line, 1);
}

/* A counter that moves forward within a bounded number of reads: the timeouts that guard a store are never "spin until it changes". */
static int counter_advances(void)
{
    if (!counter_usable()) return 0;
    uint64_t first = S.env->counter();
    for (unsigned i = 0; i <= Q1N1_WTAB_STUCK_READS; i++) {
        uint64_t now = S.env->counter();
        if (now < first) return 0;
        if (now > first) return 1;
    }
    return 0;
}

/* What the table needs of the platform, asked before anything runs: a run that could write must be able to read, store, see an SError and measure time, and a table
 * that waits or polls must have a counter that counts. Without them the first thing that would notice is the store. */
static int platform_reason(void)
{
    unsigned writes = 0, timed = 0;
    for (uint32_t i = 0; i < S.hdr->rows; i++) {
        const struct q1n1_wtab_row *r = &S.rows[i];
        writes += r->mask != 0;
        timed |= r->settle_us | r->after_us | r->rb_timeout_us | r->undo_after_us | r->undo_timeout_us;
    }
    if (!S.env || !S.env->emit || !S.env->read32) return Q1N1_WTAB_PLATFORM;
    if (writes && (!S.env->store32 || !S.env->serror_poll)) return Q1N1_WTAB_PLATFORM;
    if ((writes || timed) && !counter_advances()) return Q1N1_WTAB_PLATFORM;
    return 0;
}

/* Gives a refused table back: the run is as if open had not been called. */
static int32_t refuse_open(int reason, const struct q1n1_wtab_diag *diag)
{
    refused_line(reason, diag);
    S.hdr = 0;
    zero(S.step_writes, sizeof S.step_writes);
    return reason;
}

static int32_t op_open(const struct q1n1_wtab_header *table)
{
    struct q1n1_wtab_diag diag = {HEADER_INDEX};
    uint64_t where = (uint64_t)(uintptr_t)table, image_end = S.machine.image_base + S.machine.image_bytes;
    if (S.opened) {
        refused_line(Q1N1_WTAB_REOPEN, 0);
        return Q1N1_WTAB_REOPEN;
    }
    if (!table || (where & 7) || where < S.machine.image_base || where > image_end || image_end < S.machine.image_base) {
        refused_line(Q1N1_WTAB_NOT_IN_IMAGE, 0);
        return Q1N1_WTAB_NOT_IN_IMAGE;
    }
    int reason = q1n1_wtab_validate(table, image_end - where, &diag);
    if (reason) {
        refused_line(reason, &diag);
        return reason;
    }
    uint32_t bytes = table->bytes;
    for (uint32_t i = 0; i < bytes; i++) ((uint8_t *)S.blob64)[i] = ((const uint8_t *)table)[i];
    S.hdr = (const struct q1n1_wtab_header *)S.blob64;
    S.rows = (const struct q1n1_wtab_row *)(S.hdr + 1);
    S.win = (const struct q1n1_wtab_window *)(S.rows + S.hdr->rows);
    for (uint32_t i = 0; i < S.hdr->rows; i++) {
        S.step_writes[S.rows[i].step] |= S.rows[i].mask != 0;
        if (!q1n1_wtab_map_allows(&S.machine, S.rows[i].addr) && S.rows[i].mask) {
            diag.index = i;
            return refuse_open(Q1N1_WTAB_ROW_ADDR_TYPE, &diag);
        }
    }
    reason = platform_reason();
    if (reason) return refuse_open(reason, 0);
    /* One line for each row, check rows included, naming the mapping of the row's page: the film of a dry run is what shows the unit's answer for the page a live row would
     * store to. Only a row that writes needs it to be Device (the ordering of the store and its read-back is that of device memory; a cacheable mapping would keep the
     * store in the data cache and let the read-back succeed on it); anything else, an answer the platform cannot give included, refuses the table. */
    S.ordinary_limit = Q1N1_WTAB_LINES_MAX - q1n1_wtab_line_reserve(S.hdr, S.rows);
    uint32_t bad_attr = HEADER_INDEX;
    for (uint32_t i = 0; i < S.hdr->rows; i++) {
        int attr = S.env->attr ? S.env->attr(S.rows[i].addr) : Q1N1_WTAB_ATTR_UNKNOWN;
        struct q1n1_payload_line attr_line;
        char tag[Q1N1_WTAB_TAG_BYTES + 1];
        tag_text(&S.rows[i], tag);
        q1n1_payload_line_begin(&attr_line, "WTAB ATTR");
        q1n1_payload_line_word(&attr_line, tag);
        q1n1_payload_line_word(&attr_line, attr == Q1N1_WTAB_ATTR_DEVICE ? "DEVICE" : attr == Q1N1_WTAB_ATTR_NORMAL ? "NORMAL" :
                                           attr == Q1N1_WTAB_ATTR_NONE ? "NONE" : "UNKNOWN");
        put(&attr_line, 0);
        if (S.rows[i].mask && attr != Q1N1_WTAB_ATTR_DEVICE && bad_attr == HEADER_INDEX) bad_attr = i;
    }
    if (bad_attr != HEADER_INDEX) {
        diag.index = bad_attr;
        return refuse_open(Q1N1_WTAB_ROW_ATTR, &diag);
    }
    q1n1_sha256(S.blob64, bytes, S.last.digest);
    S.opened = 1;
    S.announced = HEADER_INDEX;
    struct q1n1_payload_line line;
    char name[Q1N1_WTAB_NAME_BYTES + 1];
    unsigned n = 0;
    while (n < Q1N1_WTAB_NAME_BYTES && S.hdr->name[n]) {
        name[n] = S.hdr->name[n];
        n++;
    }
    name[n] = 0;
    q1n1_payload_line_begin(&line, "WTAB OPEN");
    q1n1_payload_line_word(&line, name);
    q1n1_payload_line_dec(&line, "ROWS", S.hdr->rows);
    q1n1_payload_line_dec(&line, "STEPS", S.hdr->steps);
    q1n1_payload_line_digest(&line, "SHA", S.last.digest);
    put(&line, 1);
    return Q1N1_WTAB_OK;
}

static int32_t op_row(uint32_t index)
{
    if (!S.opened) {
        if (!S.refused_not_open++) refused_line(Q1N1_WTAB_NOT_OPEN, 0);
        return Q1N1_WTAB_NOT_OPEN;
    }
    if (S.stopped || S.finished) return Q1N1_WTAB_STOPPED;
    if (index >= S.hdr->rows) return stop(Q1N1_WTAB_INDEX, index, 0, index, S.hdr->rows, 0);
    if (index != S.next) return stop(Q1N1_WTAB_ORDER, index, 0, index, S.next, 0);
    const struct q1n1_wtab_row *r = &S.rows[index];
    struct q1n1_payload_line line;
    uint32_t pre = 0, got = 0, us = 0;
    char text[24];

    if (S.announced != r->step && S.step_writes[r->step]) {
        q1n1_payload_line_begin(&line, "WTAB NEXT STEP");
        q1n1_payload_fmt_dec(text, sizeof text, r->step);
        q1n1_payload_line_raw(&line, "=");
        q1n1_payload_line_raw(&line, text);
        q1n1_payload_line_raw(&line, " AFTER ");
        q1n1_payload_fmt_dec(text, sizeof text, S.hdr->pause_s);
        q1n1_payload_line_raw(&line, text);
        q1n1_payload_line_raw(&line, " S");
        put(&line, 0);
        if (wait_us((uint64_t)S.hdr->pause_s * 1000000u)) return stop(Q1N1_WTAB_COUNTER, index, 0, 0, 0, 0);
    }
    S.announced = r->step;

    if (S.env->read32(r->addr, &pre)) return stop(Q1N1_WTAB_FAULT, index, r->addr, 0, 0, 0);
    if ((pre & r->found_mask) != r->found_value) return stop(Q1N1_WTAB_FOUND, index, r->addr, pre & r->found_mask, r->found_value, r->found_mask);

    int writes = r->mask != 0, skip = writes && (pre & r->mask) == r->value;
    if (writes && !skip) {
        uint32_t next = (pre & ~r->mask) | r->value;
        /* An error response left by an earlier access (the payload's own reads between rows included) must not be taken for the store's: nothing is stored over one. */
        if (S.env->serror_poll && S.env->serror_poll()) return stop(Q1N1_WTAB_SERROR, index, r->addr, pre, next, r->mask);
        row_head(&line, "W", index);
        q1n1_payload_line_hex(&line, "OLD", pre);
        q1n1_payload_line_hex(&line, "NEW", next);
        if (!put(&line, 0)) return stop(Q1N1_WTAB_BUDGET, index, r->addr, S.lines, S.ordinary_limit, 0);
        S.stores++;
        /* In force from here on, before anything else can fail: an external abort on a write leaves the word unknown, so a stop reads it, puts it back if it changed and
         * proves it. The store that faulted, raised an SError or never reads back is exactly the one that has to be undone. */
        S.journal[index].old = pre;
        S.journal[index].state = J_STORED;
        if (S.env->store32(r->addr, next)) return stop(Q1N1_WTAB_FAULT, index, r->addr, pre, next, r->mask);
        if (S.env->serror_poll && S.env->serror_poll()) return stop(Q1N1_WTAB_SERROR, index, r->addr, pre, next, r->mask);
    } else {
        S.journal[index].state = skip ? J_SKIPPED : J_CHECKED;
    }

    if (wait_us(r->settle_us)) return stop(Q1N1_WTAB_COUNTER, index, r->addr, 0, 0, 0);
    int rc = r->rb_mask ? poll_match(r->rb_addr, r->rb_mask, r->rb_value, r->rb_timeout_us, &got, &us) : 0;
    if (S.env->serror_poll && S.env->serror_poll()) return stop(Q1N1_WTAB_SERROR, index, r->rb_addr, got, r->rb_value, r->rb_mask);
    if (rc) return stop(rc, index, r->rb_addr, got, r->rb_value, r->rb_mask);

    if (writes && !skip) {
        /* the row's own line was the W line: this one is its result */
        q1n1_payload_line_begin(&line, "R");
        q1n1_payload_fmt_dec(text, sizeof text, index);
        q1n1_payload_line_word(&line, text);
        q1n1_payload_line_word(&line, "OK");
    } else {
        row_head(&line, skip ? "S" : "C", index);
        q1n1_payload_line_hex(&line, "V", pre);
    }
    if (r->rb_mask) {
        q1n1_payload_line_hex(&line, "RB", got);
        q1n1_payload_line_dec(&line, "US", us);
    }
    put(&line, 0);
    if (wait_us(r->after_us)) return stop(Q1N1_WTAB_COUNTER, index, r->addr, 0, 0, 0);
    S.next = index + 1;
    return Q1N1_WTAB_OK;
}

static int32_t op_unwind(void)
{
    if (!S.opened) return Q1N1_WTAB_NOT_OPEN;
    if (!S.finished) {
        unwind_all();
        end_line(result_name());
    }
    return S.undo_failed ? Q1N1_WTAB_UNDO_FAILED : Q1N1_WTAB_OK;
}

static const struct q1n1_payload_wtab_ops ops = {Q1N1_WTAB_OPS_MAGIC, Q1N1_WTAB_TABLE_VERSION, sizeof(struct q1n1_payload_wtab_ops), op_open, op_row,
                                                 op_unwind, {0, 0}};

const struct q1n1_payload_wtab_ops *q1n1_wtab_ops(void)
{
    return &ops;
}

static const struct q1n1_wtab_env *attached_env;

void q1n1_wtab_attach(const struct q1n1_wtab_env *env)
{
    attached_env = env;
}

const struct q1n1_wtab_env *q1n1_wtab_attached(void)
{
    return attached_env;
}

void q1n1_wtab_begin(const struct q1n1_wtab_env *env, const struct q1n1_wtab_machine *machine)
{
    zero(&S, sizeof S);
    S.env = env;
    S.machine = *machine;
}

/* ---- Reads ---------------------------------------------------------------------------------------------------------------- */

static const struct q1n1_wtab_window *window_of(uint64_t addr)
{
    for (uint32_t j = 0; S.opened && j < S.hdr->windows; j++) {
        if (addr >= S.win[j].base && addr < (uint64_t)S.win[j].base + S.win[j].size) return &S.win[j];
    }
    return 0;
}

int q1n1_wtab_load_check(uint64_t addr)
{
    const struct q1n1_wtab_window *w = window_of(addr);
    if (!w) return 0;
    int state = S.journal[w->after_row].state;
    int open = !S.stopped && !S.finished && S.window_reads < Q1N1_WTAB_WINDOW_READS_MAX &&
               (state == J_CHECKED || state == J_SKIPPED || state == J_STORED);
    if (open) return 0;
    if (S.window_refusals++ < 2) {
        struct q1n1_payload_line line;
        q1n1_payload_line_begin(&line, "WTAB READ REFUSED");
        q1n1_payload_line_hex(&line, "A", addr);
        q1n1_payload_line_word(&line, S.stopped || S.finished ? "RUN_ENDED" : "GATE_CLOSED");
        put(&line, 1);
    }
    return Q1N1_WTAB_LOAD_E_GATED;
}

int q1n1_wtab_load_done(uint64_t addr)
{
    if (!window_of(addr)) return 0;
    S.window_reads++;
    if (S.env->serror_poll && S.env->serror_poll()) {
        S.serror_seen = 1;
        stop(Q1N1_WTAB_WINDOW_READ, S.next, (uint32_t)addr, 0, 0, 0);
        return Q1N1_WTAB_LOAD_E_GATED;
    }
    return 0;
}

/* ---- The ops of the payload ABI that act on a pointer of the payload ------------------------------------------------------------------------- */

/* ops.hex writes at most `cap` bytes at a destination the payload names, and ops.puts reads a string at an address the payload names. The write table promises that the
 * only device words that change are the rows' words, so a payload may not use these two to store or to read where it likes: ops.load32 already refuses a destination outside
 * the stack (q1n1_payload_load32_check), and these two refuse in the same way. Neither refusal is a stop of the table's run: the op does nothing and says so. */
int q1n1_wtab_hex_ok(const void *dst, uint32_t cap, uint64_t stack_base, uint64_t stack_size)
{
    uint64_t where = (uint64_t)(uintptr_t)dst;
    if (!cap) return 1;
    return where >= stack_base && cap <= stack_size && where - stack_base <= stack_size - cap;
}

int q1n1_wtab_puts_ok(const char *line, uint64_t stack_base, uint64_t stack_size, uint64_t image_base, uint64_t image_size)
{
    uint64_t where = (uint64_t)(uintptr_t)line, room = 0;
    if (where >= stack_base && where - stack_base < stack_size) room = stack_size - (where - stack_base);
    else if (where >= image_base && where - image_base < image_size) room = image_size - (where - image_base);
    for (uint64_t k = 0; k <= Q1N1_PAYLOAD_LINE_MAX; k++) {
        if (k >= room) return 0;
        if (!line[k]) return 1;
    }
    return 1;
}

static void snapshot(void)
{
    struct q1n1_wtab_result *r = &S.last;
    r->opened = S.opened;
    r->stopped = S.stopped;
    r->reason = S.reason;
    r->finished = S.finished;
    r->restored = S.opened && S.finished && !S.undo_failed && !S.irreversible && S.undo_ok == S.undo_needed;
    r->rows_done = S.next;
    r->stores = S.stores;
    r->undos = S.undos;
    r->undo_ok = S.undo_ok;
    r->undo_failed = S.undo_failed;
    r->window_reads = S.window_reads;
    r->lines = S.lines;
    r->dropped = S.dropped;
    r->stop_row = S.stop_row;
}

void q1n1_wtab_finish(struct q1n1_wtab_result *out)
{
    if (S.opened && !S.finished) {
        struct q1n1_payload_line line;
        unsigned in_force = 0;
        for (uint32_t i = 0; i < S.hdr->rows; i++) in_force += S.journal[i].state == J_STORED;
        if (S.hdr->flags & Q1N1_WTAB_F_RESTORE_AT_END) {
            q1n1_payload_line_begin(&line, "WTAB AUTO_UNWIND");
            q1n1_payload_line_dec(&line, "IN_FORCE", in_force);
            put(&line, 1);
            unwind_all();
            end_line(result_name());
        } else {
            S.finished = 1;
            S.undo_needed = in_force;
            end_line("LEFT");
        }
    }
    snapshot();
    if (out) *out = S.last;
}

const struct q1n1_wtab_result *q1n1_wtab_last(void)
{
    snapshot();
    return &S.last;
}

#endif /* Q1N1_SP11_PAYLOAD && Q1N1_SP11_WTAB */
