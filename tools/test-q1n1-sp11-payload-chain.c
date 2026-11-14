/* SPDX-License-Identifier: MIT */
/* Host tests for the payload runner's chain (platform/uefi/sp11-payload-run.c): several payloads called one after
 * the other in one boot. Driven by tools/test-q1n1-sp11-payload.py and tools/test-q1n1-sp11-payload-chain.py under
 * ASan and UBSan. The single-payload sequence is in tools/test-q1n1-sp11-payload-run.c; this is what the chain adds.
 *
 * The fake platform records every line and every call the runner makes into it, in order, and its payloads are
 * ordinary C functions with the payload ABI. The loaded files stand in memory the way the runner records them:
 * a letter per file, P for a payload (LoaderCode, called) and D for data (LoaderData, never called).
 *
 *   order    which payloads are called, in which order, with what, and that data is skipped; the exact lines
 *   verify   a payload that no longer hashes stops the chain at its turn, whoever damaged it, and nothing after it runs
 *   stop     a payload that overran its stack guard stops the chain; what a payload returns does not
 *   budget   the lines and loads of every call start again, and each DONE line has its own numbers
 *   args     every payload gets its own base and size and an argument block rebuilt from nothing
 *   lines    the shape of the lines the runner adds for the chain
 *
 * Nothing here runs at EL2 or on hardware. Evidence: EXPERIMENTAL (host model only). */
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SNAP_PLATFORM_SP11 1
#define Q1N1_SP11_PAYLOAD 1
#include "sp11-payload.h"
#include "sha256.h"

static unsigned checks;
#define CHECK(x) do { \
        if (!(x)) { fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #x); return 1; } \
        checks++; \
    } while (0)

/* ---- The fake platform ---------------------------------------------------------------------------------- */

enum { EV_EMIT, EV_SYNC, EV_CALL, EV_GUARDED };
struct event { int kind; char text[128]; uint64_t a, b, c, d; };
static struct event log_[1024];
static unsigned log_n, guarded_total, data_calls, scramble_guard_after_done0;
static void record(int kind, const char *text, uint64_t a, uint64_t b, uint64_t c, uint64_t d)
{
    if (log_n >= sizeof log_ / sizeof log_[0]) { fprintf(stderr, "FAIL: event log full\n"); exit(2); }
    struct event *e = &log_[log_n++];
    e->kind = kind; e->a = a; e->b = b; e->c = c; e->d = d;
    snprintf(e->text, sizeof e->text, "%s", text ? text : "");
}
static unsigned count_of(int kind) { unsigned n = 0; for (unsigned i = 0; i < log_n; i++) n += log_[i].kind == kind; return n; }
/* The index in the log of the n-th event of a kind; -1 when there are fewer. */
static int nth(int kind, unsigned n)
{
    for (unsigned i = 0; i < log_n; i++) if (log_[i].kind == kind && n-- == 0) return (int)i;
    return -1;
}
static int find(int kind, const char *prefix)
{
    for (unsigned i = 0; i < log_n; i++)
        if (log_[i].kind == kind && !strncmp(log_[i].text, prefix, strlen(prefix))) return (int)i;
    return -1;
}
static unsigned emitted_with(const char *prefix)
{
    unsigned n = 0;
    for (unsigned i = 0; i < log_n; i++) n += log_[i].kind == EV_EMIT && !strncmp(log_[i].text, prefix, strlen(prefix));
    return n;
}

#define MAXF Q1N1_PAYLOAD_MAX_FILES
static struct q1n1_payload_loaded loaded;
static uint8_t *file_mem[MAXF], *stack_mem;
static struct q1n1_preload_cache *table;
static uint64_t (*fn[MAXF])(const struct q1n1_payload_args *);
static unsigned files;

static void fake_emit(const char *line)
{
    record(EV_EMIT, line, 0, 0, 0, 0);
    /* Something between two payloads writes the whole low end of the stack: the next payload must start from armed
     * guard words all the same. */
    if (scramble_guard_after_done0 && !strncmp(line, "PAYLOAD DONE INDEX=0", 20)) memset(stack_mem, 0, 64);
}
static void fake_sync(uint64_t base, uint64_t bytes) { record(EV_SYNC, "", base, bytes, 0, 0); }
static uint64_t fake_call(uint64_t entry, const struct q1n1_payload_args *args, uint64_t top)
{
    unsigned index = MAXF;
    for (unsigned i = 0; i < files; i++) if (loaded.file[i].base == entry) index = i;
    if (index == MAXF) { fprintf(stderr, "FAIL tripwire: called %" PRIx64 ", which is not a loaded file\n", entry); exit(3); }
    if (!q1n1_payload_file_is_code(&loaded.file[index])) data_calls++;
    record(EV_CALL, "", entry, (uint64_t)(uintptr_t)args, top, index);
    return fn[index](args);
}
static int fake_guarded(int kind, uint64_t dst, uint64_t src, uint64_t size)
{
    if (kind != Q1N1_PAYLOAD_G_COPY32) { fprintf(stderr, "FAIL tripwire: the runner asked for a guarded kind %d\n", kind); exit(3); }
    guarded_total++;
    if (log_n < 600) record(EV_GUARDED, "", dst, src, size, 0);
    *(uint32_t *)(uintptr_t)dst = (uint32_t)(src * 2654435761u);
    return 0;
}
static uint64_t fake_counter(void) { return 1000; }
static struct q1n1_payload_env env = {fake_emit, fake_sync, fake_call, fake_guarded, fake_counter};
static const struct q1n1_payload_platform platform = {
    .fb_base = 0xe4800000, .fb_bytes = 0x1518000, .map_base = 0x7000, .map_size = 10896, .map_stride = 48,
    .fb_width = 2880, .fb_height = 1920, .fb_stride = 2880, .fb_format = 1,
};

/* ---- Loaded files in host memory --------------------------------------------------------------------------- */

#define FILE_BYTES(i) (3000u + 100u * (i))
#define GUARD UINT64_C(0x5afe5afe5afe5afe)

/* One file per letter: 'P' is a payload, 'D' is data. Every file has bytes of its own, so no two digests agree. */
static void build(const char *kinds)
{
    for (unsigned i = 0; i < MAXF; i++) { free(file_mem[i]); file_mem[i] = NULL; fn[i] = NULL; }
    free(stack_mem); free(table);
    stack_mem = aligned_alloc(4096, Q1N1_PAYLOAD_STACK_BYTES);
    table = aligned_alloc(4096, 8192);
    memset(stack_mem, 0xa5, Q1N1_PAYLOAD_STACK_BYTES);
    memset(table, 0, 8192);
    memset(&loaded, 0, sizeof loaded);
    files = (unsigned)strlen(kinds);
    loaded.count = files;
    table->magic = Q1N1_CACHE_MAGIC; table->version = 1; table->count = files; table->entry_size = sizeof table->files[0];
    for (unsigned i = 0; i < files; i++) {
        int code = kinds[i] == 'P';
        file_mem[i] = aligned_alloc(4096, 4096);
        memset(file_mem[i], 0, 4096);
        for (unsigned k = 0; k < FILE_BYTES(i); k++) file_mem[i][k] = (uint8_t)(i * 31 + k * 7 + 3);
        struct q1n1_payload_file *f = &loaded.file[i];
        f->base = (uint64_t)(uintptr_t)file_mem[i];
        f->bytes = FILE_BYTES(i);
        f->alloc = 4096;
        f->memory_type = code ? Q1N1_PAYLOAD_TYPE_CODE : Q1N1_PAYLOAD_TYPE_DATA;
        q1n1_sha256(file_mem[i], f->bytes, f->sha256);
        loaded.code_count += code;
        table->files[i].base = f->base;
        table->files[i].allocation = f->alloc;
        table->files[i].file.size = f->bytes;
        memcpy(table->files[i].file.sha256, f->sha256, 32);
        snprintf(table->files[i].file.path, sizeof table->files[i].file.path, "\\SP11\\F%u.%s", i, code ? "BIN" : "DAT");
    }
    loaded.table_base = (uint64_t)(uintptr_t)table;
    loaded.table_alloc = 8192;
    loaded.stack_base = (uint64_t)(uintptr_t)stack_mem;
    loaded.stack_alloc = Q1N1_PAYLOAD_STACK_BYTES;
    snprintf(loaded.note[0], sizeof loaded.note[0], "PAYLOAD LOADED NOTE");
    snprintf(loaded.note[1], sizeof loaded.note[1], "PAYLOAD READY NOTE");
    loaded.notes = 2;
    scramble_guard_after_done0 = 0;
}

static void hash16(unsigned index, char out[17])
{
    const uint8_t *d = loaded.file[index].sha256;
    snprintf(out, 17, "%02X%02X%02X%02X%02X%02X%02X%02X", d[0], d[1], d[2], d[3], d[4], d[5], d[6], d[7]);
}
static void hash16_of(const uint8_t *bytes, uint64_t size, char out[17])
{
    uint8_t d[32];
    q1n1_sha256(bytes, size, d);
    snprintf(out, 17, "%02X%02X%02X%02X%02X%02X%02X%02X", d[0], d[1], d[2], d[3], d[4], d[5], d[6], d[7]);
}

static struct q1n1_payload_result result;
static unsigned ran[16], ran_n;
static struct q1n1_payload_args seen[MAXF];
static int run(void)
{
    log_n = 0; ran_n = 0; guarded_total = 0; data_calls = 0;
    memset(&result, 0x77, sizeof result);
    memset(seen, 0, sizeof seen);
    return q1n1_payload_run(&env, &loaded, &platform, &result);
}

/* ---- Payloads, as C functions ------------------------------------------------------------------------------ */

static unsigned index_of_base(uint64_t base)
{
    for (unsigned i = 0; i < files; i++) if (loaded.file[i].base == base) return i;
    return 99;
}
/* Says who it is, remembers what it was given, returns 0x100 + its index. */
static uint64_t fn_mark(const struct q1n1_payload_args *a)
{
    unsigned i = index_of_base(a->payload_base);
    char text[32];
    ran[ran_n++] = i;
    if (i < MAXF) seen[i] = *a;
    snprintf(text, sizeof text, "MARK %u", i);
    a->ops.puts(text);
    return 0x100 + i;
}
static uint64_t fn_noisy(const struct q1n1_payload_args *a)
{
    ran[ran_n++] = index_of_base(a->payload_base);
    for (unsigned i = 0; i < 45; i++) a->ops.puts("NOISE");
    return 7;
}
static uint64_t fn_loads(const struct q1n1_payload_args *a)
{
    uint32_t *cell = (uint32_t *)(uintptr_t)(a->stack_base + 256);
    unsigned ok = 0, refused = 0;
    ran[ran_n++] = index_of_base(a->payload_base);
    for (unsigned i = 0; i < Q1N1_PAYLOAD_LOADS_MAX + 4; i++) {
        if (a->ops.load32(0x2000 + 4 * (i % 64), cell) == Q1N1_PAYLOAD_LOAD_OK) ok++; else refused++;
    }
    return ((uint64_t)ok << 32) | refused;
}
static uint64_t fn_overflow(const struct q1n1_payload_args *a)
{
    ran[ran_n++] = index_of_base(a->payload_base);
    ((volatile uint64_t *)(uintptr_t)a->stack_base)[1] = 0;     /* ran past the end of its stack */
    return 1;
}
static uint64_t fn_garbage(const struct q1n1_payload_args *a)
{
    ran[ran_n++] = index_of_base(a->payload_base);
    return ~UINT64_C(0);
}
/* Damages another file of the chain: a flip in the bytes of file `damage_file`, or in the digest the table keeps
 * for it when `damage_table` is set. */
static unsigned damage_file, damage_table;
static uint64_t fn_damage(const struct q1n1_payload_args *a)
{
    ran[ran_n++] = index_of_base(a->payload_base);
    if (damage_table) table->files[damage_file].file.sha256[3] ^= 0x10;
    else file_mem[damage_file][5] ^= 0x01;
    return 0;
}
/* Scribbles on its own copy of the arguments, which nothing may carry over to the next payload. */
static uint64_t fn_scribble_args(const struct q1n1_payload_args *a)
{
    struct q1n1_payload_args *mine = (struct q1n1_payload_args *)(uintptr_t)a;
    ran[ran_n++] = index_of_base(a->payload_base);
    seen[index_of_base(a->payload_base)] = *a;
    mine->payload_base = 0x1234; mine->payload_size = 0x5678; mine->magic = 0; mine->stack_base = 0; mine->ops.puts = NULL;
    mine->preload_table = 0; mine->map_base = 0; mine->reserved[2] = 99;
    return 5;
}

static void all_fn(uint64_t (*f)(const struct q1n1_payload_args *))
{
    for (unsigned i = 0; i < MAXF; i++) fn[i] = f;
}
/* Everything that makes a DONE line long: 45 lines (40 kept), 4100 loads (4096 made), an overflow, all ones back. */
static uint64_t fn_worst(const struct q1n1_payload_args *a)
{
    uint32_t *cell = (uint32_t *)(uintptr_t)(a->stack_base + 256);
    ran[ran_n++] = index_of_base(a->payload_base);
    for (unsigned i = 0; i < 45; i++) a->ops.puts("NOISE");
    for (unsigned i = 0; i < Q1N1_PAYLOAD_LOADS_MAX + 4; i++) a->ops.load32(0x2000, cell);
    ((volatile uint64_t *)(uintptr_t)a->stack_base)[0] = 0;
    return ~UINT64_C(0);
}
/* The data files must never run: a payload in their place would say so. */
static uint64_t fn_data_trap(const struct q1n1_payload_args *a)
{
    (void)a;
    fprintf(stderr, "FAIL tripwire: a data file was called\n");
    exit(3);
}

/* The lines the runner emitted from the first one that starts with `prefix`, as a single block, for comparing with
 * what a chain must print. */
static int emitted_equal(const char *const want[], unsigned n)
{
    unsigned seen_n = 0;
    for (unsigned i = 0; i < log_n; i++) {
        if (log_[i].kind != EV_EMIT) continue;
        if (seen_n >= n || strcmp(log_[i].text, want[seen_n])) {
            fprintf(stderr, "emitted line %u: '%s' != '%s'\n", seen_n, log_[i].text, seen_n < n ? want[seen_n] : "(nothing)");
            return 0;
        }
        seen_n++;
    }
    if (seen_n != n) fprintf(stderr, "emitted %u lines, wanted %u\n", seen_n, n);
    return seen_n == n;
}

/* ---- order ----------------------------------------------------------------------------------------------- */

static int suite_order(void)
{
    build("PPP");
    all_fn(fn_mark);
    CHECK(run() == Q1N1_PAYLOAD_RUN_OK && result.status == Q1N1_PAYLOAD_RUN_OK);
    CHECK(result.called == 3 && result.stopped == 0);
    CHECK(ran_n == 3 && ran[0] == 0 && ran[1] == 1 && ran[2] == 2);
    /* Three calls, each preceded by the cache maintenance of its own allocation and followed by its own lines. */
    CHECK(count_of(EV_CALL) == 3 && count_of(EV_SYNC) == 3);
    for (unsigned k = 0; k < 3; k++) {
        int sync = nth(EV_SYNC, k), call = nth(EV_CALL, k);
        char want[64];
        CHECK(log_[sync].a == loaded.file[k].base && log_[sync].b == 4096);
        CHECK(log_[call].a == loaded.file[k].base && log_[call].d == k);
        CHECK(log_[call].c == loaded.stack_base + Q1N1_PAYLOAD_STACK_BYTES && (log_[call].c & 15) == 0);
        char h[17];
        hash16(k, h);
        snprintf(want, sizeof want, "PAYLOAD CALL %u %s", k, h);
        int named = find(EV_EMIT, want);
        CHECK(named > sync && call > named);
        CHECK(result.call[k].index == k && result.call[k].retval == 0x100 + k && result.call[k].stack_ok == 1);
        CHECK(result.call[k].lines == 1 && result.call[k].dropped == 0);
    }
    /* Every line, in order: the notes, then for each payload VERIFY, CALL, its own line and DONE. */
    char h0[17], h1[17], h2[17];
    hash16(0, h0); hash16(1, h1); hash16(2, h2);
    char c0[40], c1[40], c2[40];
    snprintf(c0, sizeof c0, "PAYLOAD CALL 0 %s", h0);
    snprintf(c1, sizeof c1, "PAYLOAD CALL 1 %s", h1);
    snprintf(c2, sizeof c2, "PAYLOAD CALL 2 %s", h2);
    const char *const lines[] = {
        "PAYLOAD LOADED NOTE", "PAYLOAD READY NOTE",
        "PAYLOAD VERIFY=OK", c0, "MARK 0", "PAYLOAD DONE INDEX=0 RETURN=0X100 STACK=OK LOADS=0 FAULTS=0 REFUSED=0 LINES=1 DROPPED=0",
        "PAYLOAD VERIFY=OK", c1, "MARK 1", "PAYLOAD DONE INDEX=1 RETURN=0X101 STACK=OK LOADS=0 FAULTS=0 REFUSED=0 LINES=1 DROPPED=0",
        "PAYLOAD VERIFY=OK", c2, "MARK 2", "PAYLOAD DONE INDEX=2 RETURN=0X102 STACK=OK LOADS=0 FAULTS=0 REFUSED=0 LINES=1 DROPPED=0",
    };
    CHECK(emitted_equal(lines, sizeof lines / sizeof lines[0]));
    CHECK(emitted_with("PAYLOAD CHAIN STOPPED") == 0 && emitted_with("PAYLOAD REFUSED") == 0);
    /* The three payloads are three different files. */
    CHECK(strcmp(h0, h1) && strcmp(h1, h2) && strcmp(h0, h2));

    /* A chain of one is what the single-payload runner printed, with the index and the one DONE line. */
    build("P");
    all_fn(fn_mark);
    CHECK(run() == Q1N1_PAYLOAD_RUN_OK && result.called == 1 && ran_n == 1);

    /* Data between and after payloads is skipped, never called, never synchronised, never counted. */
    build("PDPDP");
    all_fn(fn_mark);
    fn[1] = fn[3] = fn_data_trap;
    CHECK(run() == Q1N1_PAYLOAD_RUN_OK && result.called == 3 && data_calls == 0);
    CHECK(ran_n == 3 && ran[0] == 0 && ran[1] == 2 && ran[2] == 4);
    CHECK(count_of(EV_CALL) == 3 && count_of(EV_SYNC) == 3);
    CHECK(log_[nth(EV_CALL, 0)].d == 0 && log_[nth(EV_CALL, 1)].d == 2 && log_[nth(EV_CALL, 2)].d == 4);
    CHECK(log_[nth(EV_SYNC, 0)].a == loaded.file[0].base && log_[nth(EV_SYNC, 1)].a == loaded.file[2].base &&
          log_[nth(EV_SYNC, 2)].a == loaded.file[4].base);
    CHECK(result.call[0].index == 0 && result.call[1].index == 2 && result.call[2].index == 4);
    CHECK(emitted_with("PAYLOAD DONE INDEX=0") == 1 && emitted_with("PAYLOAD DONE INDEX=2") == 1 &&
          emitted_with("PAYLOAD DONE INDEX=4") == 1 && emitted_with("PAYLOAD DONE INDEX=1") == 0 && emitted_with("PAYLOAD DONE INDEX=3") == 0);
    CHECK(emitted_with("PAYLOAD CALL 1 ") == 0 && emitted_with("PAYLOAD CALL 3 ") == 0);
    /* The data file is the table's entry 1 and is still verified in the table, but its bytes are not hashed. */
    file_mem[1][100] ^= 0xff;
    CHECK(run() == Q1N1_PAYLOAD_RUN_OK && result.called == 3);

    /* A chain that begins with data (the loader never makes one) still calls only what is code. */
    build("DPD");
    all_fn(fn_mark);
    fn[0] = fn[2] = fn_data_trap;
    CHECK(run() == Q1N1_PAYLOAD_RUN_OK && result.called == 1 && ran_n == 1 && ran[0] == 1 && data_calls == 0);
    /* Nothing but data is refused outright. */
    build("DD");
    all_fn(fn_data_trap);
    CHECK(run() == Q1N1_PAYLOAD_RUN_NO_PAYLOAD && count_of(EV_CALL) == 0 && count_of(EV_SYNC) == 0);
    CHECK(find(EV_EMIT, "PAYLOAD REFUSED=NO_PAYLOAD") >= 0 && result.called == 0);

    /* Five payloads, the most a stick holds: all run, in order, and the runner's own lines stay few. */
    build("PPPPP");
    all_fn(fn_mark);
    CHECK(run() == Q1N1_PAYLOAD_RUN_OK && result.called == 5);
    for (unsigned k = 0; k < 5; k++) CHECK(ran[k] == k && result.call[k].index == k);
    CHECK(log_n - count_of(EV_SYNC) - count_of(EV_CALL) == 2 + 5 * 4);      /* two notes and four lines for each payload */
    return 0;
}

/* ---- verify ---------------------------------------------------------------------------------------------- */

static int suite_verify(void)
{
    /* A payload whose bytes changed before the chain started stops it at its turn: the ones before it ran, the ones
     * after it did not, and the stop is named with both digests. */
    for (unsigned bad = 0; bad < 3; bad++) {
        build("PPP");
        all_fn(fn_mark);
        char want[17], have[17];
        hash16(bad, want);
        file_mem[bad][FILE_BYTES(bad) - 1] ^= 0x80;
        hash16_of(file_mem[bad], FILE_BYTES(bad), have);
        CHECK(run() == Q1N1_PAYLOAD_RUN_HASH && result.status == Q1N1_PAYLOAD_RUN_HASH);
        CHECK(result.stopped == bad && result.called == bad && ran_n == bad);
        for (unsigned k = 0; k < bad; k++) CHECK(ran[k] == k);
        CHECK(count_of(EV_CALL) == bad && count_of(EV_SYNC) == bad);
        char refused[100], stopped[80];
        snprintf(refused, sizeof refused, "PAYLOAD REFUSED=HASH_AT_EL2 INDEX=%u WANT=%s HAVE=%s", bad, want, have);
        snprintf(stopped, sizeof stopped, "PAYLOAD CHAIN STOPPED INDEX=%u REASON=HASH_AT_EL2", bad);
        int r = find(EV_EMIT, refused), s = find(EV_EMIT, stopped);
        CHECK(strcmp(want, have));
        CHECK(r >= 0 && s == r + 1);
        CHECK(!strcmp(log_[log_n - 1].text, stopped));                      /* the stop is the last word */
        CHECK(emitted_with("PAYLOAD CALL ") == bad && emitted_with("PAYLOAD VERIFY=OK") == bad);
        CHECK(emitted_with("PAYLOAD DONE") == bad);
        for (unsigned k = bad; k < 3; k++) { char name[40]; snprintf(name, sizeof name, "MARK %u", k); CHECK(find(EV_EMIT, name) < 0); }
    }

    /* Damage done by an earlier payload, while the chain runs, is found at the damaged payload's turn: the next one
     * and a later one alike, and a payload that damages a file that is not called again changes nothing. */
    build("PPP");
    all_fn(fn_mark);
    fn[0] = fn_damage;
    damage_file = 1; damage_table = 0;
    CHECK(run() == Q1N1_PAYLOAD_RUN_HASH && result.stopped == 1 && result.called == 1 && ran_n == 1);
    CHECK(emitted_with("PAYLOAD REFUSED=HASH_AT_EL2 INDEX=1 WANT=") == 1 && emitted_with("PAYLOAD CHAIN STOPPED INDEX=1 REASON=HASH_AT_EL2") == 1);
    build("PPP");
    all_fn(fn_mark);
    fn[0] = fn_damage;
    damage_file = 2; damage_table = 0;
    CHECK(run() == Q1N1_PAYLOAD_RUN_HASH && result.stopped == 2 && result.called == 2 && ran_n == 2 && ran[1] == 1);
    build("PPP");
    all_fn(fn_mark);
    fn[1] = fn_damage;
    damage_file = 0; damage_table = 0;
    CHECK(run() == Q1N1_PAYLOAD_RUN_OK && result.called == 3);           /* payload 0 already ran: nothing looks at it again */

    /* The table is compared as a whole before each call: damage to the entry of a data file, which no payload is
     * hashed for, still stops the chain at the next payload. The same for the entry of the payload that is next. */
    for (unsigned entry = 0; entry < 2; entry++) {
        build("PDP");
        all_fn(fn_mark);
        fn[0] = fn_damage;
        fn[1] = fn_data_trap;
        damage_file = entry == 0 ? 1 : 2; damage_table = 1;
        CHECK(run() == Q1N1_PAYLOAD_RUN_HASH && result.stopped == 2 && result.called == 1 && ran_n == 1);
        CHECK(emitted_with("PAYLOAD CHAIN STOPPED INDEX=2 REASON=HASH_AT_EL2") == 1);
    }
    /* Damaged table fields before the chain starts: no payload is called at all. */
    struct { const char *what; unsigned offset; } fields[] = {
        {"digest of a data file", (unsigned)offsetof(struct q1n1_preload_cache, files[1].file.sha256) + 9},
        {"base of a data file", (unsigned)offsetof(struct q1n1_preload_cache, files[1].base)},
        {"size of a data file", (unsigned)offsetof(struct q1n1_preload_cache, files[1].file.size)},
        {"allocation of a data file", (unsigned)offsetof(struct q1n1_preload_cache, files[1].allocation)},
        {"count", (unsigned)offsetof(struct q1n1_preload_cache, count)},
        {"digest of the last payload", (unsigned)offsetof(struct q1n1_preload_cache, files[2].file.sha256)},
    };
    for (unsigned i = 0; i < sizeof fields / sizeof fields[0]; i++) {
        build("PDP");
        all_fn(fn_mark);
        fn[1] = fn_data_trap;
        ((uint8_t *)table)[fields[i].offset] ^= 0x08;
        int rc = run();
        if (rc != Q1N1_PAYLOAD_RUN_HASH) fprintf(stderr, "table fault: %s was not caught\n", fields[i].what);
        CHECK(rc == Q1N1_PAYLOAD_RUN_HASH && result.stopped == 0 && result.called == 0 && count_of(EV_CALL) == 0);
    }
    /* The record the runner keeps is checked against the table too: a payload that is not the one that was measured. */
    build("PPP");
    all_fn(fn_mark);
    loaded.file[1].sha256[0] ^= 1;
    CHECK(run() == Q1N1_PAYLOAD_RUN_HASH && result.stopped == 0 && result.called == 0);
    return 0;
}

/* ---- stop ------------------------------------------------------------------------------------------------ */

static int suite_stop(void)
{
    /* A payload that ran past its stack ends the chain: its DONE line says so, the stop line follows, the next
     * payload is not called, and the status says where. */
    build("PPP");
    all_fn(fn_mark);
    fn[1] = fn_overflow;
    CHECK(run() == Q1N1_PAYLOAD_RUN_STACK && result.status == Q1N1_PAYLOAD_RUN_STACK);
    CHECK(result.stopped == 1 && result.called == 2 && ran_n == 2 && ran[0] == 0 && ran[1] == 1);
    CHECK(result.call[1].stack_ok == 0 && result.call[0].stack_ok == 1);
    CHECK(count_of(EV_CALL) == 2 && emitted_with("PAYLOAD CALL 2 ") == 0 && emitted_with("MARK 2") == 0);
    int done = find(EV_EMIT, "PAYLOAD DONE INDEX=1 RETURN=0X1 STACK=OVERFLOW "), stop = find(EV_EMIT, "PAYLOAD CHAIN STOPPED INDEX=1 REASON=STACK_OVERFLOW");
    CHECK(done >= 0 && stop == done + 1 && (unsigned)stop == log_n - 1);
    CHECK(emitted_with("PAYLOAD DONE INDEX=0 RETURN=0X100 STACK=OK ") == 1);
    /* The first, the last and the only payload overrunning stop the chain just the same. */
    build("PPP");
    all_fn(fn_mark);
    fn[0] = fn_overflow;
    CHECK(run() == Q1N1_PAYLOAD_RUN_STACK && result.stopped == 0 && result.called == 1 && ran_n == 1);
    build("PPP");
    all_fn(fn_mark);
    fn[2] = fn_overflow;
    CHECK(run() == Q1N1_PAYLOAD_RUN_STACK && result.stopped == 2 && result.called == 3);
    CHECK(emitted_with("PAYLOAD CHAIN STOPPED INDEX=2 REASON=STACK_OVERFLOW") == 1);

    /* What a payload returns never stops the chain: all ones, the argument-error value, zero. */
    build("PPP");
    all_fn(fn_garbage);
    fn[1] = fn_mark;
    CHECK(run() == Q1N1_PAYLOAD_RUN_OK && result.called == 3 && ran_n == 3);
    CHECK(result.call[0].retval == ~UINT64_C(0) && result.call[1].retval == 0x101 && result.call[2].retval == ~UINT64_C(0));
    CHECK(emitted_with("PAYLOAD DONE INDEX=0 RETURN=0XFFFFFFFFFFFFFFFF STACK=OK ") == 1);
    CHECK(emitted_with("PAYLOAD CHAIN STOPPED") == 0);
    build("PP");
    all_fn(fn_garbage);
    CHECK(run() == Q1N1_PAYLOAD_RUN_OK && result.called == 2);

    /* Every call starts from armed guard words: here the whole low end of the stack is wiped between payload 0 and
     * payload 1, which says nothing about payload 1, and it must not be blamed for it. */
    build("PPP");
    all_fn(fn_mark);
    scramble_guard_after_done0 = 1;
    CHECK(run() == Q1N1_PAYLOAD_RUN_OK && result.called == 3 && result.call[1].stack_ok == 1 && result.call[2].stack_ok == 1);
    CHECK(emitted_with("PAYLOAD DONE INDEX=1 RETURN=0X101 STACK=OK ") == 1);
    CHECK(((uint64_t *)stack_mem)[0] == GUARD && ((uint64_t *)stack_mem)[1] == GUARD);
    return 0;
}

/* ---- budget ---------------------------------------------------------------------------------------------- */

static int suite_budget(void)
{
    /* Two payloads that print 45 lines each: each keeps 40 and drops 5, the second no less than the first. */
    build("PPPP");
    fn[0] = fn[1] = fn_noisy;
    fn[2] = fn[3] = fn_loads;
    CHECK(run() == Q1N1_PAYLOAD_RUN_OK && result.called == 4);
    CHECK(emitted_with("NOISE") == 2 * Q1N1_PAYLOAD_LINES_MAX);
    CHECK(result.call[0].lines == 40 && result.call[0].dropped == 5 && result.call[1].lines == 40 && result.call[1].dropped == 5);
    CHECK(emitted_with("PAYLOAD DONE INDEX=0 RETURN=0X7 STACK=OK LOADS=0 FAULTS=0 REFUSED=0 LINES=40 DROPPED=5") == 1);
    CHECK(emitted_with("PAYLOAD DONE INDEX=1 RETURN=0X7 STACK=OK LOADS=0 FAULTS=0 REFUSED=0 LINES=40 DROPPED=5") == 1);
    /* Two payloads that load 4100 times: each gets its 4096 and is refused the 4, the second no less than the first. */
    CHECK(result.call[2].loads == Q1N1_PAYLOAD_LOADS_MAX && result.call[2].refused == 4);
    CHECK(result.call[3].loads == Q1N1_PAYLOAD_LOADS_MAX && result.call[3].refused == 4 && result.call[3].lines == 0);
    CHECK(guarded_total == 2 * Q1N1_PAYLOAD_LOADS_MAX);
    CHECK(result.call[2].retval == (((uint64_t)Q1N1_PAYLOAD_LOADS_MAX << 32) | 4) && result.call[3].retval == result.call[2].retval);
    CHECK(emitted_with("PAYLOAD DONE INDEX=3 RETURN=0X100000000004 STACK=OK LOADS=4096 FAULTS=0 REFUSED=4 LINES=0 DROPPED=0") == 1);
    /* A quiet payload after a noisy one does not inherit its numbers. */
    build("PPP");
    fn[0] = fn_noisy;
    fn[1] = fn_mark;
    fn[2] = fn_loads;
    CHECK(run() == Q1N1_PAYLOAD_RUN_OK && result.called == 3);
    CHECK(result.call[1].lines == 1 && result.call[1].dropped == 0 && result.call[1].loads == 0 && result.call[1].refused == 0);
    CHECK(result.call[2].lines == 0 && result.call[2].dropped == 0 && result.call[2].loads == Q1N1_PAYLOAD_LOADS_MAX);
    CHECK(emitted_with("PAYLOAD DONE INDEX=1 RETURN=0X101 STACK=OK LOADS=0 FAULTS=0 REFUSED=0 LINES=1 DROPPED=0") == 1);
    /* The runner's own lines are not charged to any payload's budget. */
    CHECK(emitted_with("PAYLOAD VERIFY=OK") == 3 && emitted_with("PAYLOAD CALL ") == 3 && emitted_with("PAYLOAD DONE ") == 3);
    return 0;
}

/* ---- args ------------------------------------------------------------------------------------------------ */

static int suite_args(void)
{
    build("PDPP");
    all_fn(fn_mark);
    fn[1] = fn_data_trap;
    fn[0] = fn_scribble_args;
    CHECK(run() == Q1N1_PAYLOAD_RUN_OK && result.called == 3);
    const unsigned code[3] = {0, 2, 3};
    for (unsigned n = 0; n < 3; n++) {
        const struct q1n1_payload_args *a = &seen[code[n]];
        unsigned i = code[n];
        /* ABI version 1, byte for byte what it was: magic, version, size, then this payload's own base and size. */
        CHECK(a->magic == Q1N1_PAYLOAD_ABI_MAGIC && a->version == 1 && a->size == 192 && a->size == sizeof *a);
        CHECK(a->payload_base == loaded.file[i].base && a->payload_size == FILE_BYTES(i));
        CHECK(a->fb_base == platform.fb_base && a->fb_bytes == platform.fb_bytes);
        CHECK(a->fb_width == 2880 && a->fb_height == 1920 && a->fb_stride == 2880 && a->fb_format == 1);
        CHECK(a->map_base == 0x7000 && a->map_size == 10896 && a->map_stride == 48);
        CHECK(a->preload_table == loaded.table_base && a->preload_size == sizeof(struct q1n1_preload_cache));
        CHECK(a->stack_base == loaded.stack_base && a->stack_size == Q1N1_PAYLOAD_STACK_BYTES);
        CHECK(a->ops.puts && a->ops.hex && a->ops.load32 && a->ops.counter);
        for (unsigned k = 0; k < 5; k++) CHECK(a->reserved[k] == 0);
        /* This payload's entry in the table is the one whose base is its payload_base. */
        const struct q1n1_preload_cache *cache = (const void *)(uintptr_t)a->preload_table;
        CHECK(cache->files[i].base == a->payload_base && q1n1_preload_verify(cache, i) == 1);
    }
    /* Apart from the base and the size nothing differs from one payload to the next, and payload 0 scribbling on its
     * own copy changed nothing for the others. */
    struct q1n1_payload_args one = seen[2], two = seen[3];
    one.payload_base = two.payload_base = 0;
    one.payload_size = two.payload_size = 0;
    CHECK(!memcmp(&one, &two, sizeof one));
    CHECK(seen[0].payload_base == loaded.file[0].base && seen[2].magic == Q1N1_PAYLOAD_ABI_MAGIC);
    CHECK(seen[2].payload_base != seen[3].payload_base && seen[2].payload_size != seen[3].payload_size);
    return 0;
}

/* ---- lines ----------------------------------------------------------------------------------------------- */

static int in_font(const char *text)
{
    for (; *text; text++)
        if (!((*text >= 'A' && *text <= 'Z') || (*text >= '0' && *text <= '9') || strchr(" :-./=?()_", *text))) return 0;
    return 1;
}

static int suite_lines(void)
{
    /* Every line the runner adds is in the page font and within the cap, whatever came back. */
    build("PPPPP");
    fn[0] = fn_noisy; fn[1] = fn_garbage; fn[2] = fn_loads; fn[3] = fn_overflow; fn[4] = fn_mark;
    CHECK(run() == Q1N1_PAYLOAD_RUN_STACK && result.stopped == 3 && result.called == 4);
    for (unsigned i = 0; i < log_n; i++) {
        if (log_[i].kind != EV_EMIT) continue;
        CHECK(strlen(log_[i].text) <= Q1N1_PAYLOAD_LINE_MAX && in_font(log_[i].text));
    }
    /* The chain is named once, and only when it stopped. */
    CHECK(emitted_with("PAYLOAD CHAIN STOPPED") == 1 && emitted_with("PAYLOAD CHAIN STOPPED INDEX=3 REASON=STACK_OVERFLOW") == 1);
    /* Three runner lines for each payload that ran, besides the two notes. */
    unsigned runner = emitted_with("PAYLOAD VERIFY=OK") + emitted_with("PAYLOAD CALL ") + emitted_with("PAYLOAD DONE ");
    CHECK(runner == 3 * 4);
    /* No old line is left. */
    CHECK(emitted_with("PAYLOAD RETURN=") == 0 && emitted_with("PAYLOAD STACK=") == 0 && emitted_with("PAYLOAD OPS") == 0);
    /* The worst DONE line there can be: a full-width return, an overflow and the largest counters. It is cut at the cap
     * and never runs past it (the tail of DROPPED is what the cap costs), and the chain stops after it. */
    build("PP");
    fn[0] = fn_worst;
    fn[1] = fn_mark;
    CHECK(run() == Q1N1_PAYLOAD_RUN_STACK && result.called == 1 && result.call[0].dropped == 5);
    int worst = find(EV_EMIT, "PAYLOAD DONE INDEX=0 ");
    CHECK(worst >= 0 && strlen(log_[worst].text) == Q1N1_PAYLOAD_LINE_MAX);
    CHECK(!strncmp(log_[worst].text, "PAYLOAD DONE INDEX=0 RETURN=0XFFFFFFFFFFFFFFFF STACK=OVERFLOW LOADS=4096 FAULTS=0 REFUSED=4 LINES=40", 100));
    CHECK(in_font(log_[worst].text));
    return 0;
}

/* The numbers docs/SP11-PAYLOAD.md plans a chain's page with, measured rather than copied: the lines the runner adds for
 * each payload that ran (payloads that print nothing, in chains of one to five), and the rows of the panel region on the
 * unit's 2880x1920 panel (as the planner's own test places it) and in the least layout. Run as `lines-report`;
 * tools/test-q1n1-sp11-payload-chain.py compares the planning table of the document with its output. */
static uint64_t fn_silent(const struct q1n1_payload_args *a)
{
    ran[ran_n++] = index_of_base(a->payload_base);
    return 0;
}
static int report_lines(void)
{
    unsigned per_payload = 0;
    for (unsigned n = 1; n <= MAXF; n++) {
        char kinds[MAXF + 1];
        memset(kinds, 'P', n);
        kinds[n] = 0;
        build(kinds);
        all_fn(fn_silent);
        if (run() != Q1N1_PAYLOAD_RUN_OK) return 1;
        unsigned added = count_of(EV_EMIT) - loaded.notes;      /* the notes are replayed first and are not the runner's */
        if (n == 1) per_payload = added;
        if (added != per_payload * n) return 1;
    }
    struct q1n1_payload_region unit;
    q1n1_payload_region_place(2880, 1920, 3, 20, &unit);
    printf("RUNNER_LINES_PER_PAYLOAD=%u UNIT_ROWS=%u STOCK_ROWS=%u\n", per_payload, (unsigned)unit.rows,
           (unsigned)Q1N1_PAYLOAD_REGION_LINES);
    return 0;
}

int main(int argc, char **argv)
{
    static const struct { const char *name; int (*run)(void); } suites[] = {
        {"order", suite_order}, {"verify", suite_verify}, {"stop", suite_stop}, {"budget", suite_budget},
        {"args", suite_args}, {"lines", suite_lines},
    };
    if (argc > 1 && !strcmp(argv[1], "lines-report")) return report_lines();
    unsigned ran_suites = 0;
    for (unsigned i = 0; i < sizeof suites / sizeof suites[0]; i++) {
        if (argc > 1 && strcmp(argv[1], "all") && strcmp(argv[1], suites[i].name)) continue;
        if (suites[i].run()) { fprintf(stderr, "FAIL: suite %s\n", suites[i].name); return 1; }
        ran_suites++;
    }
    printf("PASS: %u payload chain suites, %u checks\n", ran_suites, checks);
    return 0;
}
