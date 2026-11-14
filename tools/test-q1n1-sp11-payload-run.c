/* SPDX-License-Identifier: MIT */
/* Host tests for the payload runner's EL2 half (platform/uefi/sp11-payload-run.c) against a fake platform.
 * Driven by tools/test-q1n1-sp11-payload.py under ASan and UBSan.
 *
 * The fake platform records every emitted line and every call the runner makes into it, in order, and
 * its "payloads" are ordinary C functions with the payload ABI, so the order of events is what is checked:
 * the second hash before the cache maintenance before the line that names the call before the call. A
 * payload that is not verified is never called.
 *
 *   order      the sequence of lines and calls for a good payload, and what the call is given
 *   verify     every way the payload, the table and the runner's own record can disagree after the bounce
 *   ops        puts (the font, the cap, the budget), hex, counter, and load32 and its policy
 *   guard      the stack guard words and what the runner says afterwards
 *   args       every field of the argument block a payload receives
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

enum { EV_EMIT, EV_SYNC, EV_CALL, EV_GUARDED, EV_COUNTER };
struct event { int kind; char text[128]; uint64_t a, b, c, d; };
static struct event log_[512];
static unsigned log_n;
static void record(int kind, const char *text, uint64_t a, uint64_t b, uint64_t c, uint64_t d)
{
    if (log_n >= sizeof log_ / sizeof log_[0]) { fprintf(stderr, "FAIL: event log full\n"); exit(2); }
    struct event *e = &log_[log_n++];
    e->kind = kind; e->a = a; e->b = b; e->c = c; e->d = d;
    snprintf(e->text, sizeof e->text, "%s", text ? text : "");
}
static unsigned count_of(int kind) { unsigned n = 0; for (unsigned i = 0; i < log_n; i++) n += log_[i].kind == kind; return n; }
/* The index of the first event of this kind whose text starts with `prefix`; -1 when none. */
static int find(int kind, const char *prefix)
{
    for (unsigned i = 0; i < log_n; i++)
        if (log_[i].kind == kind && !strncmp(log_[i].text, prefix, strlen(prefix))) return (int)i;
    return -1;
}
static int find_kind(int kind)
{
    for (unsigned i = 0; i < log_n; i++) if (log_[i].kind == kind) return (int)i;
    return -1;
}

static uint64_t fault_addr = 0xdead0000, counter_value;
static unsigned guarded_calls;
static uint64_t (*payload_fn)(const struct q1n1_payload_args *);

static void fake_emit(const char *line) { record(EV_EMIT, line, 0, 0, 0, 0); }
static void fake_sync(uint64_t base, uint64_t bytes) { record(EV_SYNC, "", base, bytes, 0, 0); }
static uint64_t fake_call(uint64_t entry, const struct q1n1_payload_args *args, uint64_t top)
{
    record(EV_CALL, "", entry, (uint64_t)(uintptr_t)args, top, 0);
    return payload_fn(args);
}
static int fake_guarded(int kind, uint64_t dst, uint64_t src, uint64_t size)
{
    if (kind != Q1N1_PAYLOAD_G_COPY32) { fprintf(stderr, "FAIL tripwire: the runner asked for a guarded kind %d\n", kind); exit(3); }
    guarded_calls++;
    if (log_n < 300) record(EV_GUARDED, "", dst, src, size, 0);   /* the budget test makes thousands */
    if (src == fault_addr) return 1;
    *(uint32_t *)(uintptr_t)dst = (uint32_t)(src * 2654435761u);
    return 0;
}
static uint64_t fake_counter(void) { record(EV_COUNTER, "", 0, 0, 0, 0); return counter_value += 1000; }
static struct q1n1_payload_env env = {fake_emit, fake_sync, fake_call, fake_guarded, fake_counter};

static const struct q1n1_payload_platform platform = {
    .fb_base = 0xe4800000, .fb_bytes = 0x1518000, .map_base = 0x7000, .map_size = 10896, .map_stride = 48,
    .fb_width = 2880, .fb_height = 1920, .fb_stride = 2880, .fb_format = 1,
};

/* ---- A loaded payload in host memory ---------------------------------------------------------------------- */

static struct q1n1_payload_loaded loaded;
static uint8_t *payload_mem, *stack_mem;
static struct q1n1_preload_cache *table;
#define PAYLOAD_BYTES 3000u

static void make_loaded(void)
{
    free(payload_mem); free(stack_mem); free(table);
    payload_mem = aligned_alloc(4096, 4096);
    stack_mem = aligned_alloc(4096, Q1N1_PAYLOAD_STACK_BYTES);
    table = aligned_alloc(4096, 8192);
    memset(payload_mem, 0, 4096);
    for (unsigned i = 0; i < PAYLOAD_BYTES; i++) payload_mem[i] = (uint8_t)(i * 7 + 3);
    memset(stack_mem, 0xa5, Q1N1_PAYLOAD_STACK_BYTES);
    memset(table, 0, 8192);
    memset(&loaded, 0, sizeof loaded);
    loaded.count = 1;
    loaded.code_count = 1;
    loaded.file[0].base = (uint64_t)(uintptr_t)payload_mem;
    loaded.file[0].bytes = PAYLOAD_BYTES;
    loaded.file[0].alloc = 4096;
    loaded.file[0].memory_type = 1;
    q1n1_sha256(payload_mem, PAYLOAD_BYTES, loaded.file[0].sha256);
    loaded.table_base = (uint64_t)(uintptr_t)table;
    loaded.table_alloc = 8192;
    loaded.stack_base = (uint64_t)(uintptr_t)stack_mem;
    loaded.stack_alloc = Q1N1_PAYLOAD_STACK_BYTES;
    table->magic = Q1N1_CACHE_MAGIC; table->version = 1; table->count = 1; table->entry_size = sizeof table->files[0];
    table->files[0].base = loaded.file[0].base;
    table->files[0].allocation = 4096;
    table->files[0].file.size = PAYLOAD_BYTES;
    memcpy(table->files[0].file.sha256, loaded.file[0].sha256, 32);
    snprintf(table->files[0].file.path, sizeof table->files[0].file.path, "\\SP11\\STATE.BIN");
    snprintf(loaded.note[0], sizeof loaded.note[0], "PAYLOAD LOADED INDEX=0");
    snprintf(loaded.note[1], sizeof loaded.note[1], "PAYLOAD READY FILES=1 RANGES=4");
    loaded.notes = 2;
    log_n = 0;
    counter_value = 0;
}

static struct q1n1_payload_result result;
static int run(void)
{
    log_n = 0;
    guarded_calls = 0;
    memset(&result, 0x77, sizeof result);
    return q1n1_payload_run(&env, &loaded, &platform, &result);
}

/* ---- Payloads, as C functions -------------------------------------------------------------------------------- */

static struct q1n1_payload_args seen;
static unsigned seen_calls;
static uint64_t seen_counters[2];
static uint64_t payload_hello(const struct q1n1_payload_args *a)
{
    seen = *a;
    seen_calls++;
    a->ops.puts("PAYLOAD HELLO ONE");
    char text[32];
    a->ops.hex(text, sizeof text, 0xabc);
    a->ops.puts(text);
    seen_counters[0] = a->ops.counter();
    seen_counters[1] = a->ops.counter();
    return 0x1234;
}
static uint64_t payload_noisy(const struct q1n1_payload_args *a)
{
    for (unsigned i = 0; i < 50; i++) a->ops.puts("PAYLOAD NOISE");
    return 7;
}
static uint64_t payload_all_ones(const struct q1n1_payload_args *a)
{
    (void)a;
    return ~UINT64_C(0);
}
static uint64_t payload_scribble(const struct q1n1_payload_args *a)
{
    ((volatile uint64_t *)(uintptr_t)a->stack_base)[1] = 0;      /* ran past the end of its stack */
    return 0;
}
static uint64_t payload_text(const struct q1n1_payload_args *a)
{
    char longline[200];
    memset(longline, 'x', sizeof longline - 1);
    longline[sizeof longline - 1] = 0;
    a->ops.puts("lower Case, [brackets] \t tab \xc3\xa9");
    a->ops.puts(longline);
    a->ops.puts(NULL);
    a->ops.puts("");
    return 0;
}

#define LOAD_CASES 20
static int32_t load_rc[LOAD_CASES];
static uint32_t load_val[LOAD_CASES];
static uint64_t payload_load32(const struct q1n1_payload_args *a)
{
    /* On the real stack these are locals; under test the payload runs on the host's stack, so the cells
     * that stand for "locals" are placed inside the fake payload stack, and `outside` is a real local,
     * which the policy must refuse because it is not in that stack. */
    uint32_t *cell = (uint32_t *)(uintptr_t)(a->stack_base + 256);
    cell[0] = cell[1] = cell[2] = cell[3] = 0x11111111;
    uint64_t stack_end = a->stack_base + a->stack_size;
    uint32_t *top = (uint32_t *)(uintptr_t)(stack_end - 4), *bottom = (uint32_t *)(uintptr_t)a->stack_base;
    uint32_t outside = 0x22222222;
    unsigned n = 0;
#define TRY(addr, out) do { load_rc[n] = a->ops.load32((addr), (out)); n++; } while (0)
    TRY(0x1000, &cell[0]);                                       /* 0: fine */
    load_val[0] = cell[0];
    TRY(0x1002, &cell[1]);                                       /* 1: address misaligned */
    TRY(0x1000, (uint32_t *)((uint8_t *)&cell[1] + 1));          /* 2: destination misaligned */
    TRY(0x1000, NULL);                                           /* 3: no destination */
    TRY(0x1000, &outside);                                       /* 4: not in the stack (a local) */
    TRY(0x1000, top);                                            /* 5: the last word of the stack is inside */
    TRY(0x1000, bottom);                                         /* 6: the first word too */
    ((volatile uint64_t *)(uintptr_t)a->stack_base)[0] = UINT64_C(0x5afe5afe5afe5afe);   /* it is the runner's guard: put it back */
    TRY(0x1000, (uint32_t *)(uintptr_t)stack_end);               /* 7: one past the stack */
    TRY(0x1000, (uint32_t *)(uintptr_t)(stack_end - 2));         /* 8: straddles the end (and is misaligned) */
    TRY(0x1000, (uint32_t *)(uintptr_t)(a->stack_base - 4));     /* 9: one word before the stack */
    TRY(UINT64_C(1) << 48, &cell[2]);                            /* 10: beyond the address space */
    TRY((UINT64_C(1) << 48) - 4, &cell[2]);                      /* 11: its last word */
    TRY(0xfffffffffffffffcull, &cell[2]);                        /* 12: the top of the address space */
    TRY(fault_addr, &cell[3]);                                   /* 13: the guarded read aborts */
    load_val[13] = cell[3];
    load_val[1] = cell[1];
    load_val[4] = outside;
    return n;
}
static uint64_t payload_budget(const struct q1n1_payload_args *a)
{
    uint32_t *cell = (uint32_t *)(uintptr_t)(a->stack_base + 256);
    unsigned ok = 0, refused = 0;
    int32_t last = 0;
    for (unsigned i = 0; i < Q1N1_PAYLOAD_LOADS_MAX + 10; i++) {
        last = a->ops.load32(0x2000 + 4 * (i % 64), cell);
        if (last == Q1N1_PAYLOAD_LOAD_OK) ok++; else refused++;
    }
    load_rc[0] = last;
    return ((uint64_t)ok << 32) | refused;
}

/* ---- order ---------------------------------------------------------------------------------------------------- */

static int suite_order(void)
{
    make_loaded();
    payload_fn = payload_hello;
    seen_calls = 0;
    CHECK(run() == Q1N1_PAYLOAD_RUN_OK && result.status == Q1N1_PAYLOAD_RUN_OK);
    CHECK(seen_calls == 1 && result.call[0].retval == 0x1234 && result.call[0].stack_ok == 1);
    CHECK(result.called == 1 && result.call[0].index == 0);
    int notes0 = find(EV_EMIT, "PAYLOAD LOADED"), ready = find(EV_EMIT, "PAYLOAD READY"), verify = find(EV_EMIT, "PAYLOAD VERIFY=OK");
    int sync = find_kind(EV_SYNC), call_line = find(EV_EMIT, "PAYLOAD CALL "), call = find_kind(EV_CALL);
    int hello = find(EV_EMIT, "PAYLOAD HELLO ONE"), done = find(EV_EMIT, "PAYLOAD DONE ");
    CHECK(notes0 == 0 && ready == 1);                           /* the notes from before the bounce come first */
    CHECK(verify > ready && sync > verify && call_line > sync && call > call_line);
    CHECK(hello > call && done > hello);
    /* The old RETURN, STACK and OPS lines are one line now, the last the runner prints for the payload. */
    CHECK(find(EV_EMIT, "PAYLOAD RETURN=") < 0 && find(EV_EMIT, "PAYLOAD STACK=") < 0 && find(EV_EMIT, "PAYLOAD OPS ") < 0);
    CHECK(count_of(EV_CALL) == 1 && count_of(EV_SYNC) == 1);
    /* The cache maintenance is of the whole allocation and the call is to its first byte. */
    CHECK(log_[sync].a == loaded.file[0].base && log_[sync].b == 4096);
    CHECK(log_[call].a == loaded.file[0].base);
    CHECK(log_[call].c == loaded.stack_base + Q1N1_PAYLOAD_STACK_BYTES && (log_[call].c & 15) == 0);
    /* The line that names the call carries the payload's index and the hash prefix of the file. */
    uint8_t digest[32];
    q1n1_sha256(payload_mem, PAYLOAD_BYTES, digest);
    char want[64];
    snprintf(want, sizeof want, "PAYLOAD CALL 0 %02X%02X%02X%02X%02X%02X%02X%02X", digest[0], digest[1], digest[2], digest[3],
             digest[4], digest[5], digest[6], digest[7]);
    CHECK(!strcmp(log_[call_line].text, want));
    CHECK(!strcmp(log_[done].text, "PAYLOAD DONE INDEX=0 RETURN=0X1234 STACK=OK LOADS=0 FAULTS=0 REFUSED=0 LINES=2 DROPPED=0"));
    /* hex through the op, and the counter through the platform. */
    CHECK(find(EV_EMIT, "0XABC") > call);
    CHECK(seen_counters[0] == 1000 && seen_counters[1] == 2000 && count_of(EV_COUNTER) == 2);
    CHECK(result.call[0].lines == 2 && result.call[0].dropped == 0 && result.call[0].loads == 0 && result.call[0].faults == 0 &&
          result.call[0].refused == 0);
    /* The payload's own bytes are untouched by the runner. */
    CHECK(!memcmp(payload_mem, (uint8_t[]){3, 10, 17}, 3));

    /* Return values are printed whatever they are, the biggest included. */
    make_loaded();
    payload_fn = payload_all_ones;
    CHECK(run() == Q1N1_PAYLOAD_RUN_OK && result.call[0].retval == ~UINT64_C(0));
    CHECK(find(EV_EMIT, "PAYLOAD DONE INDEX=0 RETURN=0XFFFFFFFFFFFFFFFF STACK=OK") >= 0);
    make_loaded();
    payload_fn = payload_noisy;
    CHECK(run() == Q1N1_PAYLOAD_RUN_OK && result.call[0].retval == 7 && find(EV_EMIT, "PAYLOAD DONE INDEX=0 RETURN=0X7 ") >= 0);
    return 0;
}

/* ---- verify --------------------------------------------------------------------------------------------------- */

static int refused_not_called(const char *prefix)
{
    if (count_of(EV_CALL) || count_of(EV_SYNC) || count_of(EV_GUARDED)) return 0;
    if (find(EV_EMIT, "PAYLOAD CALL") >= 0 || find(EV_EMIT, "PAYLOAD VERIFY") >= 0) return 0;
    return find(EV_EMIT, prefix) >= 0;
}

static int suite_verify(void)
{
    payload_fn = payload_hello;
    /* The payload's own bytes changed after the first hash. */
    for (unsigned offset = 0; offset < PAYLOAD_BYTES; offset += 499) {
        make_loaded();
        payload_mem[offset] ^= 0x01;
        seen_calls = 0;
        CHECK(run() == Q1N1_PAYLOAD_RUN_HASH && seen_calls == 0);
        CHECK(refused_not_called("PAYLOAD REFUSED=HASH_AT_EL2 INDEX=0 WANT="));
        int line = find(EV_EMIT, "PAYLOAD REFUSED=HASH_AT_EL2");
        CHECK(strstr(log_[line].text, " HAVE=") != NULL);
        CHECK(result.called == 0 && result.stopped == 0);
    }
    /* The last byte of the file, and the first byte past it (which is not hashed): only the first is caught. */
    make_loaded();
    payload_mem[PAYLOAD_BYTES - 1] ^= 0x80;
    CHECK(run() == Q1N1_PAYLOAD_RUN_HASH);
    make_loaded();
    payload_mem[PAYLOAD_BYTES] ^= 0x80;
    CHECK(run() == Q1N1_PAYLOAD_RUN_OK);
    /* The table says something else: another digest, base, size, allocation, count, magic. */
    struct { const char *what; int offset; } table_faults[] = {
        {"digest", offsetof(struct q1n1_preload_cache, files[0].file.sha256) + 5},
        {"base", offsetof(struct q1n1_preload_cache, files[0].base)},
        {"size", offsetof(struct q1n1_preload_cache, files[0].file.size)},
        {"allocation", offsetof(struct q1n1_preload_cache, files[0].allocation)},
        {"magic", offsetof(struct q1n1_preload_cache, magic)},
        {"version", offsetof(struct q1n1_preload_cache, version)},
        {"count", offsetof(struct q1n1_preload_cache, count)},
        {"entry size", offsetof(struct q1n1_preload_cache, entry_size)},
    };
    for (unsigned i = 0; i < sizeof table_faults / sizeof table_faults[0]; i++) {
        make_loaded();
        ((uint8_t *)table)[table_faults[i].offset] ^= 0x08;
        int rc = run();
        if (rc != Q1N1_PAYLOAD_RUN_HASH) fprintf(stderr, "table fault: %s was not caught\n", table_faults[i].what);
        CHECK(rc == Q1N1_PAYLOAD_RUN_HASH && refused_not_called("PAYLOAD REFUSED=HASH_AT_EL2"));
    }
    /* A table that is itself consistent with the file but is not what was measured before the bounce: both
     * the digest in the table and the bytes agree, the runner's own record does not. */
    make_loaded();
    payload_mem[10] ^= 0x01;
    q1n1_sha256(payload_mem, PAYLOAD_BYTES, table->files[0].file.sha256);
    CHECK(q1n1_payload_verify_in_place(&loaded, 0) == 0);
    CHECK(run() == Q1N1_PAYLOAD_RUN_HASH && refused_not_called("PAYLOAD REFUSED=HASH_AT_EL2"));
    make_loaded();
    loaded.file[0].bytes--;                                      /* the record says another size: the table's is not it */
    CHECK(run() == Q1N1_PAYLOAD_RUN_HASH);
    make_loaded();
    loaded.file[0].alloc += 4096;
    CHECK(run() == Q1N1_PAYLOAD_RUN_HASH);
    make_loaded();
    /* The record points at a second, identical copy: the table's base is not it. */
    uint8_t *copy = aligned_alloc(4096, 4096);
    memcpy(copy, payload_mem, 4096);
    loaded.file[0].base = (uint64_t)(uintptr_t)copy;
    CHECK(run() == Q1N1_PAYLOAD_RUN_HASH);
    free(copy);
    make_loaded();
    loaded.file[0].sha256[31] ^= 1;
    CHECK(run() == Q1N1_PAYLOAD_RUN_HASH);
    make_loaded();
    CHECK(q1n1_payload_verify_in_place(&loaded, 0) == 1);
    loaded.table_base = 0;
    CHECK(q1n1_payload_verify_in_place(&loaded, 0) == 0);
    /* An index past the files, and a count the record cannot hold, are not payloads that verify. */
    make_loaded();
    CHECK(q1n1_payload_verify_in_place(&loaded, 1) == 0 && q1n1_payload_verify_in_place(&loaded, 99) == 0);
    loaded.count = Q1N1_PAYLOAD_MAX_FILES + 1;
    CHECK(q1n1_payload_verify_in_place(&loaded, 0) == 0);
    /* Nothing loaded. */
    make_loaded();
    loaded.count = 0;
    CHECK(run() == Q1N1_PAYLOAD_RUN_NO_PAYLOAD && refused_not_called("PAYLOAD REFUSED=NO_PAYLOAD"));
    CHECK(find(EV_EMIT, "PAYLOAD LOADED") == 0);                 /* the notes are still shown */
    make_loaded();
    loaded.stack_base = 0;
    CHECK(run() == Q1N1_PAYLOAD_RUN_NO_PAYLOAD && refused_not_called("PAYLOAD REFUSED=NO_PAYLOAD"));
    return 0;
}

/* ---- ops ------------------------------------------------------------------------------------------------------ */

static int suite_ops(void)
{
    /* The line budget: the payload's 41st line and every one after it is counted and dropped. */
    make_loaded();
    payload_fn = payload_noisy;
    CHECK(run() == Q1N1_PAYLOAD_RUN_OK);
    unsigned noise = 0;
    for (unsigned i = 0; i < log_n; i++) noise += log_[i].kind == EV_EMIT && !strcmp(log_[i].text, "PAYLOAD NOISE");
    CHECK(noise == Q1N1_PAYLOAD_LINES_MAX && result.call[0].lines == Q1N1_PAYLOAD_LINES_MAX && result.call[0].dropped == 10);
    CHECK(find(EV_EMIT, "PAYLOAD DONE INDEX=0 RETURN=0X7 STACK=OK LOADS=0 FAULTS=0 REFUSED=0 LINES=40 DROPPED=10") >= 0);
    /* The runner's own lines are not charged to the payload's budget, so they all arrive. */
    CHECK(find(EV_EMIT, "PAYLOAD VERIFY=OK") >= 0 && find(EV_EMIT, "PAYLOAD CALL 0 ") >= 0 && find(EV_EMIT, "PAYLOAD DONE INDEX=0") >= 0);
    CHECK(log_n <= Q1N1_PAYLOAD_REGION_LINES);

    /* The font and the cap, a NULL line and an empty one. */
    make_loaded();
    payload_fn = payload_text;
    CHECK(run() == Q1N1_PAYLOAD_RUN_OK);
    int first = find(EV_EMIT, "LOWER CASE_");
    CHECK(first >= 0 && !strcmp(log_[first].text, "LOWER CASE_ _BRACKETS_ _ TAB __"));
    int longest = -1;
    for (unsigned i = 0; i < log_n; i++) if (log_[i].kind == EV_EMIT && log_[i].text[0] == 'X') longest = (int)i;
    CHECK(longest >= 0 && strlen(log_[longest].text) == Q1N1_PAYLOAD_LINE_MAX);      /* cut at the cap, folded up */
    CHECK(log_[longest].text[Q1N1_PAYLOAD_LINE_MAX - 1] == 'X');
    CHECK(result.call[0].lines == 3);                            /* NULL is not a line; the empty one is */

    /* load32: every case of the policy, in one payload. */
    make_loaded();
    payload_fn = payload_load32;
    memset(load_rc, 0x7f, sizeof load_rc);
    CHECK(run() == Q1N1_PAYLOAD_RUN_OK && result.call[0].retval == 14);
    CHECK(load_rc[0] == Q1N1_PAYLOAD_LOAD_OK && load_val[0] == (uint32_t)(0x1000u * 2654435761u));
    CHECK(load_rc[1] == Q1N1_PAYLOAD_LOAD_E_ALIGN && load_val[1] == 0x11111111);
    CHECK(load_rc[2] == Q1N1_PAYLOAD_LOAD_E_ALIGN);
    CHECK(load_rc[3] == Q1N1_PAYLOAD_LOAD_E_PARAM);
    CHECK(load_rc[4] == Q1N1_PAYLOAD_LOAD_E_OUT && load_val[4] == 0x22222222);   /* nothing was stored outside */
    CHECK(load_rc[5] == Q1N1_PAYLOAD_LOAD_OK && load_rc[6] == Q1N1_PAYLOAD_LOAD_OK);
    CHECK(load_rc[7] == Q1N1_PAYLOAD_LOAD_E_OUT && load_rc[8] == Q1N1_PAYLOAD_LOAD_E_ALIGN);
    CHECK(load_rc[9] == Q1N1_PAYLOAD_LOAD_E_OUT);
    CHECK(load_rc[10] == Q1N1_PAYLOAD_LOAD_E_RANGE && load_rc[11] == Q1N1_PAYLOAD_LOAD_OK && load_rc[12] == Q1N1_PAYLOAD_LOAD_E_RANGE);
    CHECK(load_rc[13] == Q1N1_PAYLOAD_LOAD_E_FAULT && load_val[13] == 0x11111111);  /* a fault leaves the word alone */
    CHECK(result.call[0].loads == 5 && result.call[0].faults == 1 && result.call[0].refused == 9);
    /* The guarded copy only ever stores into the runner's own variable, never into a payload-chosen address. */
    unsigned guarded = 0;
    for (unsigned i = 0; i < log_n; i++) {
        if (log_[i].kind != EV_GUARDED) continue;
        guarded++;
        CHECK(log_[i].c == 4);
        CHECK(log_[i].a < loaded.stack_base || log_[i].a >= loaded.stack_base + loaded.stack_alloc);
    }
    CHECK(guarded == result.call[0].loads && guarded_calls == result.call[0].loads);
    CHECK(find(EV_EMIT, "PAYLOAD DONE INDEX=0 RETURN=0XE STACK=OK LOADS=5 FAULTS=1 REFUSED=9 ") >= 0);

    /* The budget: Q1N1_PAYLOAD_LOADS_MAX loads succeed and every later one is refused without a guarded read. */
    make_loaded();
    payload_fn = payload_budget;
    CHECK(run() == Q1N1_PAYLOAD_RUN_OK);
    CHECK(result.call[0].retval == (((uint64_t)Q1N1_PAYLOAD_LOADS_MAX << 32) | 10));
    CHECK(load_rc[0] == Q1N1_PAYLOAD_LOAD_E_BUDGET && guarded_calls == Q1N1_PAYLOAD_LOADS_MAX);
    CHECK(result.call[0].loads == Q1N1_PAYLOAD_LOADS_MAX && result.call[0].refused == 10);

    /* The policy function on its own, as a table. */
    uint8_t stack[64] __attribute__((aligned(8)));
    uint64_t base = (uint64_t)(uintptr_t)stack;
    struct { uint64_t addr; uint64_t out; unsigned done; int want; } policy[] = {
        {0x1000, base, 0, Q1N1_PAYLOAD_LOAD_OK},
        {0x1000, base + 60, 0, Q1N1_PAYLOAD_LOAD_OK},
        {0x1000, base + 64, 0, Q1N1_PAYLOAD_LOAD_E_OUT},
        {0x1000, base - 4, 0, Q1N1_PAYLOAD_LOAD_E_OUT},
        {0x1000, base + 61, 0, Q1N1_PAYLOAD_LOAD_E_ALIGN},
        {0x1001, base, 0, Q1N1_PAYLOAD_LOAD_E_ALIGN},
        {0x1003, base, 0, Q1N1_PAYLOAD_LOAD_E_ALIGN},
        {0x1000, 0, 0, Q1N1_PAYLOAD_LOAD_E_PARAM},
        {(UINT64_C(1) << 48) - 4, base, 0, Q1N1_PAYLOAD_LOAD_OK},
        {(UINT64_C(1) << 48), base, 0, Q1N1_PAYLOAD_LOAD_E_RANGE},
        {0x1000, base, Q1N1_PAYLOAD_LOADS_MAX - 1, Q1N1_PAYLOAD_LOAD_OK},
        {0x1000, base, Q1N1_PAYLOAD_LOADS_MAX, Q1N1_PAYLOAD_LOAD_E_BUDGET},
        {0x1000, base, Q1N1_PAYLOAD_LOADS_MAX + 1000, Q1N1_PAYLOAD_LOAD_E_BUDGET},
    };
    for (unsigned i = 0; i < sizeof policy / sizeof policy[0]; i++) {
        int got = q1n1_payload_load32_check(policy[i].addr, (const uint32_t *)(uintptr_t)policy[i].out, base, sizeof stack, policy[i].done);
        if (got != policy[i].want) fprintf(stderr, "policy case %u: got %d want %d\n", i, got, policy[i].want);
        CHECK(got == policy[i].want);
    }
    CHECK(q1n1_payload_load32_check(0x1000, (const uint32_t *)stack, base, 3, 0) == Q1N1_PAYLOAD_LOAD_E_OUT);   /* a stack too small for a word */
    CHECK(q1n1_payload_load32_check(0x1000, (const uint32_t *)stack, base, 0, 0) == Q1N1_PAYLOAD_LOAD_E_OUT);
    return 0;
}

/* ---- guard ---------------------------------------------------------------------------------------------------- */

static int suite_guard(void)
{
    make_loaded();
    payload_fn = payload_hello;
    CHECK(run() == Q1N1_PAYLOAD_RUN_OK && result.call[0].stack_ok == 1 && find(EV_EMIT, "PAYLOAD DONE INDEX=0 RETURN=0X1234 STACK=OK ") >= 0);
    CHECK(find(EV_EMIT, "PAYLOAD CHAIN STOPPED") < 0);
    CHECK(((uint64_t *)stack_mem)[0] == UINT64_C(0x5afe5afe5afe5afe) && ((uint64_t *)stack_mem)[1] == UINT64_C(0x5afe5afe5afe5afe));
    make_loaded();
    payload_fn = payload_scribble;
    /* Running past the stack stops the chain, here after its only payload, and says so. */
    CHECK(run() == Q1N1_PAYLOAD_RUN_STACK && result.call[0].stack_ok == 0 && result.stopped == 0 && result.called == 1);
    CHECK(find(EV_EMIT, "PAYLOAD DONE INDEX=0 RETURN=0X0 STACK=OVERFLOW ") >= 0 && find(EV_EMIT, " STACK=OK") < 0);
    CHECK(find(EV_EMIT, "PAYLOAD CHAIN STOPPED INDEX=0 REASON=STACK_OVERFLOW") > find(EV_EMIT, "PAYLOAD DONE"));   /* reported to the end */
    /* The guard words are written after the verification, so a refused payload leaves the stack as it was. */
    make_loaded();
    payload_mem[0] ^= 1;
    CHECK(run() == Q1N1_PAYLOAD_RUN_HASH && stack_mem[0] == 0xa5 && stack_mem[8] == 0xa5);
    return 0;
}

/* ---- args ----------------------------------------------------------------------------------------------------- */

static int suite_args(void)
{
    make_loaded();
    payload_fn = payload_hello;
    memset(&seen, 0, sizeof seen);
    CHECK(run() == Q1N1_PAYLOAD_RUN_OK);
    CHECK(seen.magic == Q1N1_PAYLOAD_ABI_MAGIC && seen.version == Q1N1_PAYLOAD_ABI_VERSION && seen.size == sizeof seen);
    CHECK(seen.payload_base == loaded.file[0].base && seen.payload_size == PAYLOAD_BYTES);
    CHECK(seen.fb_base == platform.fb_base && seen.fb_bytes == platform.fb_bytes);
    CHECK(seen.fb_width == 2880 && seen.fb_height == 1920 && seen.fb_stride == 2880 && seen.fb_format == 1);
    CHECK(seen.map_base == 0x7000 && seen.map_size == 10896 && seen.map_stride == 48);
    CHECK(seen.preload_table == loaded.table_base && seen.preload_size == sizeof(struct q1n1_preload_cache));
    CHECK(seen.stack_base == loaded.stack_base && seen.stack_size == Q1N1_PAYLOAD_STACK_BYTES);
    CHECK(seen.ops.puts && seen.ops.hex && seen.ops.load32 && seen.ops.counter);
    for (unsigned i = 0; i < 5; i++) CHECK(seen.reserved[i] == 0);
    /* hex through the op: the fewest digits, upper case, cut at the capacity. */
    char text[8];
    CHECK(seen.ops.hex(text, sizeof text, 0xdeadbeef) == 7 && !strcmp(text, "0XDEADB"));
    CHECK(seen.ops.hex(text, sizeof text, 0) == 3 && !strcmp(text, "0X0"));
    CHECK(seen.ops.hex(text, 0, 5) == 0);
    /* The table the payload is told about is the table the runner verified. */
    const struct q1n1_preload_cache *cache = (const void *)(uintptr_t)seen.preload_table;
    CHECK(cache->magic == Q1N1_CACHE_MAGIC && q1n1_preload_verify(cache, 0) == 1);
    return 0;
}

int main(int argc, char **argv)
{
    static const struct { const char *name; int (*run)(void); } suites[] = {
        {"order", suite_order}, {"verify", suite_verify}, {"ops", suite_ops}, {"guard", suite_guard}, {"args", suite_args},
    };
    unsigned ran = 0;
    for (unsigned i = 0; i < sizeof suites / sizeof suites[0]; i++) {
        if (argc > 1 && strcmp(argv[1], "all") && strcmp(argv[1], suites[i].name)) continue;
        if (suites[i].run()) { fprintf(stderr, "FAIL: suite %s\n", suites[i].name); return 1; }
        ran++;
    }
    printf("PASS: %u payload run suites, %u checks\n", ran, checks);
    return 0;
}
