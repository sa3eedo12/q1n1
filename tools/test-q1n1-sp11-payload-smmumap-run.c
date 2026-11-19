/* SPDX-License-Identifier: MIT */
/* Host test for the one hook of the mapping step in the payload runner (platform/uefi/sp11-payload-run.c, built with
 * Q1N1_SP11_SMMUMAP=1), against a fake platform: where the hook runs (after the first payload's own hash check, once every payload of
 * the chain has been seen to verify, and before the first call), what each answer does to the chain, and that a runner with no hook is
 * the chain it was. The step's own logic is tested by tools/test-q1n1-sp11-payload-smmumap.c. Driven by
 * tools/test-q1n1-sp11-payload-smmumap.py under ASan and UBSan. Nothing here runs at EL2 or on hardware. Evidence: EXPERIMENTAL (host model only). */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SNAP_PLATFORM_SP11 1
#define Q1N1_SP11_PAYLOAD 1
#include "sp11-payload.h"
#include "sp11-smmumap.h"
#include "sha256.h"

static unsigned checks, failures;
#define CHECK(x, ...) do { checks++; if (!(x)) { failures++; printf("FAIL %s:%d: ", __FILE__, __LINE__); printf(__VA_ARGS__); printf("\n"); } } while (0)

enum { EV_EMIT, EV_SYNC, EV_CALL, EV_HOOK };
struct event { int kind; char text[128]; };
static struct event log_[64];
static unsigned log_n, hook_calls;
static int hook_answer;

static void record(int kind, const char *text)
{
    if (log_n >= sizeof log_ / sizeof log_[0]) { printf("FAIL: event log full\n"); exit(2); }
    log_[log_n].kind = kind;
    snprintf(log_[log_n].text, sizeof log_[0].text, "%s", text);
    log_n++;
}
static void fake_emit(const char *line) { record(EV_EMIT, line); }
static void fake_sync(uint64_t base, uint64_t bytes) { (void)base; (void)bytes; record(EV_SYNC, ""); }
static uint64_t fake_call(uint64_t entry, const struct q1n1_payload_args *args, uint64_t top)
{
    (void)entry; (void)args; (void)top;
    record(EV_CALL, "");
    return 0;
}
static int fake_guarded(int kind, uint64_t dst, uint64_t src, uint64_t size)
{
    (void)kind; (void)dst; (void)src; (void)size;
    return 1;
}
static uint64_t fake_counter(void) { return 0; }
static int fake_hook(void)
{
    record(EV_HOOK, "");
    hook_calls++;
    return hook_answer;
}

static const struct q1n1_payload_platform platform = {
    .fb_base = 0xe4800000, .fb_bytes = 0x1518000, .map_base = 0x7000, .map_size = 10896, .map_stride = 48,
    .fb_width = 2880, .fb_height = 1920, .fb_stride = 2880, .fb_format = 1,
};
static struct q1n1_payload_loaded loaded;
static uint8_t *payload_mem[3], *stack_mem;
static struct q1n1_preload_cache *table;
#define PAYLOAD_BYTES 3000u

/* `count` files: the first `code` of them payloads (<stem>.BIN, LoaderCode) and the rest data, each with its own bytes and its own digest. */
static void make_loaded_files(unsigned count, unsigned code)
{
    free(stack_mem); free(table);
    for (unsigned i = 0; i < 3; i++) { free(payload_mem[i]); payload_mem[i] = NULL; }
    stack_mem = aligned_alloc(4096, Q1N1_PAYLOAD_STACK_BYTES);
    table = aligned_alloc(4096, 8192);
    memset(stack_mem, 0xa5, Q1N1_PAYLOAD_STACK_BYTES);
    memset(table, 0, 8192);
    memset(&loaded, 0, sizeof loaded);
    loaded.count = count;
    loaded.code_count = code;
    loaded.table_base = (uint64_t)(uintptr_t)table;
    loaded.table_alloc = 8192;
    loaded.stack_base = (uint64_t)(uintptr_t)stack_mem;
    loaded.stack_alloc = Q1N1_PAYLOAD_STACK_BYTES;
    table->magic = Q1N1_CACHE_MAGIC; table->version = 1; table->count = count; table->entry_size = sizeof table->files[0];
    for (unsigned f = 0; f < count; f++) {
        payload_mem[f] = aligned_alloc(4096, 4096);
        memset(payload_mem[f], 0, 4096);
        for (unsigned i = 0; i < PAYLOAD_BYTES; i++) payload_mem[f][i] = (uint8_t)(i * 7 + 3 + 41 * f);
        loaded.file[f].base = (uint64_t)(uintptr_t)payload_mem[f];
        loaded.file[f].bytes = PAYLOAD_BYTES;
        loaded.file[f].alloc = 4096;
        loaded.file[f].memory_type = f < code ? Q1N1_PAYLOAD_TYPE_CODE : Q1N1_PAYLOAD_TYPE_DATA;
        q1n1_sha256(payload_mem[f], PAYLOAD_BYTES, loaded.file[f].sha256);
        table->files[f].base = loaded.file[f].base;
        table->files[f].allocation = 4096;
        table->files[f].file.size = PAYLOAD_BYTES;
        memcpy(table->files[f].file.sha256, loaded.file[f].sha256, 32);
        snprintf(table->files[f].file.path, sizeof table->files[f].file.path, f < code ? "\\SP11\\PAYLOAD%u.BIN" : "\\SP11\\STATE%u.DAT", f);
        snprintf(loaded.note[f], sizeof loaded.note[f], "PAYLOAD LOADED INDEX=%u", f);
    }
    snprintf(loaded.note[count], sizeof loaded.note[count], "PAYLOAD READY FILES=%u RANGES=4", count);
    loaded.notes = count + 1;
}
static void make_loaded(void) { make_loaded_files(1, 1); }

/* Damage a payload after it was loaded and hashed: the byte the runner's second hash must see. */
static void damage(unsigned index) { payload_mem[index][17] ^= 0x40; }

static unsigned count_of(int kind)
{
    unsigned n = 0;
    for (unsigned i = 0; i < log_n; i++) n += log_[i].kind == kind;
    return n;
}
static int first_of(int kind)
{
    for (unsigned i = 0; i < log_n; i++)
        if (log_[i].kind == kind) return (int)i;
    return -1;
}
static int first_text(const char *prefix)
{
    for (unsigned i = 0; i < log_n; i++)
        if (log_[i].kind == EV_EMIT && !strncmp(log_[i].text, prefix, strlen(prefix))) return (int)i;
    return -1;
}

static int run_chain(int use_hook, int answer, struct q1n1_payload_result *result)
{
    struct q1n1_payload_env env = {fake_emit, fake_sync, fake_call, fake_guarded, fake_counter, use_hook ? fake_hook : NULL};
    log_n = 0;
    hook_calls = 0;
    hook_answer = answer;
    memset(result, 0x77, sizeof *result);
    return q1n1_payload_run(&env, &loaded, &platform, result);
}

int main(void)
{
    struct q1n1_payload_result r;
    int status;
    static const int ok_answers[] = {Q1N1_SMMUMAP_MAPPED, Q1N1_SMMUMAP_REFUSED};

    for (unsigned i = 0; i < 2; i++) {
        make_loaded();
        status = run_chain(1, ok_answers[i], &r);
        CHECK(status == Q1N1_PAYLOAD_RUN_OK && r.status == Q1N1_PAYLOAD_RUN_OK && r.called == 1, "answer %d: status %d, %u called", ok_answers[i], status, r.called);
        CHECK(hook_calls == 1 && count_of(EV_HOOK) == 1, "answer %d: the hook ran %u times", ok_answers[i], hook_calls);
        CHECK(count_of(EV_CALL) == 1 && count_of(EV_SYNC) == 1, "answer %d: the chain did not run to its payload", ok_answers[i]);
        /* The notes first, then the payload's own hash check, then the hook, and only then the payload is made executable and called. */
        CHECK(log_n > 4 && log_[0].kind == EV_EMIT && !strcmp(log_[0].text, "PAYLOAD LOADED INDEX=0") && !strcmp(log_[1].text, "PAYLOAD READY FILES=1 RANGES=4"),
              "answer %d: the notes are not first", ok_answers[i]);
        CHECK(first_text("PAYLOAD VERIFY=OK") == 2, "answer %d: the payload's hash check is event %d, not the one after the notes", ok_answers[i], first_text("PAYLOAD VERIFY=OK"));
        CHECK(first_of(EV_HOOK) == 3, "answer %d: the hook is event %d, not the one after the hash check", ok_answers[i], first_of(EV_HOOK));
        CHECK(first_of(EV_SYNC) > first_of(EV_HOOK) && first_of(EV_CALL) > first_of(EV_HOOK) && first_text("PAYLOAD CALL") > first_of(EV_HOOK),
              "answer %d: the payload was made executable or called before the hook", ok_answers[i]);
        CHECK(first_text("PAYLOAD CHAIN STOPPED") < 0 && first_text("PAYLOAD DONE") > first_of(EV_CALL), "answer %d: the chain's own lines", ok_answers[i]);
    }

    /* A descriptor that could be neither checked nor removed: the payload was verified but is neither synced nor called, and the chain says why. */
    make_loaded();
    status = run_chain(1, Q1N1_SMMUMAP_UNSAFE, &r);
    CHECK(status == Q1N1_PAYLOAD_RUN_SMMUMAP && r.status == Q1N1_PAYLOAD_RUN_SMMUMAP && r.called == 0 && r.stopped == 0, "UNSAFE: status %d, %u called, stopped %u", status, r.called, r.stopped);
    CHECK(hook_calls == 1 && count_of(EV_CALL) == 0 && count_of(EV_SYNC) == 0 && first_text("PAYLOAD CALL") < 0, "UNSAFE: the payload was reached");
    CHECK(first_text("PAYLOAD VERIFY=OK") == 2 && first_of(EV_HOOK) == 3, "UNSAFE: the hook did not follow the hash check");
    CHECK(log_n && log_[log_n - 1].kind == EV_EMIT && !strcmp(log_[log_n - 1].text, "PAYLOAD CHAIN STOPPED INDEX=0 REASON=SMMUMAP"),
          "UNSAFE: the last line is '%s'", log_n ? log_[log_n - 1].text : "");

    /* A refusal of the step leaves the chain's lines exactly as a runner with no hook gives them, and the hook adds no line of its own here. */
    {
        char want[64][128];
        unsigned wanted;
        make_loaded();
        status = run_chain(0, Q1N1_SMMUMAP_UNSAFE, &r);
        CHECK(status == Q1N1_PAYLOAD_RUN_OK && r.called == 1 && count_of(EV_HOOK) == 0 && count_of(EV_CALL) == 1, "no hook: status %d", status);
        wanted = 0;
        for (unsigned i = 0; i < log_n; i++)
            if (log_[i].kind == EV_EMIT) memcpy(want[wanted++], log_[i].text, sizeof want[0]);
        make_loaded();
        status = run_chain(1, Q1N1_SMMUMAP_REFUSED, &r);
        for (unsigned i = 0, k = 0; i < log_n; i++) {
            if (log_[i].kind != EV_EMIT) continue;
            CHECK(k < wanted && !strcmp(log_[i].text, want[k]), "a refused step changed the chain's line %u: '%s'", k, log_[i].text);
            k++;
        }
    }

    /* Nothing to call, nothing to map for: the hook does not run. */
    make_loaded();
    loaded.count = 0;
    status = run_chain(1, Q1N1_SMMUMAP_MAPPED, &r);
    CHECK(status == Q1N1_PAYLOAD_RUN_NO_PAYLOAD && hook_calls == 0 && first_text("PAYLOAD REFUSED=NO_PAYLOAD") >= 0, "no payload: status %d, hook %u", status, hook_calls);
    make_loaded();
    loaded.stack_base = 0;
    status = run_chain(1, Q1N1_SMMUMAP_MAPPED, &r);
    CHECK(status == Q1N1_PAYLOAD_RUN_NO_PAYLOAD && hook_calls == 0, "no stack: status %d, hook %u", status, hook_calls);

    /* A payload that does not verify: nothing is written for it. The first one gives the loop's own refusal before the hook is reached. */
    make_loaded();
    damage(0);
    status = run_chain(1, Q1N1_SMMUMAP_MAPPED, &r);
    CHECK(status == Q1N1_PAYLOAD_RUN_HASH && r.stopped == 0 && r.called == 0 && hook_calls == 0 && first_text("PAYLOAD VERIFY=OK") < 0 &&
          first_text("PAYLOAD REFUSED=HASH_AT_EL2 INDEX=0") >= 0, "payload 0 damaged: status %d, hook %u", status, hook_calls);

    /* A LATER payload that does not verify: the chain stops BEFORE the hook, so that no descriptor is written for a chain that will not run, and
     * the lines are the ones the loop gives the same payload when it reaches it with no hook (payload 0 is then called first). */
    {
        char refused[2][128] = {"", ""};
        make_loaded_files(2, 2);
        damage(1);
        status = run_chain(0, Q1N1_SMMUMAP_MAPPED, &r);
        CHECK(status == Q1N1_PAYLOAD_RUN_HASH && r.stopped == 1 && r.called == 1, "no hook, payload 1 damaged: status %d, stopped %u, %u called", status, r.stopped, r.called);
        for (unsigned i = 0; i < log_n; i++) {
            if (log_[i].kind != EV_EMIT) continue;
            if (!strncmp(log_[i].text, "PAYLOAD REFUSED=HASH_AT_EL2", 27)) memcpy(refused[0], log_[i].text, sizeof refused[0]);
            if (!strncmp(log_[i].text, "PAYLOAD CHAIN STOPPED", 21)) memcpy(refused[1], log_[i].text, sizeof refused[1]);
        }
        CHECK(!strncmp(refused[0], "PAYLOAD REFUSED=HASH_AT_EL2 INDEX=1 WANT=", 41) && !strcmp(refused[1], "PAYLOAD CHAIN STOPPED INDEX=1 REASON=HASH_AT_EL2"), "the loop's own refusal is '%s' / '%s'", refused[0], refused[1]);

        make_loaded_files(2, 2);
        damage(1);
        status = run_chain(1, Q1N1_SMMUMAP_MAPPED, &r);
        CHECK(status == Q1N1_PAYLOAD_RUN_HASH && r.status == Q1N1_PAYLOAD_RUN_HASH && r.stopped == 1 && r.called == 0, "payload 1 damaged: status %d, stopped %u, %u called", status, r.stopped, r.called);
        CHECK(hook_calls == 0 && count_of(EV_HOOK) == 0 && count_of(EV_SYNC) == 0 && count_of(EV_CALL) == 0, "payload 1 damaged: the hook ran or a payload was reached");
        CHECK(first_text("PAYLOAD VERIFY=OK") == 3 && first_text("PAYLOAD REFUSED=HASH_AT_EL2 INDEX=1") == 4 && first_text("PAYLOAD CHAIN STOPPED") == 5 && log_n == 6,
              "payload 1 damaged: the lines are not the first payload's hash check, the refusal and the stop (%u events)", log_n);
        CHECK(!strcmp(log_[4].text, refused[0]) && !strcmp(log_[5].text, refused[1]), "payload 1 damaged: the refusal differs from the loop's own ('%s')", log_[4].text);
    }

    /* The third of three, and a data file: every later payload is checked, and only a payload is. */
    make_loaded_files(3, 3);
    damage(2);
    status = run_chain(1, Q1N1_SMMUMAP_MAPPED, &r);
    CHECK(status == Q1N1_PAYLOAD_RUN_HASH && r.stopped == 2 && r.called == 0 && hook_calls == 0 && first_text("PAYLOAD REFUSED=HASH_AT_EL2 INDEX=2") >= 0 &&
          first_text("PAYLOAD CHAIN STOPPED INDEX=2 REASON=HASH_AT_EL2") >= 0, "payload 2 of 3 damaged: status %d, stopped %u, hook %u", status, r.stopped, hook_calls);
    make_loaded_files(2, 1);
    damage(1);
    status = run_chain(1, Q1N1_SMMUMAP_MAPPED, &r);
    CHECK(status == Q1N1_PAYLOAD_RUN_OK && r.called == 1 && hook_calls == 1, "a damaged data file: status %d, hook %u", status, hook_calls);

    /* Two good payloads: the hook runs once, after the first's hash check and before its call, not again for the second. */
    make_loaded_files(2, 2);
    status = run_chain(1, Q1N1_SMMUMAP_MAPPED, &r);
    CHECK(status == Q1N1_PAYLOAD_RUN_OK && r.called == 2 && hook_calls == 1 && count_of(EV_HOOK) == 1 && count_of(EV_CALL) == 2, "two payloads: status %d, %u called, hook %u", status, r.called, hook_calls);
    {
        int verify0 = first_text("PAYLOAD VERIFY=OK"), hook = first_of(EV_HOOK), call0 = first_of(EV_CALL), verify1 = -1;
        for (unsigned i = (unsigned)verify0 + 1; i < log_n; i++)
            if (log_[i].kind == EV_EMIT && !strncmp(log_[i].text, "PAYLOAD VERIFY=OK", 17)) { verify1 = (int)i; break; }
        CHECK(verify0 == 3 && hook == 4 && call0 > hook && verify1 > call0, "two payloads: verify %d, hook %d, first call %d, second verify %d", verify0, hook, call0, verify1);
    }
    /* An answer that ends the chain with two payloads: the second is never verified by the loop. */
    make_loaded_files(2, 2);
    status = run_chain(1, Q1N1_SMMUMAP_UNSAFE, &r);
    CHECK(status == Q1N1_PAYLOAD_RUN_SMMUMAP && r.called == 0 && r.stopped == 0 && count_of(EV_CALL) == 0, "two payloads, UNSAFE: status %d, %u called", status, r.called);

    for (unsigned i = 0; i < 3; i++) free(payload_mem[i]);
    free(stack_mem); free(table);
    if (failures) {
        printf("FAILED: %u of %u checks\n", failures, checks);
        return 1;
    }
    printf("PASS: smmumap runner hook, %u checks\n", checks);
    return 0;
}
