/* SPDX-License-Identifier: MIT */
/* The world the retprobe host test (tools/test-q1n1-sp11-payload-retprobe.c) runs the payload in: a model of the machine, and an oracle of
 * the page format. Header only, included once. Evidence: EXPERIMENTAL (host model only); hardware NOT RUN.
 *
 * The model. Memory has two copies, as in the cpuon test: `arena` is what the CPU sees through its cache and the payload's pointers point
 * into, `truth` is what DRAM holds and what survives a reset. They agree only through cache maintenance: DC CVAC and DC CIVAC queue a
 * line, a DSB commits the queue to `truth`, and after a DSB a line that was invalidated (DC CIVAC) is read again from `truth`. A store
 * that was never cleaned and fenced is not in `truth`. A SYSTEM_RESET or SYSTEM_RESET2 that works does not return (the model jumps out of
 * the payload, as a reset would) and the test then asks what `truth` holds. PSCI is scripted: PSCI_FEATURES for the two reset functions,
 * SYSTEM_RESET and SYSTEM_RESET2 are known, and any other function id, or another argument, is a tripwire. The counter advances a fixed
 * step at every read, so a wait of eight seconds is a few thousand reads. The memory map, the preload table, the configuration file and
 * every answer of the MMU are built per scenario.
 *
 * The oracle is a second, independent copy of the page format in the payload's header comment, written with explicit byte offsets and a
 * table-driven CRC-32; it never calls the payload's code. */
#include <inttypes.h>
#include <setjmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SNAP_PLATFORM_SP11 1
#define Q1N1_SP11_PAYLOAD 1
#include "sp11-payload.h"
#include "preload.h"

uint64_t payload_entry(const struct q1n1_payload_args *a);

static unsigned checks;
#define CHECK(x) do { \
        if (!(x)) { fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #x); return 1; } \
        checks++; \
    } while (0)

#define PAGE 4096u
#define ARENA_PAGES 32u
#define SLOTS 3u
#define MAX_EVENTS 4096
#define ID_FEATURES 0x8400000Au
#define ID_RESET 0x84000009u
#define ID_RESET2 0xC4000012u
#define PFX "PAYLOAD RETPROBE "
#define COUNTER_MAX 0xfffffu
#define PAYLOAD_BASE UINT64_C(0x70000000)
#define STACK_BASE UINT64_C(0x71000000)
enum { RET_OK = 0, RET_BAD = 1, RET_NOT_EL2 = 2, RET_MAP = 3, RET_CONFIG = 4, RET_PAGE = 5, RET_VERIFY = 6, RET_NOT_IMPL = 7,
       RET_RETURNED = 8, RET_COUNTER = 9, RET_OVERFLOW = 10, RET_CACHE = 11 };
enum { S_NONE = 0, S_PARTIAL = 1, S_WHOLE = 2, S_UNREADABLE = 3 };
static const char *const state_names[4] = {"NONE", "PARTIAL", "WHOLE", "UNREADABLE"};
static const char *const path_names[3] = {"NONE", "PSCI_RESET", "PSCI_RESET2"};

static uint64_t rng = 0x9e3779b97f4a7c15ull;
static uint64_t next_random(void)
{
    rng ^= rng << 13; rng ^= rng >> 7; rng ^= rng << 17;
    return rng;
}

/* ---- The oracle ------------------------------------------------------------------------------------------------------------ */

static uint32_t crc_table[256];
static void crc_init(void)
{
    for (uint32_t n = 0; n < 256; n++) {
        uint32_t c = n;
        for (int k = 0; k < 8; k++) c = c & 1 ? 0xEDB88320u ^ (c >> 1) : c >> 1;
        crc_table[n] = c;
    }
}
static uint32_t crc32_ref(const uint8_t *p, size_t n)
{
    uint32_t c = 0xFFFFFFFFu;
    while (n--) c = crc_table[(c ^ *p++) & 0xFF] ^ (c >> 8);
    return ~c;
}
static void put32(uint8_t *p, uint32_t v) { for (int i = 0; i < 4; i++) p[i] = (uint8_t)(v >> 8 * i); }
static void put64(uint8_t *p, uint64_t v) { for (int i = 0; i < 8; i++) p[i] = (uint8_t)(v >> 8 * i); }
static uint32_t get32(const uint8_t *p) { return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24; }
static uint64_t get64(const uint8_t *p) { return (uint64_t)get32(p) | (uint64_t)get32(p + 4) << 32; }

struct stamp {
    uint32_t counter, previous_counter, frequency, feature_reset, feature_reset2, requested, used, previous_state[3], extent_type;
    uint64_t timestamp, extent_start, extent_bytes;
};
static void oracle_page(uint8_t *out, uint32_t slot, uint64_t address, const struct stamp *s)
{
    memset(out, 0, PAGE);
    memcpy(out, "RETCAN01", 8);
    put32(out + 8, 1);
    put32(out + 12, slot);
    put64(out + 16, address);
    put32(out + 24, s->counter);
    put32(out + 28, s->previous_counter);
    put64(out + 32, s->timestamp);
    put32(out + 40, s->frequency);
    put32(out + 44, s->feature_reset);
    put32(out + 48, s->feature_reset2);
    out[52] = (uint8_t)s->requested;
    out[53] = (uint8_t)s->used;
    out[54] = (uint8_t)s->previous_state[0];
    out[55] = (uint8_t)s->previous_state[1];
    out[56] = (uint8_t)s->previous_state[2];
    out[57] = 1;
    put32(out + 60, s->extent_type);
    put64(out + 64, s->extent_start);
    put64(out + 72, s->extent_bytes);
    for (uint32_t i = 0; i < 992; i++) put32(out + 128 + 4 * i, s->counter << 12 | slot << 10 | i);
    put32(out + 124, crc32_ref(out, PAGE));
}

/* (state, counter, bad words) of a page, decided from the specification and not from the payload's code. */
struct verdict {
    unsigned state, counter, bad_words;
};
static struct verdict oracle_classify(const uint8_t *page, uint32_t slot, uint64_t address)
{
    struct verdict v = {S_NONE, 0, 0};
    uint8_t copy[PAGE];
    static uint32_t keys[992];
    unsigned n = 0, matches = 0;
    uint32_t counter = get32(page + 24), best = 0, epoch = 0;
    memcpy(copy, page, PAGE);
    put32(copy + 124, 0);
    int crc_ok = crc32_ref(copy, PAGE) == get32(page + 124);
    if (!memcmp(page, "RETCAN01", 8) && get32(page + 8) == 1 && get32(page + 12) == slot && get64(page + 16) == address &&
        counter >= 1 && counter <= COUNTER_MAX) {
        for (uint32_t i = 0; i < 992; i++) v.bad_words += get32(page + 128 + 4 * i) != (counter << 12 | slot << 10 | i);
        v.counter = counter;
        v.state = crc_ok && !v.bad_words ? S_WHOLE : S_PARTIAL;
        return v;
    }
    for (uint32_t i = 0; i < 992; i++) {
        uint32_t w = get32(page + 128 + 4 * i);
        if ((w & 0x3ff) == i) keys[n++] = w >> 10;
    }
    for (unsigned i = 0; i < n; i++) {
        uint32_t count = 0;
        for (unsigned j = 0; j < n; j++) count += keys[j] == keys[i];
        if (count > best || (count == best && keys[i] < epoch)) { best = count; epoch = keys[i]; }
    }
    for (uint32_t i = 0; i < 992; i++) matches += get32(page + 128 + 4 * i) == (epoch << 10 | i);
    v.bad_words = 992 - matches;
    v.state = matches >= 16 ? S_PARTIAL : S_NONE;
    return v;
}

static void config_blob(uint8_t *out, uint32_t path, uint32_t countdown, const uint64_t pages[3])
{
    memset(out, 0, 64);
    memcpy(out, "RETCFG01", 8);
    put32(out + 8, 1);
    put32(out + 12, path);
    put32(out + 16, countdown);
    put32(out + 20, 3);
    for (unsigned k = 0; k < 3; k++) put64(out + 24 + 8 * k, pages[k]);
    put32(out + 60, crc32_ref(out, 60));
}
static void config_fix_crc(uint8_t *out) { put32(out + 60, crc32_ref(out, 60)); }

/* ---- The world ------------------------------------------------------------------------------------------------------------- */

static uint8_t *arena, *truth, *pristine;
static uint64_t slot_addr[SLOTS];
static const unsigned slot_page[SLOTS] = {3, 11, 20};
static uint8_t *table_buf, *map_buf, *config_buf;      /* what the payload is given and only reads: the preload table, the memory map, the configuration file */
static uint8_t *table_snap, *map_snap, *config_snap;   /* each of them as it was when the run began */

struct desc {
    uint32_t type;
    uint64_t start, pages;
};
#define MAX_DESC 24
struct world {
    uint64_t el, ctr, cntfrq, step, now;
    uint32_t path, countdown;
    uint64_t feat[2];                   /* raw x0 of PSCI_FEATURES(SYSTEM_RESET), PSCI_FEATURES(SYSTEM_RESET2) */
    int reset_returns;                  /* the reset call returns reset_ret instead of resetting */
    uint64_t reset_ret;
    unsigned have_config, extra_entries;
    uint8_t config[64];
    struct desc desc[MAX_DESC];
    unsigned ndesc;
    uint64_t map_stride_override, stack_base;
    uint64_t at_read[SLOTS], at_write[SLOTS];   /* PAR_EL1 per page, 0 for the identity write-back default */
    int fault_slot;                     /* load32 aborts at this word of this page */
    unsigned fault_word;
    int lossy_slot;                     /* a clean of a line of this page never reaches truth */
    int lossy_line;                     /* ... of this line of it only (a negative number: of every line) */
    unsigned stuck_after;               /* the counter stops advancing after this many reads, 0 never */
    unsigned back_after;                /* from this read on (counting from 0) the counter reads back_by lower than it should: it ran backwards, 0 never */
    uint64_t back_by;
};
static struct world w;

enum { EV_LINE, EV_SMC, EV_CACHE, EV_AT };
struct event {
    int kind;
    char text[200];
    uint64_t id, x1, x2, x3, now;
};
static struct event ev[MAX_EVENTS];
static unsigned nev, loads, counter_calls, bad_lines, bad_smc, bad_at, bad_cache, resets_called;
static uint64_t first_counter;
static char first_bad[200];
static jmp_buf reset_jump;

static int in_font(const char *text)
{
    for (; *text; text++)
        if (!((*text >= 'A' && *text <= 'Z') || (*text >= '0' && *text <= '9') || strchr(" :-./=?()_", *text))) return 0;
    return 1;
}
static void record(struct event e)
{
    if (nev >= MAX_EVENTS) { fprintf(stderr, "FAIL: event log full\n"); exit(2); }
    e.now = w.now;
    ev[nev++] = e;
}
static void fake_puts(const char *line)
{
    struct event e = {.kind = EV_LINE};
    snprintf(e.text, sizeof e.text, "%.199s", line);
    if (getenv("RETPROBE_TRACE")) fprintf(stderr, "LINE %s\n", line);
    if (strlen(line) > Q1N1_PAYLOAD_LINE_MAX || !in_font(line)) {
        bad_lines++;
        if (!first_bad[0]) snprintf(first_bad, sizeof first_bad, "%.199s", line);
    }
    record(e);
}
static uint32_t fake_hex(char *dst, uint32_t cap, uint64_t value) { return (uint32_t)q1n1_payload_fmt_hex(dst, cap, value); }
static int32_t fake_load32(uint64_t addr, uint32_t *out)
{
    if (!out || (addr & 3) || (uintptr_t)out & 3) return Q1N1_PAYLOAD_LOAD_E_ALIGN;
    if (++loads > Q1N1_PAYLOAD_LOADS_MAX) return Q1N1_PAYLOAD_LOAD_E_BUDGET;
    if (w.fault_slot >= 0 && addr == slot_addr[w.fault_slot] + 4u * w.fault_word) return Q1N1_PAYLOAD_LOAD_E_FAULT;
    if (addr < (uint64_t)(uintptr_t)arena || addr + 4 > (uint64_t)(uintptr_t)arena + (uint64_t)ARENA_PAGES * PAGE)
        return Q1N1_PAYLOAD_LOAD_E_FAULT;
    memcpy(out, (const void *)(uintptr_t)addr, 4);
    return 0;
}
static uint64_t fake_counter(void)
{
    uint64_t value = w.now;
    if (!w.stuck_after || counter_calls < w.stuck_after) w.now += w.step;
    if (!counter_calls) first_counter = value;
    if (w.back_after && counter_calls >= w.back_after) value -= w.back_by;
    counter_calls++;
    return value;
}

uint64_t pl_host_sysreg(const char *name);
uint64_t pl_host_sysreg(const char *name)
{
    if (!strcmp(name, "CurrentEL")) return w.el << 2;
    if (!strcmp(name, "ctr_el0")) return w.ctr;
    if (!strcmp(name, "cntfrq_el0")) return w.cntfrq;
    fprintf(stderr, "FAIL: the payload read a register the test does not know: %s\n", name);
    exit(3);
}

static uint64_t par_ok(uint64_t va, unsigned attr, unsigned sh) { return (va & ~UINT64_C(0xfff)) | (uint64_t)attr << 56 | (uint64_t)sh << 7; }
static uint64_t par_fault(unsigned fst) { return 1u | (uint64_t)fst << 1; }
static uint64_t at_answer(uint64_t va, const uint64_t *script, const char *what)
{
    struct event e = {.kind = EV_AT, .id = va};
    snprintf(e.text, sizeof e.text, "%s", what);
    record(e);
    for (unsigned k = 0; k < SLOTS; k++)
        if (va == slot_addr[k]) return script[k] ? script[k] : par_ok(va, 0xFF, 3);
    bad_at++;
    return par_fault(5);
}
uint64_t pl_host_at_s1e2r(uint64_t va);
uint64_t pl_host_at_s1e2r(uint64_t va) { return at_answer(va, w.at_read, "R"); }
uint64_t pl_host_at_s1e2w(uint64_t va);
uint64_t pl_host_at_s1e2w(uint64_t va) { return at_answer(va, w.at_write, "W"); }

void pl_host_smc(uint64_t regs[4]);
void pl_host_smc(uint64_t regs[4])
{
    struct event e = {.kind = EV_SMC, .id = regs[0], .x1 = regs[1], .x2 = regs[2], .x3 = regs[3]};
    uint64_t reply = ~UINT64_C(0);
    record(e);
    if (regs[0] == ID_FEATURES) {
        if (regs[1] == ID_RESET && !regs[2] && !regs[3]) reply = w.feat[0];
        else if (regs[1] == ID_RESET2 && !regs[2] && !regs[3]) reply = w.feat[1];
        else bad_smc++;
    } else if (regs[0] == ID_RESET || regs[0] == ID_RESET2) {
        resets_called++;
        if (regs[1] || regs[2] || regs[3]) bad_smc++;        /* reset type 0 and cookie 0 are zero, SYSTEM_RESET has no argument */
        if (!w.reset_returns) longjmp(reset_jump, 1);
        reply = w.reset_ret;
    } else {
        bad_smc++;
    }
    regs[0] = reply;
    regs[1] = regs[2] = regs[3] = 0;
}

#define LINE_MAX 4096
static struct { uint64_t address; int invalid; } pending[LINE_MAX];
static unsigned npending, cache_line = 64;
static int in_arena(uint64_t address)
{
    return address >= (uint64_t)(uintptr_t)arena && address < (uint64_t)(uintptr_t)arena + (uint64_t)ARENA_PAGES * PAGE;
}
void pl_host_cache(const char *operation, uint64_t address);
void pl_host_cache(const char *operation, uint64_t address)
{
    struct event e = {.kind = EV_CACHE, .id = address};
    snprintf(e.text, sizeof e.text, "%s", operation);
    record(e);
    if (!strcmp(operation, "dsb")) {
        for (unsigned i = 0; i < npending; i++) {
            uint64_t base = pending[i].address & ~(uint64_t)(cache_line - 1), offset = base - (uint64_t)(uintptr_t)arena;
            int lost = w.lossy_slot >= 0 && base >= slot_addr[w.lossy_slot] && base < slot_addr[w.lossy_slot] + PAGE &&
                       (w.lossy_line < 0 || (base - slot_addr[w.lossy_slot]) / cache_line == (uint64_t)w.lossy_line);
            if (!lost) memcpy(truth + offset, arena + offset, cache_line);
            if (pending[i].invalid) memcpy(arena + offset, truth + offset, cache_line);
        }
        npending = 0;
        return;
    }
    if ((strcmp(operation, "cvac") && strcmp(operation, "civac")) || !in_arena(address) || npending >= LINE_MAX) {
        bad_cache++;
        return;
    }
    pending[npending].address = address;
    pending[npending++].invalid = operation[1] == 'i';
}

/* CTR_EL0 as the unit reads it (DminLine 4: 64-byte lines, OBSERVED) with another DminLine. */
static uint64_t ctr_with(unsigned dminline) { return (0xB4440004u & ~UINT64_C(0xF0000)) | (uint64_t)dminline << 16; }
static void set_cache_line(unsigned dminline)
{
    w.ctr = ctr_with(dminline);
    cache_line = dminline >= 2 && dminline <= 9 ? 4u << dminline : 64;
}
static void set_defaults(void)
{
    memset(&w, 0, sizeof w);
    w.el = 2;
    w.cntfrq = 19200000;
    w.step = 19200;                     /* 1 ms of the counter per read */
    w.countdown = 8;
    w.feat[1] = ~UINT64_C(0);
    w.have_config = 1;
    w.fault_slot = w.lossy_slot = w.lossy_line = -1;
    w.stack_base = STACK_BASE;
    set_cache_line(4);
    w.desc[w.ndesc++] = (struct desc){7, (uint64_t)(uintptr_t)arena, ARENA_PAGES};
    w.desc[w.ndesc++] = (struct desc){1, PAYLOAD_BASE, 4};
    w.desc[w.ndesc++] = (struct desc){2, STACK_BASE, 16};
    w.desc[w.ndesc++] = (struct desc){2, (uint64_t)(uintptr_t)table_buf, 2};
    w.desc[w.ndesc++] = (struct desc){2, (uint64_t)(uintptr_t)map_buf, 1};
    w.desc[w.ndesc++] = (struct desc){2, (uint64_t)(uintptr_t)config_buf, 1};
}
static void world_memory(void)
{
    for (size_t i = 0; i < (size_t)ARENA_PAGES * PAGE; i++) arena[i] = (uint8_t)(next_random() >> 24);
    memcpy(truth, arena, (size_t)ARENA_PAGES * PAGE);
    memcpy(pristine, arena, (size_t)ARENA_PAGES * PAGE);
    for (unsigned k = 0; k < SLOTS; k++) slot_addr[k] = (uint64_t)(uintptr_t)arena + (uint64_t)slot_page[k] * PAGE;
}
static void put_page_bytes(unsigned slot, const uint8_t *page)
{
    memcpy(arena + (size_t)slot_page[slot] * PAGE, page, PAGE);
    memcpy(truth + (size_t)slot_page[slot] * PAGE, page, PAGE);
    memcpy(pristine + (size_t)slot_page[slot] * PAGE, page, PAGE);
}
static void set_config(uint32_t path, uint32_t countdown)
{
    w.path = path;
    w.countdown = countdown;
    config_blob(w.config, path, countdown, slot_addr);
}
/* Noise everywhere, a configuration, features answering SYSTEM_RESET only. */
static void fresh(uint32_t path, uint32_t countdown)
{
    world_memory();
    set_defaults();
    set_config(path, countdown);
}
/* A page of an earlier boot, as the oracle writes it, with the index and the address fields that are asked for. */
static void make_page(uint8_t *page, uint32_t index_field, uint64_t address_field, uint32_t counter)
{
    struct stamp s;
    memset(&s, 0, sizeof s);
    s.counter = counter;
    s.previous_counter = counter ? counter - 1 : 0;
    s.timestamp = 12345;
    s.frequency = 19200000;
    s.extent_type = 7;
    oracle_page(page, index_field, address_field, &s);
}
static void previous_whole(uint32_t counter0, uint32_t counter1, uint32_t counter2)
{
    uint32_t counters[3] = {counter0, counter1, counter2};
    for (unsigned k = 0; k < 3; k++) {
        uint8_t page[PAGE];
        make_page(page, k, slot_addr[k], counters[k]);
        put_page_bytes(k, page);
    }
}

static struct q1n1_payload_args build_args(void)
{
    struct q1n1_payload_args a;
    struct q1n1_preload_cache *t = (struct q1n1_preload_cache *)table_buf;
    uint64_t stride = w.map_stride_override ? w.map_stride_override : 48;
    memset(&a, 0, sizeof a);
    a.magic = Q1N1_PAYLOAD_ABI_MAGIC;
    a.version = Q1N1_PAYLOAD_ABI_VERSION;
    a.size = sizeof a;
    a.payload_base = PAYLOAD_BASE;
    a.payload_size = 12668;
    a.stack_base = w.stack_base;
    a.stack_size = 65536;
    a.ops.puts = fake_puts; a.ops.hex = fake_hex; a.ops.load32 = fake_load32; a.ops.counter = fake_counter;
    memset(map_buf, 0, PAGE);
    for (unsigned i = 0; i < w.ndesc; i++) {
        uint8_t *d = map_buf + (size_t)i * stride;
        put32(d, w.desc[i].type);
        put64(d + 8, w.desc[i].start);
        put64(d + 24, w.desc[i].pages);
        put64(d + 32, 0x100F);
    }
    a.map_base = (uint64_t)(uintptr_t)map_buf;
    a.map_size = (uint64_t)w.ndesc * stride;
    a.map_stride = stride;
    memset(table_buf, 0, 2 * PAGE);
    t->magic = Q1N1_CACHE_MAGIC;
    t->version = 1;
    t->entry_size = sizeof(struct q1n1_cached_file);
    t->count = 1;
    t->files[0].base = PAYLOAD_BASE;
    t->files[0].file.size = a.payload_size;
    snprintf(t->files[0].file.path, sizeof t->files[0].file.path, "\\SP11\\RETPROBE.BIN");
    if (w.have_config) {
        memcpy(config_buf, w.config, 64);
        t->files[t->count].base = (uint64_t)(uintptr_t)config_buf;
        t->files[t->count].file.size = 64;
        snprintf(t->files[t->count].file.path, sizeof t->files[0].file.path, "\\SP11\\RETPATH.DAT");
        t->count++;
    }
    for (unsigned i = 0; i < w.extra_entries; i++) {     /* other data files, which are never the configuration */
        t->files[t->count].base = (uint64_t)(uintptr_t)map_buf;
        t->files[t->count].file.size = 100 + i;
        snprintf(t->files[t->count].file.path, sizeof t->files[0].file.path, "\\SP11\\DATA%u.DAT", i);
        t->count++;
    }
    a.preload_table = (uint64_t)(uintptr_t)table_buf;
    a.preload_size = 32 + t->count * sizeof(struct q1n1_cached_file);
    return a;
}

/* The buffers the payload is given are only read: a store to one of them, by any instruction and through any pointer, is a stray store. The
 * arena outside the three pages is held to the same rule by arena_outside_pages_unchanged(); an address that is in neither is unmapped here
 * and ASan stops the program. Every run is compared, so a scenario cannot forget to ask. */
static void snapshot_buffers(void)
{
    memcpy(table_snap, table_buf, 2 * PAGE);
    memcpy(map_snap, map_buf, PAGE);
    memcpy(config_snap, config_buf, PAGE);
}
static const char *buffers_changed(void)
{
    if (memcmp(table_snap, table_buf, 2 * PAGE)) return "the preload table";
    if (memcmp(map_snap, map_buf, PAGE)) return "the memory map";
    if (memcmp(config_snap, config_buf, PAGE)) return "the configuration file";
    return NULL;
}

static int arena_outside_pages_unchanged(void);

/* One run: the payload's value, and *reset set when a reset call did not return. */
static uint64_t go(const struct q1n1_payload_args *a, int *reset)
{
    uint64_t value = 0;
    const char *stored;
    nev = loads = counter_calls = bad_lines = bad_smc = bad_at = bad_cache = resets_called = npending = 0;
    first_bad[0] = 0;
    w.now = 1000000;
    if (reset) *reset = 0;
    snapshot_buffers();
    if (setjmp(reset_jump) == 0) value = payload_entry(a);
    else if (reset) *reset = 1;
    if ((stored = buffers_changed()) != NULL) {
        fprintf(stderr, "FAIL: the payload stored to %s, which it is given to read\n", stored);
        exit(1);
    }
    if (!arena_outside_pages_unchanged()) {
        fprintf(stderr, "FAIL: the payload stored to memory outside its three pages\n");
        exit(1);
    }
    return value;
}
static uint64_t run(int *reset)
{
    struct q1n1_payload_args a = build_args();
    return go(&a, reset);
}

/* ---- Reading what the run left --------------------------------------------------------------------------------------------- */

static unsigned lines_n(void) { unsigned n = 0; for (unsigned i = 0; i < nev; i++) n += ev[i].kind == EV_LINE; return n; }
static unsigned smc_n(void) { unsigned n = 0; for (unsigned i = 0; i < nev; i++) n += ev[i].kind == EV_SMC; return n; }
static unsigned smc_with(uint64_t id) { unsigned n = 0; for (unsigned i = 0; i < nev; i++) n += ev[i].kind == EV_SMC && ev[i].id == id; return n; }
static int smc_index(uint64_t id)
{
    for (unsigned i = 0; i < nev; i++) if (ev[i].kind == EV_SMC && ev[i].id == id) return (int)i;
    return -1;
}
/* The log index of the first line that starts with PFX and `text`, or -1. */
static int line_has(const char *text)
{
    char full[220];
    snprintf(full, sizeof full, "%s%s", PFX, text);
    for (unsigned i = 0; i < nev; i++) if (ev[i].kind == EV_LINE && !strncmp(ev[i].text, full, strlen(full))) return (int)i;
    return -1;
}
static int line_contains(const char *needle)
{
    for (unsigned i = 0; i < nev; i++) if (ev[i].kind == EV_LINE && strstr(ev[i].text, needle)) return (int)i;
    return -1;
}
static unsigned cache_n(const char *op) { unsigned n = 0; for (unsigned i = 0; i < nev; i++) n += ev[i].kind == EV_CACHE && !strcmp(ev[i].text, op); return n; }
static int arena_outside_pages_unchanged(void)
{
    for (size_t i = 0; i < (size_t)ARENA_PAGES * PAGE; i++) {
        int inside = 0;
        for (unsigned k = 0; k < SLOTS; k++) if (i / PAGE == slot_page[k]) inside = 1;
        if (!inside && (arena[i] != pristine[i] || truth[i] != pristine[i])) return 0;
    }
    return 1;
}
static int pages_unchanged(void)
{
    for (unsigned k = 0; k < SLOTS; k++)
        if (memcmp(arena + (size_t)slot_page[k] * PAGE, pristine + (size_t)slot_page[k] * PAGE, PAGE) ||
            memcmp(truth + (size_t)slot_page[k] * PAGE, pristine + (size_t)slot_page[k] * PAGE, PAGE)) return 0;
    return 1;
}
static int no_stray_calls(void) { return !bad_lines && !bad_smc && !bad_at && !bad_cache; }
/* A run that stopped before the first store: nothing in memory, no cache operation, no reset call, only the two PSCI_FEATURES calls. */
static int left_alone(void)
{
    return pages_unchanged() && arena_outside_pages_unchanged() && no_stray_calls() && smc_n() == 2 && cache_n("cvac") == 0 &&
           cache_n("civac") == 0 && cache_n("dsb") == 0 && resets_called == 0;
}

/* The stamp the run should have written: the timestamp is the first counter value it read. */
static void expected_stamp(struct stamp *s, uint32_t counter, uint32_t previous_counter, const unsigned previous_state[3])
{
    memset(s, 0, sizeof *s);
    s->counter = counter;
    s->previous_counter = previous_counter;
    s->timestamp = first_counter;
    s->frequency = (uint32_t)w.cntfrq;
    s->feature_reset = (uint32_t)w.feat[0];
    s->feature_reset2 = (uint32_t)w.feat[1];
    s->requested = s->used = w.path;
    for (unsigned k = 0; k < 3; k++) s->previous_state[k] = previous_state[k];
    s->extent_type = 7;
    s->extent_start = (uint64_t)(uintptr_t)arena;
    s->extent_bytes = (uint64_t)ARENA_PAGES * PAGE;
}
static int truth_page_is(unsigned slot, const struct stamp *s)
{
    uint8_t want[PAGE];
    oracle_page(want, slot, slot_addr[slot], s);
    return !memcmp(truth + (size_t)slot_page[slot] * PAGE, want, PAGE) && !memcmp(arena + (size_t)slot_page[slot] * PAGE, want, PAGE);
}
static int all_truth_pages_are(uint32_t counter, uint32_t previous_counter, const unsigned previous_state[3])
{
    struct stamp s;
    expected_stamp(&s, counter, previous_counter, previous_state);
    for (unsigned k = 0; k < SLOTS; k++) if (!truth_page_is(k, &s)) return 0;
    return 1;
}
static void alloc_world(void)
{
    crc_init();
    arena = aligned_alloc(PAGE, (size_t)ARENA_PAGES * PAGE);
    truth = aligned_alloc(PAGE, (size_t)ARENA_PAGES * PAGE);
    pristine = aligned_alloc(PAGE, (size_t)ARENA_PAGES * PAGE);
    table_buf = aligned_alloc(PAGE, 2 * PAGE);
    map_buf = aligned_alloc(PAGE, PAGE);
    config_buf = aligned_alloc(PAGE, PAGE);
    table_snap = aligned_alloc(PAGE, 2 * PAGE);
    map_snap = aligned_alloc(PAGE, PAGE);
    config_snap = aligned_alloc(PAGE, PAGE);
    if (!arena || !truth || !pristine || !table_buf || !map_buf || !config_buf || !table_snap || !map_snap || !config_snap) exit(2);
}
