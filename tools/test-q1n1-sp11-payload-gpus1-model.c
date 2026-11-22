/* SPDX-License-Identifier: MIT */
/* Host model of the GPU stage S1 payload (payloads/gpus1.c, payloads/gpus1d.c): the real runner loop (platform/uefi/sp11-payload-run.c and the write table of
 * sp11-payload-wtab.c) running the real payload source over the real S1 table, against a model of the CX power domain of the Adreno X1-85 and of the blocks behind it.
 * Driven by tools/test-q1n1-sp11-payload-gpus1.py under ASan and UBSan; built once for the live table and once with -DMODEL_DRY=1 for the dry table.
 *
 * The model is this harness's own statement of what the pinned Linux sources and boot 30's words say a votable GDSC and its branches do (docs/SP11-PAYLOAD-WTAB.md,
 * the S1 design): the GCC AHB branch must run before any GPUCC word answers (an unclocked read hangs the bus), the CX GDSC powers some time after its SW_COLLAPSE bit
 * clears, the branches of the domain stop reporting CLK_OFF a while after that, and CX_MISC, the GMU and the RSCC answer only while the domain is on (otherwise the bus
 * hangs, or an SError is raised). None of it is the unit: hardware NOT RUN, evidence EXPERIMENTAL.
 *
 *   normal      the whole run: one store, the order of everything, the state comparison, the restore
 *   found       the register path or the domain not as found: nothing is written, nothing behind the domain is read
 *   stops       the domain that never powers, a branch that never clocks, a store that faults, an SError on the store
 *   undo        another master holds the vote: the domain stays on, and the run says so
 *   mapping     the page of the domain word is not Device memory: the dry table opens and says so, the live table is refused
 *   drift       a word of the always-readable blocks that differs after the undo, a word that cannot be read
 *   pages       the lines of the whole page
 *   draft       built twice more: the live table is a draft, which the runner as the Makefile builds it refuses at open, and which the payload refuses itself when the runner
 *               takes it. The blocks behind the domain (CX_MISC, the GMU, the RSCC) are not read by this payload: the model answers them (or hangs) so that a read is seen.
 */
#include <inttypes.h>
#include <setjmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SNAP_PLATFORM_SP11 1
#define Q1N1_SP11_PAYLOAD 1
#define Q1N1_SP11_WTAB 1
#include "sp11-payload.h"
#include "sp11-payload-wtab.h"
#include "sha256.h"
#include "payload-wtab.h"

/* The payload opens a page-aligned copy of its table that the harness loads as its image (the runner loads payloads from page boundaries only). */
static uint8_t table_page[4096] __attribute__((aligned(4096)));
#define WTAB_TABLE_ADDRESS ((const struct q1n1_wtab_header *)table_page)
#define payload_entry gpus1_entry
#ifdef MODEL_DRY
#define GPUS1_DRY 1
#endif
/* The live table is a draft: the model of its code runs with the payload's own refusal compiled out (as the runner's is, by Q1N1_WTAB_ALLOW_DRAFT in the build line), except in
 * the two builds that test the refusals. */
#if !defined(MODEL_DRY) && !defined(MODEL_DRAFT_RUNNER) && !defined(MODEL_DRAFT_PAYLOAD)
#define GPUS1_ALLOW_DRAFT 1
#endif
#include "gpus1.c"
#undef payload_entry

#if defined(MODEL_DRY)
#define MODE "DRY"
#define EXPECT_DRY 1
#elif defined(MODEL_DRAFT_RUNNER)
#define MODE "DRAFT_RUNNER"
#define EXPECT_DRY 0
#elif defined(MODEL_DRAFT_PAYLOAD)
#define MODE "DRAFT_PAYLOAD"
#define EXPECT_DRY 0
#else
#define MODE "LIVE"
#define EXPECT_DRY 0
#endif

static unsigned checks, fails;
static const char *suite_name = "";
#define CHECK(name, cond) do { \
        checks++; \
        if (!(cond)) { fails++; fprintf(stderr, "FAIL %s/%s (%s:%d)\n", suite_name, name, __FILE__, __LINE__); if (getenv("GPUS1_DEBUG")) dump(); } \
    } while (0)

#define HZ 19200000u
#define US(n) ((uint64_t)(n) * HZ / 1000000u)

/* ---- The model ---------------------------------------------------------------------------------------------------------------- */

#define A_CFGA 0x00171004u
#define A_MNOC 0x00171010u
#define A_AXI 0x0017115cu
#define A_GRF 0x03d9931cu
#define A_HRF 0x03d993f0u
#define A_CXGD 0x03d99108u
#define A_CXST 0x03d9953cu
#define A_AHB 0x03d9911cu
#define A_CXGMU 0x03d9913cu
#define A_CXO 0x03d99144u
#define A_HUBCX 0x03d99148u
#define A_DEMET 0x03d9900cu
#define GCC_LO 0x00100000u
#define GCC_HI 0x00300000u
#define GPUCC_LO 0x03d90000u
#define GPUCC_HI 0x03d9a000u

enum { EV_LINE, EV_STORE };
struct event { int kind; uint32_t addr, value; char text[128]; };
static struct event ev[2048];
static unsigned nev;

static struct {
    uint32_t cfga, gdscr, grf, hrf;
    uint64_t gdscr_t;
    int dom_on, was_on, drift;
    unsigned dom_on_us, dom_off_us, clk_us;
    int dom_stuck;              /* the domain never powers */
    int dom_held;               /* another master holds the vote: the domain never powers off once on */
    int clk_never;              /* the branches of the domain never stop reporting CLK_OFF */
    uint32_t fault_read, hang_read, fault_store, hang_store, serror_store, fault_after_cycle;
    int window_serror;          /* a read of a block behind the domain while the domain is off raises an SError instead of hanging the bus */
    int serror_pending;
    unsigned stray_stores, nstores, unknown_reads, gpucc_reads_unclocked, closed_window_reads, window_reads, stores_before_rows, nreads;
    int hung;
    int attr_set;               /* the platform reports `attr_page_class` for the page of the CX GDSC word instead of Device */
    int attr_page_class;        /* a Q1N1_WTAB_ATTR_ value (UNKNOWN is 0) */
} D;
static uint64_t now_ticks;
static jmp_buf hang_jump;

static void dump(void)
{
    for (unsigned i = 0; i < nev; i++) {
        if (ev[i].kind == EV_LINE) fprintf(stderr, "    | %s\n", ev[i].text);
        else fprintf(stderr, "    | STORE %#" PRIx32 " <- %#" PRIx32 "\n", ev[i].addr, ev[i].value);
    }
}

static void emit_event(int kind, uint32_t addr, uint32_t value, const char *text)
{
    if (nev >= sizeof ev / sizeof ev[0]) { fprintf(stderr, "FAIL harness: event log full\n"); exit(2); }
    ev[nev].kind = kind; ev[nev].addr = addr; ev[nev].value = value;
    snprintf(ev[nev].text, sizeof ev[nev].text, "%s", text ? text : "");
    nev++;
}

static void dev_found(void)
{
    memset(&D, 0, sizeof D);
    D.cfga = 0x1;
    D.gdscr = 0x0022f801;
    D.dom_on_us = 5; D.dom_off_us = 5; D.clk_us = 3;
    nev = 0; now_ticks = 100000;
}

static void dom_update(void)
{
    if (!(D.gdscr & 1) && !D.dom_on && !D.dom_stuck && now_ticks >= D.gdscr_t + US(D.dom_on_us)) D.dom_on = D.was_on = 1;
    if ((D.gdscr & 1) && D.dom_on && !D.dom_held && now_ticks >= D.gdscr_t + US(D.dom_off_us)) D.dom_on = 0;
}
static int branches_run(void)
{
    dom_update();
    return D.dom_on && !D.clk_never && now_ticks >= D.gdscr_t + US(D.dom_on_us + D.clk_us);
}
static void hang(void) { D.hung = 1; longjmp(hang_jump, 1); }

static int in_window(uint32_t addr)
{
    return (addr >= 0x03d9e000u && addr < 0x03d9f000u) || (addr >= 0x03d6a000u && addr < 0x03d90000u) || (addr >= 0x03d50000u && addr < 0x03d60000u);
}

static int dev_read(uint32_t addr, uint32_t *out)
{
    D.nreads++;
    if (addr == D.fault_read) return 1;
    if (addr == D.fault_after_cycle && D.was_on && !D.dom_on) return 1;
    if (addr == D.hang_read) hang();
    dom_update();
    if (addr >= GCC_LO && addr < GCC_HI) {
        switch (addr) {
        case A_CFGA: *out = D.cfga ? 0x1u : 0x80000000u; return 0;
        case A_MNOC: *out = D.drift && D.was_on ? 0x82000013u : 0x82000003u; return 0;
        case A_AXI: *out = 0x82300003u; return 0;
        default: D.unknown_reads++; return 1;
        }
    }
    if (addr >= GPUCC_LO && addr < GPUCC_HI) {
        if (!(D.cfga & 1)) { D.gpucc_reads_unclocked++; hang(); }       /* GPUCC is behind the GCC AHB branch: an unclocked read hangs the bus */
        switch (addr) {
        case A_GRF: *out = D.grf; return 0;
        case A_HRF: *out = D.hrf; return 0;
        case A_AHB: case A_DEMET: *out = addr == A_DEMET ? 1u : 0u; return 0;
        case A_CXGD: *out = D.gdscr; return 0;
        case A_CXST: *out = D.dom_on ? 0x80000000u : 0u; return 0;
        case A_CXGMU: *out = 0x2001u | (branches_run() ? 0u : 0x80000000u); return 0;
        case A_CXO: case A_HUBCX: *out = 0x1u | (branches_run() ? 0u : 0x80000000u); return 0;
        default: D.unknown_reads++; return 1;
        }
    }
    if (in_window(addr)) {
        if (!D.dom_on) {
            D.closed_window_reads++;
            if (!D.window_serror) hang();
            D.serror_pending = 1;
            *out = 0xffffffffu;
            return 0;
        }
        D.window_reads++;
        *out = 0xb10c0000u | (addr & 0xffffu);
        return 0;
    }
    D.unknown_reads++;
    return 1;
}

static int dev_store(uint32_t addr, uint32_t value)
{
    D.nstores++;
    emit_event(EV_STORE, addr, value, "");
    if (addr != A_CXGD) D.stray_stores++;
    if (addr == D.fault_store) return 1;
    if (addr == D.hang_store) hang();
    if (addr == D.serror_store) { D.serror_pending = 1; D.serror_store = 0; }
    dom_update();
    if (addr != A_CXGD) return 1;
    D.gdscr = value;
    D.gdscr_t = now_ticks;
    return 0;
}

static void model_emit(const char *line)
{
    emit_event(EV_LINE, 0, 0, line);
}
static int env_read32(uint32_t pa, uint32_t *out) { return dev_read(pa, out); }
static int env_store32(uint32_t pa, uint32_t value) { return dev_store(pa, value); }
static int env_serror(void)
{
    int pending = D.serror_pending;
    D.serror_pending = 0;
    return pending;
}
static uint64_t env_counter(void)
{
    now_ticks += 19;
    return now_ticks;
}
static int env_attr(uint32_t pa)
{
    if (D.attr_set && (pa & ~0xfffu) == (A_CXGD & ~0xfffu)) return D.attr_page_class;
    return Q1N1_WTAB_ATTR_DEVICE;
}
static struct q1n1_wtab_env wenv = {model_emit, env_read32, env_store32, env_serror, env_counter, HZ, env_attr};

/* ---- The real runner loop ----------------------------------------------------------------------------------------------------- */

static struct q1n1_payload_loaded loaded;
static struct q1n1_preload_cache *cache;

static void chain_emit(const char *line) { model_emit(line); }
static void chain_sync(uint64_t base, uint64_t bytes) { (void)base; (void)bytes; }
static uint64_t chain_call(uint64_t entry, const struct q1n1_payload_args *args, uint64_t top)
{
    (void)entry; (void)top;
    return gpus1_entry(args);
}
static int chain_guarded(int kind, uint64_t dst, uint64_t src, uint64_t size)
{
    if (kind != Q1N1_PAYLOAD_G_COPY32 || size != 4) { fprintf(stderr, "FAIL tripwire: the runner asked for guarded kind %d\n", kind); exit(3); }
    uint32_t value = 0;
    int rc = dev_read((uint32_t)src, &value);
    if (!rc) *(uint32_t *)(uintptr_t)dst = value;
    return rc;
}
static struct q1n1_payload_env chain_env = {.emit = chain_emit, .sync_code = chain_sync, .call = chain_call, .guarded = chain_guarded, .counter = env_counter};

static void build_chain(void)
{
    free(cache);
    cache = aligned_alloc(4096, 8192);
    memset(cache, 0, 8192);
    memset(&loaded, 0, sizeof loaded);
    loaded.count = 1;
    cache->magic = Q1N1_CACHE_MAGIC; cache->version = 1; cache->count = 1; cache->entry_size = sizeof cache->files[0];
    memset(table_page, 0, sizeof table_page);
    memcpy(table_page, &WTAB_TABLE_SYMBOL, sizeof WTAB_TABLE_SYMBOL);
    struct q1n1_payload_file *f = &loaded.file[0];
    f->base = (uint64_t)(uintptr_t)table_page;
    f->bytes = sizeof WTAB_TABLE_SYMBOL;
    f->alloc = 4096;
    f->memory_type = Q1N1_PAYLOAD_TYPE_CODE;
    q1n1_sha256((const void *)(uintptr_t)f->base, (size_t)f->bytes, f->sha256);
    loaded.code_count = 1;
    cache->files[0].base = f->base;
    cache->files[0].allocation = f->alloc;
    cache->files[0].file.size = f->bytes;
    memcpy(cache->files[0].file.sha256, f->sha256, 32);
    snprintf(cache->files[0].file.path, sizeof cache->files[0].file.path, "\\SP11\\S1.BIN");
    loaded.table_base = (uint64_t)(uintptr_t)cache;
    /* The runner lets load32 write only inside the stack it was given; the host payload runs on the host's own stack. */
    uintptr_t frame = (uintptr_t)__builtin_frame_address(0);
    loaded.stack_base = (frame - 48 * 1024) & ~(uintptr_t)15;
    loaded.stack_alloc = Q1N1_PAYLOAD_STACK_BYTES;
}

static struct q1n1_payload_result result;

/* The unit's memory map as boot 6 recorded it, for what matters here: RAM at 2 GiB and nothing over any address of the table. */
static unsigned lines_with(const char *prefix);

static void run_payload(void)
{
    static uint8_t map[48 * 2];
    uint32_t type = 7;
    uint64_t start = 0x80000000u, pages = 0x1000;
    memset(map, 0, sizeof map);
    memcpy(map, &type, 4); memcpy(map + 8, &start, 8); memcpy(map + 24, &pages, 8);
    struct q1n1_payload_platform plat = {.fb_base = 0xe4800000, .fb_bytes = 0x1000, .map_base = (uint64_t)(uintptr_t)map, .map_size = 48,
                                         .map_stride = 48, .fb_width = 100, .fb_height = 100, .fb_stride = 100, .fb_format = 1};
    build_chain();
    q1n1_wtab_attach(&wenv);
    memset(&result, 0, sizeof result);
    if (!setjmp(hang_jump)) q1n1_payload_run(&chain_env, &loaded, &plat, &result);
    /* The runner refuses a hex or puts pointer outside the stack (and the image): the real payload never hands one over, in any scenario. */
    CHECK("no_op_pointer_of_the_payload_is_refused", lines_with("PAYLOAD OP REFUSED") == 0);
}

/* ---- Looking at what happened -------------------------------------------------------------------------------------------------- */

/* The two draft builds run one suite and use few of these. */
#pragma clang diagnostic ignored "-Wunused-function"

static int line_index(const char *prefix)
{
    for (unsigned i = 0; i < nev; i++)
        if (ev[i].kind == EV_LINE && !strncmp(ev[i].text, prefix, strlen(prefix))) return (int)i;
    return -1;
}
static unsigned lines_with(const char *prefix)
{
    unsigned n = 0;
    for (unsigned i = 0; i < nev; i++) n += ev[i].kind == EV_LINE && !strncmp(ev[i].text, prefix, strlen(prefix));
    return n;
}
static unsigned lines_total(void)
{
    unsigned n = 0;
    for (unsigned i = 0; i < nev; i++) n += ev[i].kind == EV_LINE;
    return n;
}
static const char *end_line(void)
{
    const char *last = "";
    for (unsigned i = 0; i < nev; i++)
        if (ev[i].kind == EV_LINE && !strncmp(ev[i].text, "WTAB END", 8)) last = ev[i].text;
    return last;
}
static int ret(void) { return result.called == 1 ? (int)result.call[0].retval : -1; }
static int found_state(void)
{
    return D.gdscr == 0x0022f801 && !D.dom_on && D.cfga == 1 && D.stray_stores == 0;
}
/* Every device word the table writes is written only by the runner, and never before the three checks of step 0 ran. */
static int first_store_after_step0(void)
{
    for (unsigned i = 0; i < nev; i++)
        if (ev[i].kind == EV_STORE) return line_index("C 2 HUBRCG") >= 0 && (int)i > line_index("C 2 HUBRCG");
    return 1;
}

/* ---- The suites --------------------------------------------------------------------------------------------------------------- */

static void suite_normal(void)
{
    dev_found();
    run_payload();
    CHECK("status", result.status == Q1N1_PAYLOAD_RUN_OK && result.called == 1);
    CHECK("returns_zero", ret() == 0);
    CHECK("draft_line_iff_draft", lines_with("PAYLOAD GPUS1 TABLE IS A DRAFT") == (WTAB_DRAFT ? 1u : 0u));
    CHECK("opened", lines_with("WTAB OPEN") == 1);
    CHECK("one_end_restored", lines_with("WTAB END RESULT=RESTORED") == 1 && lines_with("WTAB END") == 1);
    if (EXPECT_DRY) {
        CHECK("dry.no_store_at_all", D.nstores == 0 && D.dom_on == 0 && D.gdscr == 0x0022f801);
        CHECK("dry.no_read_behind_the_domain", D.window_reads == 0 && D.closed_window_reads == 0);
        CHECK("dry.end_line", !strcmp(end_line(), "WTAB END RESULT=RESTORED WHY=OK ROWS=4 STORES=0 UNDOS=0 RESTORED=0 OF=0"));
    } else {
        CHECK("one_store_to_the_domain_control", D.nstores == 2 && D.stray_stores == 0);
        unsigned first = 0, second = 0;
        for (unsigned i = 0; i < nev; i++) {
            if (ev[i].kind != EV_STORE) continue;
            if (!first) first = ev[i].value; else second = ev[i].value;
        }
        CHECK("store_values_clear_then_set_collapse", first == 0x0022f800u && second == 0x0022f801u);
        CHECK("end_line", !strcmp(end_line(), "WTAB END RESULT=RESTORED WHY=OK ROWS=11 STORES=1 UNDOS=1 RESTORED=1 OF=1"));
        CHECK("no_read_behind_the_domain", D.closed_window_reads == 0 && D.window_reads == 0);
        CHECK("no_refused_window_read", lines_with("WTAB READ REFUSED") == 0);
        CHECK("pause_line_before_the_store", line_index("WTAB NEXT STEP=1") >= 0 && line_index("WTAB NEXT STEP=1") < line_index("W 3 CXGDSC"));
        CHECK("undo_before_the_state_line", line_index("U 3") >= 0 && line_index("U 3") < line_index("PAYLOAD GPUS1 STATE"));
    }
    CHECK("attr_line_for_every_row_before_the_open_line", lines_with("WTAB ATTR ") == WTAB_ROWS && line_index("WTAB ATTR ") >= 0 && line_index("WTAB OPEN") == line_index("WTAB ATTR ") + (int)WTAB_ROWS);
    CHECK("attr_of_the_domain_word_is_printed", lines_with("WTAB ATTR CXGDSC DEVICE") == 1);
    CHECK("table_lines_within_the_budget", q1n1_wtab_last()->lines == (EXPECT_DRY ? 10u : 27u) && q1n1_wtab_last()->dropped == 0);
    CHECK("the_domain_is_as_found", found_state());
    CHECK("state_line", lines_with("PAYLOAD GPUS1 STATE RESTORED=YES WORDS=0X8") == 1);
    CHECK("payload_end_after_runner_end", line_index("PAYLOAD GPUS1 END") > line_index("WTAB END"));
    CHECK("no_unknown_word_read", D.unknown_reads == 0 && D.gpucc_reads_unclocked == 0 && !D.hung);
    CHECK("no_write_before_step0_done", first_store_after_step0());
    CHECK("snapshots", lines_with("PAYLOAD GPUS1 BEFORE") == 3 && lines_with("PAYLOAD GPUS1 " ON_LABEL) == 3);
    CHECK("no_auto_unwind", lines_with("WTAB AUTO_UNWIND") == 0);
    CHECK("no_line_dropped", result.call[0].dropped == 0);
    if (getenv("GPUS1_PAGE")) dump();
}

static void suite_found(void)
{
    /* The GCC AHB branch is off: GPUCC would hang the bus. The very first row stops the run, and not one GPUCC word is read. */
    dev_found(); D.cfga = 0;
    run_payload();
    CHECK("ahb_off.stops", ret() == 1 && lines_with("WTAB STOP WHY=FOUND ROW=0") == 1);
    CHECK("ahb_off.nothing_read_unclocked", D.gpucc_reads_unclocked == 0 && !D.hung && D.nstores == 0 && D.window_reads == 0);
    CHECK("ahb_off.payload_says_so", lines_with("PAYLOAD GPUS1 STOPPED=STEP0") == 1);

    /* A root clock generator that is not parked on XO: the table refuses before any store. */
    dev_found(); D.grf = 0x100;
    run_payload();
    CHECK("gmu_rcg_not_parked.refused", ret() == 1 && lines_with("WTAB STOP WHY=FOUND ROW=1") == 1 && D.nstores == 0 && D.window_reads == 0);
    dev_found(); D.hrf = 0x1;
    run_payload();
    CHECK("hub_rcg_not_parked.refused", ret() == 1 && lines_with("WTAB STOP WHY=FOUND ROW=2") == 1 && D.nstores == 0);
    dev_found(); D.gdscr = 0x0022f800; D.dom_on = 1;
    run_payload();
    CHECK("domain_already_on.refused", ret() == 1 && lines_with("WTAB STOP WHY=FOUND ROW=3") == 1 && D.nstores == 0 && D.window_reads == 0);
    dev_found(); D.gdscr = 0x0022f801 | 0x2;
    run_payload();
    CHECK("hw_control_bit_set.refused", ret() == 1 && lines_with("WTAB STOP WHY=FOUND ROW=3") == 1 && D.nstores == 0);
    dev_found(); D.gdscr = 0x00000001;
    run_payload();
    CHECK("wait_values_not_as_linux.refused", ret() == 1 && lines_with("WTAB STOP WHY=FOUND ROW=3") == 1 && D.nstores == 0);
    dev_found(); D.fault_read = A_GRF;
    run_payload();
    CHECK("pre_read_fault.stops_with_no_store", ret() == 1 && lines_with("WTAB STOP WHY=FAULT ROW=1") == 1 && D.nstores == 0);
}

static void suite_stops(void)
{
    if (EXPECT_DRY) return;
    dev_found(); D.dom_stuck = 1;
    run_payload();
    CHECK("never_powers.readback", ret() == 1 && lines_with("WTAB STOP WHY=READBACK ROW=3") == 1);
    CHECK("never_powers.undone", found_state() && D.window_reads == 0 && D.closed_window_reads == 0);
    CHECK("never_powers.end", !strncmp(end_line(), "WTAB END RESULT=RESTORED WHY=READBACK", 37));
    CHECK("never_powers.payload_says_so", lines_with("PAYLOAD GPUS1 STOPPED=STEP1") == 1 && lines_with("PAYLOAD GPUS1 END") == 0);

    dev_found(); D.clk_never = 1;
    run_payload();
    CHECK("clock_never_runs.stops_at_the_first_branch_check", ret() == 1 && lines_with("WTAB STOP WHY=READBACK ROW=5") == 1);
    CHECK("clock_never_runs.undone_and_nothing_read_behind", found_state() && D.window_reads == 0 && D.closed_window_reads == 0);
    CHECK("clock_never_runs.payload", lines_with("PAYLOAD GPUS1 STOPPED=STEP2") == 1);

    dev_found(); D.fault_store = A_CXGD;
    run_payload();
    CHECK("store_fault.stops", ret() == 1 && lines_with("WTAB STOP WHY=FAULT ROW=3") == 1 && D.window_reads == 0);
    CHECK("store_fault.undone", D.gdscr == 0x0022f801 && !D.dom_on);

    dev_found(); D.serror_store = A_CXGD;
    run_payload();
    CHECK("serror_on_the_store.stops_at_once", ret() == 1 && lines_with("WTAB STOP WHY=SERROR ROW=3") == 1 && D.window_reads == 0);
    CHECK("serror_on_the_store.undone", D.gdscr == 0x0022f801);

    dev_found(); D.hang_store = A_CXGD;
    run_payload();
    CHECK("store_hang.is_a_hang_and_the_last_line_names_the_store", D.hung && D.window_reads == 0);
    int last_line = -1;
    for (unsigned i = 0; i < nev; i++) if (ev[i].kind == EV_LINE) last_line = (int)i;
    CHECK("store_hang.last_line_is_the_w_line", last_line >= 0 && !strncmp(ev[last_line].text, "W 3 CXGDSC", 10));
}

static void suite_undo(void)
{
    if (EXPECT_DRY) return;
    /* Another master holds the vote: the runner's undo cannot clear the status bit, the domain stays on, and neither the runner nor the payload calls that restored. */
    dev_found(); D.dom_held = 1;
    run_payload();
    CHECK("held_vote.restore_fails_and_says_so", ret() == 1 && lines_with("PAYLOAD GPUS1 UNDO FAILED") == 1 && lines_with("WTAB END RESULT=UNDO_FAILED") == 1 && D.dom_on);
    CHECK("held_vote.no_state_claim", lines_with("PAYLOAD GPUS1 STATE RESTORED=YES") == 0 && lines_with("PAYLOAD GPUS1 END") == 0);
    CHECK("held_vote.nothing_behind_the_domain_was_read", D.window_reads == 0 && D.closed_window_reads == 0);
}

/* The page of the CX GDSC word is not Device memory (or its mapping is unknown or absent): the dry table, whose rows only read, opens and prints it; the live table, which
 * writes that word, is refused before a single word is read. */
static void suite_mapping(void)
{
    static const struct { int cls; const char *tag; } cases[] = {
        {Q1N1_WTAB_ATTR_NORMAL, "NORMAL"}, {Q1N1_WTAB_ATTR_NONE, "NONE"}, {Q1N1_WTAB_ATTR_UNKNOWN, "UNKNOWN"},
    };
    for (unsigned i = 0; i < sizeof cases / sizeof cases[0]; i++) {
        char name[64], line[48];
        dev_found(); D.attr_set = 1; D.attr_page_class = cases[i].cls;
        run_payload();
        snprintf(line, sizeof line, "WTAB ATTR CXGDSC %s", cases[i].tag);
        snprintf(name, sizeof name, "%s.attr_line_names_the_class", cases[i].tag);
        CHECK(name, lines_with(line) == 1);
        if (EXPECT_DRY) {
            snprintf(name, sizeof name, "%s.the_dry_run_opens_and_runs", cases[i].tag);
            CHECK(name, ret() == 0 && lines_with("WTAB REFUSED") == 0 && D.nstores == 0 && lines_with("WTAB OPEN") == 1);
        } else {
            snprintf(name, sizeof name, "%s.the_live_table_is_refused_before_any_read", cases[i].tag);
            CHECK(name, ret() == 3 && lines_with("WTAB REFUSED=ROW_ATTR AT=3") == 1 && D.nreads == 0 && D.nstores == 0 && lines_with("PAYLOAD GPUS1 REFUSED=OPEN") == 1);
            snprintf(name, sizeof name, "%s.the_domain_is_untouched", cases[i].tag);
            CHECK(name, found_state() && lines_with("WTAB OPEN") == 0 && lines_with("WTAB END") == 0);
        }
    }
}

/* The two refusals of a draft table. As the Makefile builds the runner (no allowance), open refuses it: no ATTR line, no read, no store. When the runner takes it, the payload
 * says that the table is a draft and returns before it asks for a row. */
static void suite_draft(void)
{
    dev_found();
    run_payload();
#if defined(MODEL_DRAFT_RUNNER)
    CHECK("runner.refuses_at_open", lines_with("WTAB REFUSED=DRAFT") == 1 && lines_with("WTAB OPEN") == 0 && lines_with("WTAB ATTR ") == 0);
    CHECK("runner.the_payload_says_so", ret() == 3 && lines_with("PAYLOAD GPUS1 REFUSED=OPEN") == 1);
    CHECK("runner.nothing_read_nothing_written", D.nreads == 0 && D.nstores == 0 && found_state());
#else
    CHECK("payload.the_runner_opened_the_table", lines_with("WTAB OPEN GPUS1-DRAFT") == 1 && lines_with("WTAB REFUSED") == 0);
    CHECK("payload.says_the_table_is_a_draft_and_returns", ret() == 5 && lines_with("PAYLOAD GPUS1 TABLE IS A DRAFT") == 1 && lines_with("PAYLOAD GPUS1 BEFORE") == 0);
    CHECK("payload.no_row_asked_no_store", lines_with("C 0 ") == 0 && D.nstores == 0 && D.nreads == 0 && found_state());
    CHECK("payload.the_run_ends_by_the_runner", lines_with("WTAB AUTO_UNWIND") + lines_with("WTAB END") >= 1);
#endif
}

static void suite_drift(void)
{
    if (EXPECT_DRY) return;
    /* The runner's undo verified and the domain is off, but a word of the always-readable blocks is not what it was before: the payload says so and returns 4. */
    dev_found(); D.drift = 1;
    run_payload();
    CHECK("changed_word.is_reported", ret() == 4 && lines_with("PAYLOAD GPUS1 STATE RESTORED=NO CHANGED=0X2") == 1);
    CHECK("changed_word.after_lines_and_end", lines_with("PAYLOAD GPUS1 AFTER") == 3 && lines_with("PAYLOAD GPUS1 END") == 1);
    CHECK("changed_word.runner_still_restored", !strcmp(end_line(), "WTAB END RESULT=RESTORED WHY=OK ROWS=11 STORES=1 UNDOS=1 RESTORED=1 OF=1") && found_state());

    /* A word of a snapshot that cannot be read: the comparison is UNKNOWN, never YES. */
    dev_found(); D.fault_after_cycle = A_MNOC;
    run_payload();
    CHECK("faulted_word.unknown_not_yes", ret() == 4 && lines_with("PAYLOAD GPUS1 STATE RESTORED=UNKNOWN BAD=0X2") == 1 && lines_with("PAYLOAD GPUS1 STATE RESTORED=YES") == 0);
}

static void suite_pages(void)
{
    dev_found();
    run_payload();
    CHECK("table_lines_within_the_budget_of_32", q1n1_wtab_last()->lines <= Q1N1_WTAB_LINES_MAX && q1n1_wtab_last()->dropped == 0 && result.call[0].dropped == 0);
    CHECK("payload_lines_within_the_runner_limit", result.call[0].lines <= 40);
    for (unsigned i = 0; i < nev; i++)
        if (ev[i].kind == EV_LINE) CHECK("line_fits_the_page", strlen(ev[i].text) <= 100);
}

int main(void)
{
#if defined(MODEL_DRAFT_RUNNER) || defined(MODEL_DRAFT_PAYLOAD)
    static const struct { const char *name; void (*run)(void); } suites[] = {{"draft", suite_draft}};
#else
    static const struct { const char *name; void (*run)(void); } suites[] = {
        {"normal", suite_normal}, {"found", suite_found}, {"stops", suite_stops}, {"undo", suite_undo}, {"mapping", suite_mapping}, {"drift", suite_drift}, {"pages", suite_pages},
    };
#endif
    for (unsigned i = 0; i < sizeof suites / sizeof suites[0]; i++) {
        unsigned before = fails;
        suite_name = suites[i].name;
        suites[i].run();
        printf("suite %-8s %s\n", suites[i].name, fails == before ? "ok" : "FAILED");
    }
    printf("MODEL %s CHECKS %u FAILS %u\n", MODE, checks, fails);
    return fails ? 1 : 0;
}
