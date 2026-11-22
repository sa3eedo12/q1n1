/* SPDX-License-Identifier: MIT */
/* Host tests of the runner's write table (platform/uefi/sp11-payload-wtab.c) against a fake device that can fault, raise an SError, stick, hang
 * and run on a counter that lies. Driven by tools/test-q1n1-sp11-payload-wtab.py under ASan and UBSan. The program is five files: this one (the fake device and
 * the suites of a run), -rules.c, -open.c, -faults.c and -ops.c, which share test-q1n1-sp11-payload-wtab-fixture.h.
 *
 *   validate   (-rules.c) every refusal rule of the table, one damaged field at a time, in the order of the reasons; the draft name
 *   lines      (-rules.c) the line budget at its edge: the stop, the undo and the END always fit
 *   run        a whole run, the stores it makes and in which order, the line before each store, the undo in reverse, the END line
 *   stops      every way a run can stop (found value, fault, SError, read-back, counter, order, index) and what each leaves on the device
 *   undo       an undo that fails to verify, an SError in the undo, a row that was irreversible
 *   open       (-open.c) the table that is not in the payload's image, opened twice, over RAM, over no memory map; the mapping attribute of each row;
 *              what the platform must offer; the draft that is refused
 *   faults     (-faults.c) the late error response, the undo that waits, the counter that stops being one, the undo store that faults, the mapping of the row
 *              and not of its read-back, the settle time, the line that cannot be printed before a store
 *   gate       the reads of a window: closed, open, closed again, an SError on one
 *   hang       what the page shows when a store never returns
 *   finish     the payload that returns early, and the run ended once
 *   chain      the real q1n1_payload_run with the reference payload (tools/wtab-ref/ref-payload.c): arguments, gating of loads, a second payload
 *   ops        (-ops.c) the pointers a payload gives ops.hex, ops.puts and ops.load32: refused outside the stack (the image too, for puts), counted, on the page once
 *
 *   tools/test-q1n1-sp11-payload-wtab --validate FILE   prints "REASON <name> <index>" for the table in FILE (the differential test of the Python rules)
 *   tools/test-q1n1-sp11-payload-wtab --seed-run         runs the chain once with a seeded reference payload (S38 to S40) and prints what became of its pointer
 *
 * The fake device is the harness's own statement of what a power domain and two clocks do: nothing in it is the unit. Hardware: NOT RUN.
 * Evidence: EXPERIMENTAL (host model only). */
#include "test-q1n1-sp11-payload-wtab-fixture.h"
#include "wtab-ref-table.h"

/* The reference payload, compiled for the host: the code the policy tooling audits as a binary. The runner only loads a payload from a page
 * boundary (q1n1_preload_verify), so the "image" of the chain suite is a page-aligned copy of the table, and the payload opens that. */
uint8_t table_page[4096] __attribute__((aligned(4096)));
#define WTAB_TABLE_ADDRESS ((const struct q1n1_wtab_header *)table_page)
#define payload_entry ref_payload_entry
#include REF_PAYLOAD_SOURCE
#undef payload_entry

unsigned checks, fails;
const char *suite_name = "";

/* ---- The fake device ---------------------------------------------------------------------------------------------------------- */

struct event ev[4096];
unsigned nev;

struct fake_device D;
uint64_t now_ticks;
unsigned tick_step, counter_mode, counter_calls;
jmp_buf hang_jump;

static void emit_event(int kind, uint32_t addr, uint32_t value, const char *text)
{
    if (nev >= sizeof ev / sizeof ev[0]) { fprintf(stderr, "FAIL harness: event log full\n"); exit(2); }
    ev[nev].kind = kind; ev[nev].addr = addr; ev[nev].value = value;
    snprintf(ev[nev].text, sizeof ev[nev].text, "%s", text ? text : "");
    nev++;
}

/* The mapping the fake platform reports: Device everywhere, but for one page that a scenario sets (attr_page, attr_class) and a whole-platform override (attr_all). */
uint32_t attr_page;
int attr_class, attr_all;
static int env_attr(uint32_t pa)
{
    if (attr_page && (pa & ~0xfffu) == attr_page) return attr_class;
    return attr_all;
}

static void fake_emit(const char *line);
static uint64_t env_counter(void);

void dev_found(void)
{
    memset(&D, 0, sizeof D);
    attr_page = 0; attr_class = 0; attr_all = Q1N1_WTAB_ATTR_DEVICE;
    D.gate = 0x1; D.dctl = 0x0022f801; D.clka = 0; D.clkb = 0;
    D.dom_on_us = 5; D.dom_off_us = 5; D.clk_us = 3;
    nev = 0; now_ticks = 100000; tick_step = 19; counter_mode = 0; counter_calls = 0;
    wenv.emit = fake_emit; wenv.counter = env_counter; wenv.counter_hz = HZ;
}

static void dom_update(void)
{
    if (!(D.dctl & 1) && !D.dom_on && !D.dom_stuck && now_ticks >= D.dctl_t + US(D.dom_on_us)) D.dom_on = 1;
    if ((D.dctl & 1) && D.dom_on && !D.dom_noclear && now_ticks >= D.dctl_t + US(D.dom_off_us)) D.dom_on = 0;
}
static int clk_running(uint32_t value, uint64_t since)
{
    dom_update();
    return (value & 1) && D.dom_on && now_ticks >= since + US(D.clk_us);
}
static int block_open(void) { return clk_running(D.clka, D.clka_t) && clk_running(D.clkb, D.clkb_t); }
static void hang(void) { D.hung = 1; longjmp(hang_jump, 1); }

static int dev_read(uint32_t addr, uint32_t *out)
{
    D.nreads++;
    if (addr == D.fault_read) return 1;
    if (addr == D.hang_read) hang();
    if (addr == D.serror_read) { D.serror_pending = 1; D.serror_read = 0; }       /* one error response, raised by the read that follows */
    dom_update();
    if (addr >= A_PLAIN && addr < A_PLAIN + 16) { *out = D.plain[(addr - A_PLAIN) / 4]; return 0; }
    switch (addr) {
    case A_GATE: *out = D.gate; return 0;
    case A_DCTL: *out = D.dctl; return 0;
    case A_DSTS: D.dsts_reads++; *out = D.dom_on ? 0x80000000u : 0; return 0;
    case A_CLKA: *out = (D.clka & 1) | (clk_running(D.clka, D.clka_t) ? 0 : 0x80000000u); return 0;
    case A_CLKB: *out = (D.clkb & 1) | (clk_running(D.clkb, D.clkb_t) ? 0 : 0x80000000u); return 0;
    default:
        if (addr >= A_BLK && addr < A_BLK + 0x100) {
            if (!block_open()) {
                D.closed_block_reads++;
                if (!D.block_serror) hang();
                D.serror_pending = 1;
                *out = 0xffffffffu;
                return 0;
            }
            *out = 0xb10c0000u | (addr - A_BLK);
            return 0;
        }
        return 1;
    }
}

static int dev_store(uint32_t addr, uint32_t value)
{
    D.nstores++;
    D.last_store_addr = addr;
    int is_row = addr == A_DCTL || addr == A_CLKA || addr == A_CLKB || (addr >= A_PLAIN && addr < A_PLAIN + 16);
    if (!is_row) D.stray_stores++;
    emit_event(EV_STORE, addr, value, "");
    int fault = addr == D.fault_store;
    if (fault && !D.fault_applies) return 1;
    if (addr == D.hang_store) hang();
    if (addr == D.serror_store) { D.serror_pending = 1; D.serror_store = 0; }     /* one error response: the undo's own store is not its victim */
    if (D.ignore_all || addr == D.ignore_store) return fault;
    dom_update();
    if (addr >= A_PLAIN && addr < A_PLAIN + 16) {
        D.plain[(addr - A_PLAIN) / 4] = value;
    } else {
        switch (addr) {
        case A_DCTL: D.dctl = value; D.dctl_t = now_ticks; break;
        case A_CLKA: D.clka = value & 1; D.clka_t = now_ticks; break;
        case A_CLKB: D.clkb = value & 1; D.clkb_t = now_ticks; break;
        default: return 1;
        }
    }
    if (fault) D.fault_store = 0;
    return fault;
}

static void fake_emit(const char *line)
{
    if (!strncmp(line, "WTAB STOP", 9)) D.dsts_at_stop = D.dsts_reads;
    emit_event(EV_LINE, 0, 0, line);
    if (D.emit_off_after && !strncmp(line, D.emit_off_after, strlen(D.emit_off_after))) wenv.emit = 0;     /* the page goes away after this line: nothing more can be printed */
}
/* What the last scenario did, for a failed suite: lines and stores in order. */
void dump_events(void)
{
    for (unsigned i = 0; i < nev; i++) {
        if (ev[i].kind == EV_LINE) fprintf(stderr, "    | %s\n", ev[i].text);
        else fprintf(stderr, "    | STORE %#" PRIx32 " <- %#" PRIx32 "\n", ev[i].addr, ev[i].value);
    }
}
static int env_read32(uint32_t pa, uint32_t *out) { return dev_read(pa, out); }
static int env_store32(uint32_t pa, uint32_t value) { return dev_store(pa, value); }
static int env_serror(void)
{
    if (D.serror_on_poll && --D.serror_on_poll == 0) return 1;      /* the n-th poll from now on finds an error response, whatever the device did */
    if (D.blind) return 0;
    int pending = D.serror_pending;
    D.serror_pending = 0;
    return pending;
}
static uint64_t env_counter(void)
{
    counter_calls++;
    if (counter_mode == 1) return now_ticks;
    if (counter_mode == 2 && counter_calls > 50) return now_ticks - (counter_calls - 50);
    now_ticks += tick_step;
    return now_ticks;
}
struct q1n1_wtab_env wenv = {fake_emit, env_read32, env_store32, env_serror, env_counter, HZ, env_attr};

/* ---- The table and the machine ----------------------------------------------------------------------------------------------- */

static uint64_t image64[IMAGE_BYTES / 8];
uint8_t *image = (uint8_t *)image64;
uint8_t mapbuf[48 * 4];
struct q1n1_wtab_machine machine;
const struct q1n1_wtab_header *good = (const struct q1n1_wtab_header *)&wtab_wtabref;
const uint32_t good_bytes = sizeof wtab_wtabref;

void put_desc(unsigned i, uint32_t type, uint64_t start, uint64_t pages)
{
    uint8_t *d = mapbuf + 48 * i;
    memset(d, 0, 48);
    memcpy(d, &type, 4); memcpy(d + 8, &start, 8); memcpy(d + 24, &pages, 8);
}
void machine_default(void)
{
    memset(mapbuf, 0, sizeof mapbuf);
    put_desc(0, 7, 0x80000000u, 0x40000);          /* conventional RAM at 2 GiB */
    put_desc(1, 11, 0x01000000u, 0x10);            /* memory-mapped I/O around the fake device */
    put_desc(2, 0, 0x90000000u, 0x100);            /* reserved */
    machine.image_base = (uint64_t)(uintptr_t)image;
    machine.image_bytes = IMAGE_BYTES;
    machine.map_base = (uint64_t)(uintptr_t)mapbuf;
    machine.map_size = 48 * 3;
    machine.map_stride = 48;
}
void table_from(const void *bytes, uint32_t n)
{
    memset(image, 0, IMAGE_BYTES);
    memcpy(image + TABLE_AT, bytes, n);
}
struct q1n1_wtab_header *tab(void) { return (struct q1n1_wtab_header *)(image + TABLE_AT); }
struct q1n1_wtab_row *tab_row(unsigned i) { return (struct q1n1_wtab_row *)(tab() + 1) + i; }
struct q1n1_wtab_window *tab_win(unsigned j) { return (struct q1n1_wtab_window *)((struct q1n1_wtab_row *)(tab() + 1) + tab()->rows) + j; }

const struct q1n1_payload_wtab_ops *begin_run(void)
{
    dev_found();
    machine_default();
    table_from(good, good_bytes);
    q1n1_wtab_begin(&wenv, &machine);
    return q1n1_wtab_ops();
}
int do_open(const struct q1n1_payload_wtab_ops *o) { return o->open(tab()); }

/* ---- Looking at what happened -------------------------------------------------------------------------------------------------- */

unsigned stores_of(uint32_t addr)
{
    unsigned n = 0;
    for (unsigned i = 0; i < nev; i++) n += ev[i].kind == EV_STORE && ev[i].addr == addr;
    return n;
}
int line_index(const char *prefix)
{
    for (unsigned i = 0; i < nev; i++)
        if (ev[i].kind == EV_LINE && !strncmp(ev[i].text, prefix, strlen(prefix))) return (int)i;
    return -1;
}
unsigned lines_with(const char *prefix)
{
    unsigned n = 0;
    for (unsigned i = 0; i < nev; i++) n += ev[i].kind == EV_LINE && !strncmp(ev[i].text, prefix, strlen(prefix));
    return n;
}
unsigned all_lines(void)
{
    unsigned n = 0;
    for (unsigned i = 0; i < nev; i++) n += ev[i].kind == EV_LINE;
    return n;
}
const char *end_line(void)
{
    for (unsigned i = nev; i-- > 0;)
        if (ev[i].kind == EV_LINE && !strncmp(ev[i].text, "WTAB END", 8)) return ev[i].text;
    return "";
}
/* The n-th store, in order: its address and value. */
int nth_store(unsigned n, uint32_t *addr, uint32_t *value)
{
    for (unsigned i = 0; i < nev; i++) {
        if (ev[i].kind == EV_STORE && n-- == 0) { *addr = ev[i].addr; *value = ev[i].value; return 1; }
    }
    return 0;
}
/* Every store is preceded by a line that names its address, with no other store between them: the page names the word before it is written. */
int stores_are_announced(void)
{
    for (unsigned i = 0; i < nev; i++) {
        if (ev[i].kind != EV_STORE) continue;
        char want[24];
        snprintf(want, sizeof want, "A=0X%" PRIX32, ev[i].addr);
        int found = 0;
        for (unsigned k = i; k-- > 0;) {
            if (ev[k].kind == EV_STORE) break;
            if (ev[k].kind == EV_LINE && strstr(ev[k].text, want) && (ev[k].text[0] == 'W' || ev[k].text[0] == 'U')) { found = 1; break; }
        }
        if (!found) return 0;
    }
    return 1;
}
void expect_found_state(const char *tag)
{
    char name[64];
    snprintf(name, sizeof name, "%s.device_back_to_found", tag);
    CHECK(name, D.dctl == 0x0022f801 && D.clka == 0 && D.clkb == 0);
}

int rows_ok(const struct q1n1_payload_wtab_ops *o, unsigned count)
{
    for (unsigned i = 0; i < count; i++) {
        if (o->row(i)) return 0;
    }
    return 1;
}

uint32_t budget_bytes(const struct budget_table *t) { return Q1N1_WTAB_TABLE_BYTES(t->h.rows, 0); }
void budget_build(struct budget_table *t, unsigned writes, unsigned checks)
{
    const struct q1n1_wtab_row *src = (const struct q1n1_wtab_row *)(good + 1);
    memset(t, 0, sizeof *t);
    t->h = *good;
    t->h.rows = writes + checks; t->h.windows = 0; t->h.steps = 1;
    t->h.bytes = Q1N1_WTAB_TABLE_BYTES(t->h.rows, 0);
    for (unsigned i = 0; i < writes + checks; i++) {
        t->r[i] = i < writes ? src[2] : src[0];
        t->r[i].step = 0;
        if (i < writes) {
            t->r[i].addr = A_PLAIN + 4 * (i % 4);
            t->r[i].rb_addr = t->r[i].addr; t->r[i].rb_mask = 1; t->r[i].rb_value = 1; t->r[i].rb_timeout_us = 0;
            memset(t->r[i].tag, 0, sizeof t->r[i].tag);
            t->r[i].tag[0] = 'P'; t->r[i].tag[1] = (char)('0' + i);
        }
    }
}
const struct q1n1_payload_wtab_ops *begin_budget_run(const struct budget_table *t)
{
    dev_found();
    machine_default();
    table_from(t, budget_bytes(t));
    q1n1_wtab_begin(&wenv, &machine);
    return q1n1_wtab_ops();
}

/* ---- run ----------------------------------------------------------------------------------------------------------------------- */

static void suite_run(void)
{
    const struct q1n1_payload_wtab_ops *o = begin_run();
    CHECK("open.ok", do_open(o) == 0);
    int open_line = line_index("WTAB OPEN WTABREF ROWS=4 STEPS=3 SHA=");
    CHECK("open.line_names_table", open_line == 4);
    CHECK("attr.one_line_for_every_row_before_open", lines_with("WTAB ATTR ") == 4 && lines_with("WTAB ATTR GATE DEVICE") == 1 && lines_with("WTAB ATTR DOMAIN DEVICE") == 1 &&
          lines_with("WTAB ATTR CLKA DEVICE") == 1 && lines_with("WTAB ATTR CLKB DEVICE") == 1 && line_index("WTAB ATTR ") == 0);
    uint8_t digest[32];
    q1n1_sha256(good, good_bytes, digest);
    char sha[24];
    snprintf(sha, sizeof sha, "SHA=%02X%02X%02X%02X%02X%02X%02X%02X", digest[0], digest[1], digest[2], digest[3], digest[4], digest[5], digest[6], digest[7]);
    CHECK("open.line_has_the_table_digest", strstr(ev[open_line].text, sha) != 0);
    CHECK("rows.all_done", rows_ok(o, 4));
    uint32_t a, v;
    CHECK("stores.three_before_undo", D.nstores == 3 && nth_store(0, &a, &v) && a == A_DCTL && v == 0x0022f800 && nth_store(1, &a, &v) && a == A_CLKA && v == 0x80000001u &&
          nth_store(2, &a, &v) && a == A_CLKB && v == 0x80000001u);     /* the whole word as read, with the bit: read-modify-write like Linux's regmap_update_bits */
    CHECK("stores.every_write_row_has_its_line_and_its_result", lines_with("W 1 DOMAIN") == 1 && lines_with("W 2 CLKA") == 1 && lines_with("W 3 CLKB") == 1 &&
          lines_with("R 1 OK") == 1 && lines_with("R 2 OK") == 1 && lines_with("R 3 OK") == 1);
    CHECK("stores.check_row_has_none", stores_of(A_GATE) == 0 && lines_with("C 0 GATE") == 1);
    CHECK("stores.stray_none", D.stray_stores == 0);
    CHECK("lines.next_step_before_first_store", line_index("WTAB NEXT STEP=1 AFTER 1 S") >= 0 && line_index("WTAB NEXT STEP=1") < line_index("W 1 DOMAIN"));
    CHECK("lines.next_step_two_once", lines_with("WTAB NEXT STEP=2") == 1 && lines_with("WTAB NEXT STEP=0") == 0);
    CHECK("device.domain_on", D.dom_on == 1 && (D.dctl & 1) == 0 && D.clka == 1 && D.clkb == 1);
    CHECK("window.reads_after_gate", q1n1_wtab_load_check(A_BLK) == 0);
    CHECK("unwind.ok", o->unwind() == 0);
    CHECK("unwind.is_idempotent", o->unwind() == 0 && lines_with("WTAB END") == 1);
    uint32_t addr_a, addr_b, addr_c;
    CHECK("unwind.reverse_order", nth_store(3, &addr_a, &v) && nth_store(4, &addr_b, &v) && nth_store(5, &addr_c, &v) && addr_a == A_CLKB && addr_b == A_CLKA && addr_c == A_DCTL);
    expect_found_state("unwind");
    CHECK("unwind.domain_off_again", D.dom_on == 0 || (now_ticks < D.dctl_t + US(5)));
    CHECK("lines.every_store_announced", stores_are_announced());
    CHECK("end.line", !strcmp(end_line(), "WTAB END RESULT=RESTORED WHY=OK ROWS=4 STORES=3 UNDOS=3 RESTORED=3 OF=3"));
    CHECK("rows.after_unwind_refused", o->row(0) == Q1N1_WTAB_STOPPED);

    /* a write row that finds its word already as it wants it: the table said what the word holds, so the run stops before the row writes (no row is skipped) */
    o = begin_run();
    D.clka = 1;
    CHECK("already_on.open", do_open(o) == 0 && o->row(0) == 0 && o->row(1) == 0 && o->row(2) == Q1N1_WTAB_FOUND);
    CHECK("already_on.nothing_written_over_it", stores_of(A_CLKA) == 0 && lines_with("W 2 CLKA") == 0 && D.clka == 1);
    CHECK("already_on.the_domain_is_undone", stores_of(A_DCTL) == 2 && D.dctl == 0x0022f801);
    CHECK("already_on.end", !strcmp(end_line(), "WTAB END RESULT=RESTORED WHY=FOUND ROWS=2 STORES=1 UNDOS=1 RESTORED=1 OF=1"));
}

/* ---- stops --------------------------------------------------------------------------------------------------------------------- */

static void check_stopped(const char *tag, const struct q1n1_payload_wtab_ops *o, int reason, unsigned stores_before_undo, const char *why)
{
    char name[80];
    const struct q1n1_wtab_result *r = q1n1_wtab_last();
    snprintf(name, sizeof name, "%s.reason", tag);
    CHECK(name, r->stopped && r->reason == reason);
    snprintf(name, sizeof name, "%s.stop_line", tag);
    char want[40];
    snprintf(want, sizeof want, "WTAB STOP WHY=%s", why);
    CHECK(name, lines_with(want) == 1);
    snprintf(name, sizeof name, "%s.stores_made", tag);
    CHECK(name, r->stores == stores_before_undo);
    snprintf(name, sizeof name, "%s.one_end", tag);
    CHECK(name, lines_with("WTAB END") == 1 && line_index("WTAB END") > line_index("WTAB STOP"));
    snprintf(name, sizeof name, "%s.nothing_after", tag);
    unsigned reads = D.nreads, stores = D.nstores;
    CHECK(name, o->row(r->stop_row) == Q1N1_WTAB_STOPPED && o->row(0) == Q1N1_WTAB_STOPPED && D.nreads == reads && D.nstores == stores);
    snprintf(name, sizeof name, "%s.announced", tag);
    CHECK(name, stores_are_announced());
    snprintf(name, sizeof name, "%s.no_stray", tag);
    CHECK(name, D.stray_stores == 0);
}

static void suite_stops(void)
{
    const struct q1n1_payload_wtab_ops *o;

    o = begin_run(); D.dctl = 0x0022f800;
    CHECK("found.open", do_open(o) == 0);
    CHECK("found.row0_ok_row1_refused", o->row(0) == 0 && o->row(1) == Q1N1_WTAB_FOUND);
    check_stopped("found", o, Q1N1_WTAB_FOUND, 0, "FOUND");
    CHECK("found.nothing_written", D.nstores == 0 && D.dctl == 0x0022f800);

    o = begin_run(); D.gate = 0;
    CHECK("gate_check.open", do_open(o) == 0 && o->row(0) == Q1N1_WTAB_FOUND);
    check_stopped("gate_check", o, Q1N1_WTAB_FOUND, 0, "FOUND");

    o = begin_run(); D.fault_read = A_DCTL;
    CHECK("pre_read_fault.open", do_open(o) == 0 && o->row(0) == 0 && o->row(1) == Q1N1_WTAB_FAULT);
    check_stopped("pre_read_fault", o, Q1N1_WTAB_FAULT, 0, "FAULT");

    o = begin_run(); D.fault_store = A_CLKA;
    CHECK("store_fault.open", do_open(o) == 0 && o->row(0) == 0 && o->row(1) == 0 && o->row(2) == Q1N1_WTAB_FAULT);
    check_stopped("store_fault", o, Q1N1_WTAB_FAULT, 2, "FAULT");
    expect_found_state("store_fault");
    CHECK("store_fault.end", !strcmp(end_line(), "WTAB END RESULT=RESTORED WHY=FAULT ROWS=2 STORES=2 UNDOS=2 RESTORED=2 OF=2"));
    CHECK("store_fault.the_faulted_row_was_proven_back", lines_with("U 2 CLKA") == 1 && lines_with("U 2 FAIL") == 0);

    /* a store that reached the word and then reported a fault: the row is in force from before the store, so the word goes back (journal after the store would leave it changed) */
    o = begin_run(); D.fault_store = A_DCTL; D.fault_applies = 1;
    CHECK("store_fault_applied.open", do_open(o) == 0 && o->row(0) == 0 && o->row(1) == Q1N1_WTAB_FAULT);
    check_stopped("store_fault_applied", o, Q1N1_WTAB_FAULT, 1, "FAULT");
    CHECK("store_fault_applied.word_back_to_found", D.dctl == 0x0022f801 && stores_of(A_DCTL) == 2);
    CHECK("store_fault_applied.undone", lines_with("U 1 DOMAIN") == 1 && lines_with("U 1 FAIL") == 0);
    CHECK("store_fault_applied.end", !strcmp(end_line(), "WTAB END RESULT=RESTORED WHY=FAULT ROWS=1 STORES=1 UNDOS=1 RESTORED=1 OF=1"));

    /* an error response that an earlier access left: nothing is stored over it */
    o = begin_run();
    CHECK("serror_before_store.open", do_open(o) == 0 && o->row(0) == 0);
    D.serror_pending = 1;
    CHECK("serror_before_store.stops", o->row(1) == Q1N1_WTAB_SERROR);
    CHECK("serror_before_store.nothing_stored", D.nstores == 0 && D.dctl == 0x0022f801 && lines_with("W 1 DOMAIN") == 0);
    CHECK("serror_before_store.names_the_row", lines_with("WTAB STOP WHY=SERROR ROW=1 A=0X1001000") == 1);
    CHECK("serror_before_store.end", !strcmp(end_line(), "WTAB END RESULT=RESTORED WHY=SERROR ROWS=1 STORES=0 UNDOS=0 RESTORED=0 OF=0"));

    o = begin_run(); D.serror_store = A_DCTL;
    CHECK("serror.open", do_open(o) == 0 && o->row(0) == 0 && o->row(1) == Q1N1_WTAB_SERROR);
    check_stopped("serror", o, Q1N1_WTAB_SERROR, 1, "SERROR");
    expect_found_state("serror");
    CHECK("serror.the_store_that_raised_it_is_undone", stores_of(A_DCTL) == 2);
    CHECK("serror.names_the_store", lines_with("WTAB STOP WHY=SERROR ROW=1 A=0X1001000") == 1 && D.dsts_at_stop == 0);

    o = begin_run(); D.blind = 1; D.serror_store = A_DCTL;
    CHECK("blind.open", do_open(o) == 0 && rows_ok(o, 4));
    CHECK("blind.not_seen", D.serror_pending == 1 && q1n1_wtab_last()->stopped == 0);   /* the limit, on purpose: EL3 may route SErrors away */

    o = begin_run(); D.dom_stuck = 1;
    CHECK("readback.open", do_open(o) == 0 && o->row(0) == 0 && o->row(1) == Q1N1_WTAB_READBACK);
    check_stopped("readback", o, Q1N1_WTAB_READBACK, 1, "READBACK");
    CHECK("readback.waited_its_time", lines_with("WTAB STOP WHY=READBACK ROW=1 A=0X1001004 GOT=0X0 WANT=0X80000000 MASK=0X80000000") == 1);
    CHECK("readback.undo_ran", stores_of(A_DCTL) == 2 && D.dctl == 0x0022f801);

    o = begin_run(); D.fault_read = A_DSTS;
    CHECK("readback_fault.open", do_open(o) == 0 && o->row(0) == 0 && o->row(1) == Q1N1_WTAB_FAULT);
    check_stopped("readback_fault", o, Q1N1_WTAB_FAULT, 1, "FAULT");

    o = begin_run();
    CHECK("counter_stuck.open", do_open(o) == 0);
    counter_mode = 1;       /* a counter that stops after open: the first wait finds out (a counter that is stuck at open is refused as PLATFORM, below) */
    CHECK("counter_stuck.rows", o->row(0) == 0 && o->row(1) == Q1N1_WTAB_COUNTER);
    check_stopped("counter_stuck", o, Q1N1_WTAB_COUNTER, 0, "COUNTER");

    o = begin_run(); counter_mode = 2;
    CHECK("counter_back.open", do_open(o) == 0);
    int rc = 0;
    for (unsigned i = 0; i < 4 && !rc; i++) rc = o->row(i);
    CHECK("counter_back.stops_not_skips", rc == Q1N1_WTAB_COUNTER);

    o = begin_run();
    CHECK("order.open", do_open(o) == 0 && o->row(2) == Q1N1_WTAB_ORDER);
    check_stopped("order", o, Q1N1_WTAB_ORDER, 0, "ORDER");
    o = begin_run();
    CHECK("order_repeat.open", do_open(o) == 0 && o->row(0) == 0 && o->row(0) == Q1N1_WTAB_ORDER);
    o = begin_run();
    CHECK("index.open", do_open(o) == 0 && o->row(4) == Q1N1_WTAB_INDEX);
    check_stopped("index", o, Q1N1_WTAB_INDEX, 0, "INDEX");
    o = begin_run();
    CHECK("index_huge.open", do_open(o) == 0 && o->row(0xffffffffu) == Q1N1_WTAB_INDEX);
    check_stopped("index_huge", o, Q1N1_WTAB_INDEX, 0, "INDEX");
}

/* ---- undo ---------------------------------------------------------------------------------------------------------------------- */

static void suite_undo(void)
{
    const struct q1n1_payload_wtab_ops *o;

    /* the status never clears: the domain stays on, which is not "returned to how it was found" */
    o = begin_run(); D.dom_noclear = 1; D.fault_store = A_CLKB;
    CHECK("noclear.open", do_open(o) == 0);
    CHECK("noclear.stop", rows_ok(o, 3) && o->row(3) == Q1N1_WTAB_FAULT);
    CHECK("noclear.end", !strncmp(end_line(), "WTAB END RESULT=UNDO_FAILED WHY=FAULT", 37));
    CHECK("noclear.fail_line", lines_with("U 1 FAIL VERIFY") == 1);
    CHECK("noclear.unwind_reports", o->unwind() == Q1N1_WTAB_UNDO_FAILED);

    /* an error response in the undo: the bus is not trusted with more, the rows that are left are said not to have been tried */
    o = begin_run();
    CHECK("undo_serror.open", do_open(o) == 0 && rows_ok(o, 4));
    D.serror_store = A_CLKA;
    unsigned reads_before_unwind = D.nreads;
    CHECK("undo_serror.unwind", o->unwind() == Q1N1_WTAB_UNDO_FAILED);
    CHECK("undo_serror.rest_not_tried", lines_with("U 2 FAIL SERROR") == 1 && lines_with("U 1 FAIL NOT_TRIED") == 1 && lines_with("U 3 FAIL") == 0);
    CHECK("undo_serror.no_readback_after_the_error_response", D.nreads - reads_before_unwind == 3);       /* row 3: its word and its read-back; row 2: its word only */
    CHECK("undo_serror.domain_row_never_written", stores_of(A_DCTL) == 1);
    CHECK("undo_serror.end", !strncmp(end_line(), "WTAB END RESULT=UNDO_FAILED", 27));

    /* a store the device ignores: the undo's own verification says so */
    o = begin_run();
    CHECK("ignored.open", do_open(o) == 0 && rows_ok(o, 4));
    D.ignore_store = A_CLKA;
    CHECK("ignored.unwind", o->unwind() == Q1N1_WTAB_UNDO_FAILED && lines_with("U 2 FAIL VERIFY") == 1);

    /* an error response raised by the read-back of the undo itself: the undo is not reported as proven */
    o = begin_run();
    CHECK("undo_serror_readback.open", do_open(o) == 0 && rows_ok(o, 4));
    D.serror_read = A_DSTS;
    CHECK("undo_serror_readback.unwind", o->unwind() == Q1N1_WTAB_UNDO_FAILED);
    CHECK("undo_serror_readback.fail_line", lines_with("U 1 FAIL SERROR") == 1 && lines_with("U 1 FAIL VERIFY") == 0);
    CHECK("undo_serror_readback.end", !strncmp(end_line(), "WTAB END RESULT=UNDO_FAILED", 27));

    /* an irreversible row stays: it is counted and the result says PARTIAL, never RESTORED */
    o = begin_run();
    struct q1n1_wtab_header *h = tab();
    h->flags |= Q1N1_WTAB_F_ALLOW_IRREVERSIBLE;
    struct q1n1_wtab_row *r = tab_row(2);
    r->undo_kind = 0; r->undo_value = 0; r->undo_rb_addr = r->undo_rb_mask = r->undo_rb_value = 0; r->undo_timeout_us = r->undo_after_us = 0;
    CHECK("irreversible.open", do_open(o) == 0 && rows_ok(o, 4));
    CHECK("irreversible.unwind", o->unwind() == 0 && D.clka == 1 && stores_of(A_CLKA) == 1);
    CHECK("irreversible.end", !strcmp(end_line(), "WTAB END RESULT=PARTIAL WHY=OK ROWS=4 STORES=3 UNDOS=2 RESTORED=2 OF=2"));

    /* RESTORE puts back what was found, whatever it was: a multi-bit mask on the domain word */
    o = begin_run();
    r = tab_row(1);
    r->mask = 0x00ff0001; r->value = 0x00000000; r->found_mask = 0x00fff807; r->found_value = 0x00abf801;
    r->rb_addr = A_DCTL; r->rb_mask = 0x00ff0001; r->rb_value = 0; r->rb_timeout_us = 50;
    D.dctl = 0x00ab5801 | 0xa000;
    uint32_t before = D.dctl;
    CHECK("restore_bits.open", do_open(o) == 0 && o->row(0) == 0 && o->row(1) == 0 && (D.dctl & 0x00ff0001) == 0);
    CHECK("restore_bits.unwind", o->unwind() == 0 && D.dctl == before);
}

/* ---- gate ---------------------------------------------------------------------------------------------------------------------- */

static void suite_gate(void)
{
    const struct q1n1_payload_wtab_ops *o;
    o = begin_run();
    CHECK("before_open.not_gated", q1n1_wtab_load_check(A_BLK) == 0);
    CHECK("open", do_open(o) == 0);
    CHECK("closed.refused", q1n1_wtab_load_check(A_BLK) == Q1N1_WTAB_LOAD_E_GATED && q1n1_wtab_load_check(A_BLK + 0xfc) == Q1N1_WTAB_LOAD_E_GATED);
    CHECK("closed.line_once_or_twice", lines_with("WTAB READ REFUSED") >= 1 && lines_with("WTAB READ REFUSED") <= 2);
    CHECK("outside_windows.not_gated", q1n1_wtab_load_check(A_DSTS) == 0 && q1n1_wtab_load_check(A_BLK + 0x100) == 0 && q1n1_wtab_load_check(A_BLK - 4) == 0);
    CHECK("rows", o->row(0) == 0 && o->row(1) == 0 && o->row(2) == 0);
    CHECK("still_closed_before_the_named_row", q1n1_wtab_load_check(A_BLK) == Q1N1_WTAB_LOAD_E_GATED);
    CHECK("row3", o->row(3) == 0);
    CHECK("open.allowed", q1n1_wtab_load_check(A_BLK) == 0 && q1n1_wtab_load_done(A_BLK) == 0 && q1n1_wtab_load_done(A_DSTS) == 0);
    CHECK("device_would_hang_while_closed_but_never_does", D.closed_block_reads == 0);
    CHECK("window_reads_counted", q1n1_wtab_last()->window_reads == 1);
    CHECK("unwind", o->unwind() == 0);
    CHECK("closed_again_after_the_undo", q1n1_wtab_load_check(A_BLK) == Q1N1_WTAB_LOAD_E_GATED && q1n1_wtab_load_check(A_DSTS) == 0);

    /* an error response on a read of the block: the run stops and what it switched on goes back */
    o = begin_run(); D.block_serror = 1;
    CHECK("serror.rows", do_open(o) == 0 && rows_ok(o, 4));
    D.serror_pending = 1;
    CHECK("serror.stops", q1n1_wtab_load_done(A_BLK) == Q1N1_WTAB_LOAD_E_GATED && q1n1_wtab_last()->stopped && q1n1_wtab_last()->reason == Q1N1_WTAB_WINDOW_READ);
    expect_found_state("serror");
    CHECK("serror.refuses_more", q1n1_wtab_load_check(A_BLK) == Q1N1_WTAB_LOAD_E_GATED && o->row(0) == Q1N1_WTAB_STOPPED);
    CHECK("serror.end", lines_with("WTAB END RESULT=RESTORED WHY=WINDOW_READ") == 1);

    /* the number of windowed reads is bounded */
    o = begin_run();
    CHECK("budget.rows", do_open(o) == 0 && rows_ok(o, 4));
    unsigned allowed = 0;
    for (unsigned i = 0; i < Q1N1_WTAB_WINDOW_READS_MAX + 10; i++) {
        if (q1n1_wtab_load_check(A_BLK) == 0) { allowed++; q1n1_wtab_load_done(A_BLK); }
    }
    CHECK("budget.cap", allowed == Q1N1_WTAB_WINDOW_READS_MAX);
}

/* ---- hang ---------------------------------------------------------------------------------------------------------------------- */

static void suite_hang(void)
{
    const struct q1n1_payload_wtab_ops *o = begin_run();
    CHECK("open", do_open(o) == 0 && o->row(0) == 0);
    D.hang_store = A_DCTL;
    if (setjmp(hang_jump) == 0) {
        o->row(1);
        CHECK("store_hang.did_not_return", 0);
    }
    CHECK("store_hang.hung", D.hung == 1);
    unsigned last = 0;
    for (unsigned i = 0; i < nev; i++) if (ev[i].kind == EV_LINE) last = i;
    CHECK("store_hang.last_line_names_the_row", !strcmp(ev[last].text, "W 1 DOMAIN A=0X1001000 OLD=0X22F801 NEW=0X22F800"));
    CHECK("store_hang.nothing_after_the_line_but_the_store", nev == last + 1 + 1 && ev[nev - 1].kind == EV_STORE);
    CHECK("store_hang.no_end_line_yet", lines_with("WTAB END") == 0);

    /* a hang on the read-back: the W line is still the last line, the store before it was made */
    o = begin_run(); D.hang_read = A_DSTS;
    CHECK("readback_hang.open", do_open(o) == 0 && o->row(0) == 0);
    if (setjmp(hang_jump) == 0) {
        o->row(1);
        CHECK("readback_hang.did_not_return", 0);
    }
    last = 0;
    for (unsigned i = 0; i < nev; i++) if (ev[i].kind == EV_LINE) last = i;
    CHECK("readback_hang.last_line_names_the_row", !strncmp(ev[last].text, "W 1 DOMAIN A=0X1001000", 22) && stores_of(A_DCTL) == 1);
}

/* ---- finish -------------------------------------------------------------------------------------------------------------------- */

static void suite_finish(void)
{
    const struct q1n1_payload_wtab_ops *o;
    struct q1n1_wtab_result res;

    o = begin_run();
    CHECK("auto.open", do_open(o) == 0 && rows_ok(o, 4));
    q1n1_wtab_finish(&res);
    CHECK("auto.unwinds", res.finished && res.restored && res.undo_ok == 3 && D.dctl == 0x0022f801 && lines_with("WTAB AUTO_UNWIND IN_FORCE=3") == 1);
    CHECK("auto.end_once", lines_with("WTAB END") == 1);
    q1n1_wtab_finish(&res);
    CHECK("auto.finish_twice_prints_nothing_more", lines_with("WTAB END") == 1);

    o = begin_run(); D.dctl = 0x0022f800;
    CHECK("after_stop.open", do_open(o) == 0 && o->row(0) == 0 && o->row(1) != 0);
    q1n1_wtab_finish(&res);
    CHECK("after_stop.no_second_end", lines_with("WTAB END") == 1 && lines_with("WTAB AUTO_UNWIND") == 0 && res.stopped);

    o = begin_run();
    tab()->flags = 0;
    CHECK("left.open", do_open(o) == 0 && rows_ok(o, 4));
    q1n1_wtab_finish(&res);
    CHECK("left.not_undone", !res.restored && D.dom_on && D.clka == 1 && stores_of(A_DCTL) == 1);
    CHECK("left.end", !strcmp(end_line(), "WTAB END RESULT=LEFT WHY=OK ROWS=4 STORES=3 UNDOS=0 RESTORED=0 OF=3"));

    o = begin_run();
    q1n1_wtab_finish(&res);
    CHECK("never_opened.silent", nev == 0 && !res.opened);
}

/* ---- chain: the real runner loop with the reference payload ------------------------------------------------------------------------ */

struct q1n1_payload_loaded loaded;
static struct q1n1_preload_cache *cache;

static void chain_emit(const char *line) { fake_emit(line); }
static void chain_sync(uint64_t base, uint64_t bytes) { (void)base; (void)bytes; }
/* The suite of the ops (below) calls its own code with the ops the runner gave, instead of the reference payload. */
uint64_t (*chain_probe)(const struct q1n1_payload_args *);
static uint64_t chain_call(uint64_t entry, const struct q1n1_payload_args *args, uint64_t top)
{
    (void)entry; (void)top;
    if (chain_probe) return chain_probe(args);
    return ref_payload_entry(args);
}
static int chain_guarded(int kind, uint64_t dst, uint64_t src, uint64_t size)
{
    if (kind != Q1N1_PAYLOAD_G_COPY32 || size != 4) { fprintf(stderr, "FAIL tripwire: the runner asked for guarded kind %d\n", kind); exit(3); }
    uint32_t v = 0;
    int rc = dev_read((uint32_t)src, &v);
    if (!rc) *(uint32_t *)(uintptr_t)dst = v;
    return rc;
}
static uint64_t chain_counter(void) { return env_counter(); }
struct q1n1_payload_env chain_env = {.emit = chain_emit, .sync_code = chain_sync, .call = chain_call, .guarded = chain_guarded, .counter = chain_counter};

/* Bytes of the payload's own image after the table (the strings ops.puts may read from it): `chain_extra_len` of them at CHAIN_EXTRA_AT, and the image is that much longer. */
const char *chain_extra;
size_t chain_extra_len;

void build_chain(unsigned files)
{
    free(cache);
    cache = aligned_alloc(4096, 8192);
    memset(cache, 0, 8192);
    memset(&loaded, 0, sizeof loaded);
    loaded.count = files;
    cache->magic = Q1N1_CACHE_MAGIC; cache->version = 1; cache->count = files; cache->entry_size = sizeof cache->files[0];
    for (unsigned i = 0; i < files; i++) {
        struct q1n1_payload_file *f = &loaded.file[i];
        /* The "file" is the page holding the reference table: the payload's table pointer must lie inside the image it was loaded as. */
        memcpy(table_page, &wtab_wtabref, sizeof wtab_wtabref);
        if (chain_extra_len) memcpy(table_page + CHAIN_EXTRA_AT, chain_extra, chain_extra_len);
        f->base = (uint64_t)(uintptr_t)table_page;
        f->bytes = chain_extra_len ? CHAIN_EXTRA_AT + chain_extra_len : sizeof wtab_wtabref;
        f->alloc = 4096;
        f->memory_type = Q1N1_PAYLOAD_TYPE_CODE;
        q1n1_sha256((const void *)(uintptr_t)f->base, (size_t)f->bytes, f->sha256);
        loaded.code_count++;
        cache->files[i].base = f->base;
        cache->files[i].allocation = f->alloc;
        cache->files[i].file.size = f->bytes;
        memcpy(cache->files[i].file.sha256, f->sha256, 32);
        snprintf(cache->files[i].file.path, sizeof cache->files[i].file.path, "\\SP11\\R%u.BIN", i);
    }
    loaded.table_base = (uint64_t)(uintptr_t)cache;
    /* The runner lets a payload's load32 write only inside the stack it was given (q1n1_payload_load32_check). The host payload runs on the host's own stack,
     * so that is the range the "payload stack" names here: 64 KiB around the frame of the test, whose lowest 16 KiB are unused (the guard words go there). */
    uintptr_t frame = (uintptr_t)__builtin_frame_address(0);
    loaded.stack_base = (frame - 48 * 1024) & ~(uintptr_t)15;
    loaded.stack_alloc = Q1N1_PAYLOAD_STACK_BYTES;
}

/* The platform of every chain run: the memory map the reference table's rows need (one memory-mapped I/O descriptor around the fake device, RAM at 2 GiB). */
static uint8_t chain_map[48 * 2];
void chain_platform(struct q1n1_payload_platform *plat)
{
    uint32_t type = 11;
    uint64_t start = 0x01000000u, pages = 0x10;
    memset(chain_map, 0, sizeof chain_map);
    memcpy(chain_map, &type, 4); memcpy(chain_map + 8, &start, 8); memcpy(chain_map + 24, &pages, 8);
    type = 7; start = 0x80000000u; pages = 0x1000;
    memcpy(chain_map + 48, &type, 4); memcpy(chain_map + 56, &start, 8); memcpy(chain_map + 72, &pages, 8);
    *plat = (struct q1n1_payload_platform){.fb_base = 0xe4800000, .fb_bytes = 0x1000, .map_base = (uint64_t)(uintptr_t)chain_map, .map_size = sizeof chain_map,
                                           .map_stride = 48, .fb_width = 100, .fb_height = 100, .fb_stride = 100, .fb_format = 1};
}

static void suite_chain(void)
{
    struct q1n1_payload_result result;
    struct q1n1_payload_platform plat;
    chain_platform(&plat);

    /* without the write table in the environment the payload is given none and says so: nothing is written, nothing is gated */
    dev_found(); build_chain(1);
    q1n1_wtab_attach(0);
    q1n1_payload_run(&chain_env, &loaded, &plat, &result);
    CHECK("no_env.payload_says_so", lines_with("REF REFUSED=NO_WTAB_RUNNER") == 1 && D.nstores == 0 && lines_with("WTAB") == 0);
    CHECK("no_env.ran", result.status == Q1N1_PAYLOAD_RUN_OK && result.called == 1 && result.call[0].retval == 2);

    /* with it: the whole flow */
    dev_found(); build_chain(1);
    q1n1_wtab_attach(&wenv);
    q1n1_payload_run(&chain_env, &loaded, &plat, &result);
    CHECK("flow.status", result.status == Q1N1_PAYLOAD_RUN_OK && result.called == 1 && result.call[0].retval == 0);
    CHECK("flow.lines_in_order", line_index("PAYLOAD CALL") < line_index("WTAB OPEN") && line_index("WTAB OPEN") < line_index("REF BLOCK=") &&
          line_index("REF BLOCK=") < line_index("WTAB END") && line_index("REF END") > line_index("WTAB END") && line_index("WTAB END") < line_index("PAYLOAD DONE"));
    CHECK("flow.window_read_returned_the_word", lines_with("REF BLOCK=0XB10C0000") == 1);
    CHECK("flow.restored", D.dctl == 0x0022f801 && D.clka == 0 && D.clkb == 0 && D.stray_stores == 0);
    CHECK("flow.end", !strcmp(end_line(), "WTAB END RESULT=RESTORED WHY=OK ROWS=4 STORES=3 UNDOS=3 RESTORED=3 OF=3"));
    CHECK("flow.stores_announced", stores_are_announced());
    CHECK("flow.window_read_counted_as_a_load", result.call[0].loads == 1 && result.call[0].refused == 0);

    /* a stop in the middle: the payload sees the code, nothing after it is read from the window */
    dev_found(); build_chain(1); D.dctl = 0x0022f800;
    q1n1_payload_run(&chain_env, &loaded, &plat, &result);
    CHECK("stop.payload_stopped", result.call[0].retval == 1 && lines_with("REF STOPPED") == 1 && lines_with("REF BLOCK") == 0);
    CHECK("stop.no_window_read", D.closed_block_reads == 0 && D.nstores == 0);
    CHECK("stop.end_once", lines_with("WTAB END") == 1);

    /* two payloads in one chain: the second starts from nothing */
    dev_found(); build_chain(2); D.dctl = 0x0022f800;
    q1n1_payload_run(&chain_env, &loaded, &plat, &result);
    CHECK("chain.first_stopped", result.called == 2 && result.call[0].retval == 1);
    CHECK("chain.second_is_fresh", lines_with("WTAB OPEN WTABREF") == 2 && lines_with("WTAB STOP") == 2);
    dev_found(); build_chain(2);
    q1n1_payload_run(&chain_env, &loaded, &plat, &result);
    CHECK("chain.both_run", result.called == 2 && result.call[0].retval == 0 && result.call[1].retval == 0 && lines_with("WTAB END RESULT=RESTORED") == 2);
    CHECK("chain.no_stray", D.stray_stores == 0 && D.dctl == 0x0022f801);

    /* a payload that returns in the middle of its run (here: the device faults the window read after the rows) still gets its END and its undo */
    dev_found(); build_chain(1); D.fault_read = A_BLK;
    q1n1_payload_run(&chain_env, &loaded, &plat, &result);
    CHECK("early_return.undone_by_the_runner", result.call[0].retval == 1 && D.dctl == 0x0022f801 && D.clka == 0 && lines_with("WTAB END RESULT=RESTORED") == 1);
    CHECK("early_return.auto_unwind_line", lines_with("WTAB AUTO_UNWIND") == 1);
}

/* ---- main ---------------------------------------------------------------------------------------------------------------------- */

int main(int argc, char **argv)
{
    if (argc == 3 && !strcmp(argv[1], "--validate")) return validate_file(argv[2]);
    if (argc == 3 && !strcmp(argv[1], "--validate-many")) return validate_many(argv[2]);
    if (argc == 2 && !strcmp(argv[1], "--seed-run")) return seed_run();
    static const struct { const char *name; void (*run)(void); } suites[] = {
        {"validate", suite_validate}, {"run", suite_run}, {"lines", suite_lines}, {"stops", suite_stops}, {"undo", suite_undo}, {"open", suite_open},
        {"faults", suite_faults}, {"gate", suite_gate}, {"hang", suite_hang}, {"finish", suite_finish}, {"chain", suite_chain}, {"ops", suite_ops},
    };
    for (unsigned i = 0; i < sizeof suites / sizeof suites[0]; i++) {
        unsigned before = fails;
        suite_name = suites[i].name;
        suites[i].run();
        if (fails != before && getenv("WTAB_DEBUG")) dump_events();
        printf("suite %-9s %s\n", suites[i].name, fails == before ? "ok" : "FAILED");
    }
    printf("CHECKS %u FAILS %u\n", checks, fails);
    return fails ? 1 : 0;
}
