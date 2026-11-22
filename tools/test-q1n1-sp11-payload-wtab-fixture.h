/* SPDX-License-Identifier: MIT */
/* The fixture the host tests of the runner's write table share (tools/test-q1n1-sp11-payload-wtab.c: the runs, the stops and the chain; -rules.c: the rules of the
 * table and the line budget; -open.c: the mapping attribute, the platform check and the draft that is refused; -faults.c: the faults the other suites do not reach; -ops.c: the
 * pointers a payload gives the runner's ops): the
 * fake device, the table in the payload's image, and the ways of looking at what a run did. Everything here is the harness's own statement of what a power domain and two
 * clocks do: nothing in it is the unit. Hardware: NOT RUN. */
#pragma once
#include <inttypes.h>
#include <setjmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef SNAP_PLATFORM_SP11
#define SNAP_PLATFORM_SP11 1
#endif
#define Q1N1_SP11_PAYLOAD 1
#define Q1N1_SP11_WTAB 1
#include "sp11-payload.h"
#include "sp11-payload-wtab.h"
#include "sha256.h"
#include "payload-wtab.h"

extern unsigned checks, fails;
extern const char *suite_name;
void dump_events(void);
#define CHECK(name, cond) do { \
        checks++; \
        if (!(cond)) { \
            fails++; fprintf(stderr, "FAIL %s/%s (%s:%d)\n", suite_name, name, __FILE__, __LINE__); \
            if (getenv("WTAB_DEBUG")) dump_events(); \
        } \
    } while (0)

#define A_GATE 0x01000000u
#define A_DCTL 0x01001000u
#define A_DSTS 0x01001004u
#define A_CLKA 0x01002000u
#define A_CLKB 0x01002004u
#define A_BLK 0x01008000u
#define A_PLAIN 0x01003000u     /* four plain read/write words: the tables of the line-budget tests */
#define HZ 19200000u
#define US(n) ((uint64_t)(n) * HZ / 1000000u)

enum { EV_LINE, EV_STORE, EV_READ };
struct event { int kind; uint32_t addr, value; char text[120]; };
extern struct event ev[4096];
extern unsigned nev;

struct fake_device {
    uint32_t gate, dctl, clka, clkb;
    uint64_t dctl_t, clka_t, clkb_t;
    int dom_on;
    unsigned dom_on_us, dom_off_us, clk_us;
    int dom_stuck, dom_noclear;
    uint32_t fault_read, fault_store, serror_store, serror_read, hang_store, hang_read, ignore_store;
    unsigned serror_on_poll;        /* the n-th poll of the SError state from now on answers "an error response", 0 = never */
    const char *emit_off_after;     /* a line prefix: after the line that starts with it the page is gone (the env's emit is cleared) */
    int fault_applies;              /* the faulting store reaches the word first, once: an external abort on a write leaves the word unknown */
    int ignore_all;                 /* every store is acknowledged and dropped */
    uint32_t plain[4];
    int block_serror;               /* a read of the closed block raises an SError instead of hanging the bus */
    int blind;                      /* the SError poll never sees anything (EL3 routes them away) */
    int serror_pending;
    unsigned stray_stores, closed_block_reads, nstores, nreads, dsts_reads, dsts_at_stop;
    int hung;
    uint32_t last_store_addr;
};
extern struct fake_device D;
extern uint64_t now_ticks;
extern unsigned tick_step, counter_mode, counter_calls;     /* counter_mode: 0 normal, 1 stuck, 2 runs backwards after 50 reads */
extern jmp_buf hang_jump;
/* The mapping the fake platform reports: attr_all everywhere (Device), but for the page attr_page, which a scenario sets to attr_class. */
extern uint32_t attr_page;
extern int attr_class, attr_all;
void dev_found(void);
extern struct q1n1_wtab_env wenv;

/* The table in the payload's image and the machine around it. */
#define IMAGE_BYTES 4096u
#define TABLE_AT 64u
extern uint8_t *image;
extern uint8_t mapbuf[48 * 4];
extern struct q1n1_wtab_machine machine;
extern const struct q1n1_wtab_header *good;     /* the reference table */
extern const uint32_t good_bytes;
void put_desc(unsigned i, uint32_t type, uint64_t start, uint64_t pages);
void machine_default(void);
void table_from(const void *bytes, uint32_t n);
struct q1n1_wtab_header *tab(void);
struct q1n1_wtab_row *tab_row(unsigned i);
struct q1n1_wtab_window *tab_win(unsigned j);
const struct q1n1_payload_wtab_ops *begin_run(void);
int do_open(const struct q1n1_payload_wtab_ops *o);

/* Looking at what happened. */
unsigned stores_of(uint32_t addr);
int line_index(const char *prefix);
unsigned lines_with(const char *prefix);
unsigned all_lines(void);
const char *end_line(void);
int nth_store(unsigned n, uint32_t *addr, uint32_t *value);
int stores_are_announced(void);
void expect_found_state(const char *tag);
int rows_ok(const struct q1n1_payload_wtab_ops *o, unsigned count);

/* A table of `writes` rows that each write one of the four plain words, then `checks` rows that only read the gate: the shapes the line budget is judged on. */
struct budget_table { struct q1n1_wtab_header h; struct q1n1_wtab_row r[16]; };
uint32_t budget_bytes(const struct budget_table *t);
void budget_build(struct budget_table *t, unsigned writes, unsigned checks);
const struct q1n1_payload_wtab_ops *begin_budget_run(const struct budget_table *t);

/* The suites that live in the other files. */
void suite_validate(void);
void suite_open(void);
void suite_lines(void);
void suite_faults(void);
void suite_ops(void);
int seed_run(void);

/* The chain of the main file (the real q1n1_payload_run, the reference payload) that the suite of the ops (-ops.c) drives with probes of its own. */
#define CHAIN_EXTRA_AT 2048u
extern struct q1n1_payload_loaded loaded;
extern struct q1n1_payload_env chain_env;
extern uint8_t table_page[4096];
extern uint64_t (*chain_probe)(const struct q1n1_payload_args *);
extern const char *chain_extra;
extern size_t chain_extra_len;
void build_chain(unsigned files);
void chain_platform(struct q1n1_payload_platform *plat);
int validate_file(const char *path);
int validate_many(const char *path);
