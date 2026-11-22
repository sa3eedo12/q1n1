/* SPDX-License-Identifier: MIT */
/* The runner's side of the write table (docs/SP11-PAYLOAD-WTAB.md, ABI in sp11-payload-wtab-abi.h): validates a payload's table,
 * executes it one row at a time with a read before, a guarded store, a read-back and a journal, undoes it on any failure and gates the
 * payload's reads of the blocks the table switches on. Pure policy: everything the hardware does goes through q1n1_wtab_env, so the
 * native tests run it against a fake device that can fault, raise an SError, stick, or change its mind.
 *
 * Opt-in: Q1N1_SP11_WTAB (default 0) needs Q1N1_SP11_PAYLOAD=1. With it at 0 this header declares nothing and sp11-payload-wtab.c
 * compiles to nothing, so the default runner is the pinned one byte for byte (tools/test-q1n1-sp11-payload-wtab.py).
 *
 * Evidence: EXPERIMENTAL. Built and tested on a host only; hardware NOT RUN. */
#pragma once
#include "sp11-payload.h"
#include "sp11-payload-wtab-abi.h"

#ifndef Q1N1_SP11_WTAB
#define Q1N1_SP11_WTAB 0
#endif
#if Q1N1_SP11_WTAB && !Q1N1_SP11_PAYLOAD
#error "Q1N1_SP11_WTAB=1 needs Q1N1_SP11_PAYLOAD=1: the write table is a service of the payload runner"
#endif

#if Q1N1_SP11_WTAB

/* Lines the table's own run may put on the panel: the open line, one ATTR line for each row, a NEXT line for each step that writes, and one or two lines for each
 * row. A table says what it will cost before it runs: validation (rule LINES) refuses a table whose lines plus the reserve below exceed LINES_MAX, and `put` stops
 * ordinary lines at LINES_MAX less that reserve, so that the lines that must exist always do: the STOP line (or the AUTO_UNWIND line), one U line and at most one
 * U FAIL line for each write row (undo and its failure), the END line, and, in a table with windows, the two WTAB READ REFUSED lines. A store whose own W line cannot
 * be printed is not made. */
#define Q1N1_WTAB_LINES_MAX 32u
#define Q1N1_WTAB_REFUSED_LINES 2u
/* Windowed reads the payload may make in one run, and the guarded reads one poll may make: bounds for a payload or a counter that runs wild. */
#define Q1N1_WTAB_WINDOW_READS_MAX 256u
#define Q1N1_WTAB_POLL_READS_MAX (1u << 22)
#define Q1N1_WTAB_STUCK_READS 4096u
#ifndef Q1N1_WTAB_SPIN_MAX
#define Q1N1_WTAB_SPIN_MAX 0xffffffffu
#endif
#define Q1N1_WTAB_COUNTER_HZ_MIN 1000000u
#define Q1N1_WTAB_COUNTER_HZ_MAX 1000000000u
/* A table whose name ends -DRAFT (the author's own label for expectations nobody has observed) is refused at open (reason DRAFT) unless this is built in. The
 * Makefile's WTAB=1 never sets it; the host model and the QEMU harness of a draft table do, by name, in their own build lines. */
#ifndef Q1N1_WTAB_ALLOW_DRAFT
#define Q1N1_WTAB_ALLOW_DRAFT 0
#endif

/* The mapping attribute of a word's page at EL2, as the stk survey of main.c classifies it (stk_attr: live_attr, then q1n1_mmu_attr_device). */
enum { Q1N1_WTAB_ATTR_UNKNOWN = 0, Q1N1_WTAB_ATTR_DEVICE, Q1N1_WTAB_ATTR_NORMAL, Q1N1_WTAB_ATTR_NONE };

/* What the runner needs from the platform for the table. */
struct q1n1_wtab_env {
    void (*emit)(const char *line);
    /* The recoverable-fault guarded 32-bit load and store of the runner (main.c live_guarded). 0 on success. A store that faulted may or may not have
     * written: an external abort on a write leaves the word unknown, so the runner counts the row as in force and its undo reads the word and proves it. */
    int (*read32)(uint32_t pa, uint32_t *out);
    int (*store32)(uint32_t pa, uint32_t value);
    /* Lets an error response of a store or a load reach the core and tells whether an SError was pending (and takes it): q1n1_platform_serror_poll. */
    int (*serror_poll)(void);
    uint64_t (*counter)(void);
    uint64_t counter_hz;
    /* The mapping attribute of the page of `pa` (Q1N1_WTAB_ATTR_*). A missing callback, or an answer the platform cannot give, is UNKNOWN. */
    int (*attr)(uint32_t pa);
};

/* What is true of the payload and the machine this run. */
struct q1n1_wtab_machine {
    uint64_t image_base, image_bytes;           /* the payload's own file in memory: the table must lie inside it */
    uint64_t map_base, map_size, map_stride;    /* the final UEFI memory map: no row may write a word of any memory but a device's */
};

struct q1n1_wtab_diag {
    uint32_t index;                             /* the row or window a refusal names; 0xffffffff for the header */
};

struct q1n1_wtab_result {
    int opened;
    int stopped;                                /* 1 when a row, a read or the table stopped the run */
    int reason;                                 /* the Q1N1_WTAB_ reason that stopped it, 0 when none */
    int finished;                               /* the undo ran (after a stop, on request or at the end) */
    int restored;                               /* every row that was changed was put back and proven */
    unsigned rows_done, stores, undos, undo_ok, undo_failed, window_reads, lines, dropped;
    uint32_t stop_row;
    uint8_t digest[32];                         /* SHA-256 of the table the run used */
};

const char *q1n1_wtab_reason_name(int reason);
/* Pure: the refusal rules of the table, in the order of Q1N1_WTAB_REASONS. `avail` is how many bytes may be read at `blob`. */
int q1n1_wtab_validate(const void *blob, uint64_t avail, struct q1n1_wtab_diag *diag);
/* Pure: 1 when the word at `addr` is in no descriptor of the memory map, or only in descriptors of the memory-mapped I/O types. A map
 * that cannot be read is 0 for everything. */
int q1n1_wtab_map_allows(const struct q1n1_wtab_machine *machine, uint32_t addr);
/* Pure: the ordinary lines the table can cost at most (the open line, an ATTR line for each row, the rows' own lines, a NEXT line for each step that writes). */
unsigned q1n1_wtab_line_cost(const struct q1n1_wtab_header *header, const struct q1n1_wtab_row *rows);
/* Pure: the lines kept back for the stop, the undo and the end (see Q1N1_WTAB_LINES_MAX). A table is accepted only when cost + reserve <= LINES_MAX. */
unsigned q1n1_wtab_line_reserve(const struct q1n1_wtab_header *header, const struct q1n1_wtab_row *rows);

/* The platform's services, given once at start-up (main.c) and read by the runner loop: the loop of sp11-payload-run.c has no `wtab` field in its environment, so
 * that the environment of a runner without the gate is the environment it always was. A runner that never attaches one gives no payload any ops. */
void q1n1_wtab_attach(const struct q1n1_wtab_env *env);
const struct q1n1_wtab_env *q1n1_wtab_attached(void);

/* Once for each payload, before its call: forgets the last run and arms the ops. */
void q1n1_wtab_begin(const struct q1n1_wtab_env *env, const struct q1n1_wtab_machine *machine);
const struct q1n1_payload_wtab_ops *q1n1_wtab_ops(void);
/* The gates of ops.load32: before a guarded load, 0 or Q1N1_WTAB_LOAD_E_GATED (the word is in a closed window); after one that read a
 * word of a window, the SError poll: 0, or Q1N1_WTAB_LOAD_E_GATED when one was pending (the run is stopped and undone then). */
int q1n1_wtab_load_check(uint64_t addr);
int q1n1_wtab_load_done(uint64_t addr);
/* Pure: 1 when the destination of ops.hex, [dst, dst + cap), lies inside the payload's stack (a cap of 0 writes nothing and is not looked at). No sum can wrap. */
int q1n1_wtab_hex_ok(const void *dst, uint32_t cap, uint64_t stack_base, uint64_t stack_size);
/* Pure apart from its reads: 1 when ops.puts may read `line` as the runner reads it (bytes 0 to Q1N1_PAYLOAD_LINE_MAX, stopping at the first NUL) because every byte it would read lies in
 * the stack or in the image of the payload. Nothing is read before the first byte is known to be in one of them, and no byte past the end of that one. */
int q1n1_wtab_puts_ok(const char *line, uint64_t stack_base, uint64_t stack_size, uint64_t image_base, uint64_t image_size);
/* After the payload returned: undoes what is still in force when the table says so, and ends the run if it is not yet ended. */
void q1n1_wtab_finish(struct q1n1_wtab_result *out);
const struct q1n1_wtab_result *q1n1_wtab_last(void);

#endif /* Q1N1_SP11_WTAB */
