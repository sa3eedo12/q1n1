/* SPDX-License-Identifier: MIT */
/* The write table: the one way a stick payload may change a device register (docs/SP11-PAYLOAD-WTAB.md).
 *
 * A payload does not store to a device word itself (tools/sp11_payload_memcheck.py checks that the BASE of every store of its disassembly is its own stack, and
 * tools/sp11_payload_wtab_audit.py checks the same of its IR; the OFFSET of a store is not proved, and a payload is machine code at EL2 that can store wherever it likes:
 * what keeps such a store out of a payload is that its bytes are reviewed and pinned by the SHA-256 in the manifest, sp11-payload-abi.h; these checks catch the accident).
 * A payload that must change a device word carries a TABLE of the words it may change, in its read-only data, and asks the runner to execute one row at a time:
 *
 *     rc = ops->row(k);       // k is a constant of the payload's code, never an address and never a value
 *
 * The runner validates the table once (open), keeps its own copy, and does everything that touches the device: the read before the
 * write, the guarded store, the read-back, the journal and, on any failure, the undo of every row it changed in reverse order. The
 * payload cannot name an address or a value through these ops, so the table, whose SHA-256 the operator quotes, is the whole of what the ops can write.
 *
 * This header is shared by the runner (a PE image), the payloads (bare-metal ELF), the host tests and the host tool
 * tools/sp11_wtab.py, which holds the same layout and the same refusal rules in Python (the two are tested against each other).
 * Freestanding: stdint and stddef only, and no gate: it only declares the contract. ABI v1 of the payload (sp11-payload-abi.h) is not
 * changed: the runner hands the payload's ops in args.reserved[0] when, and only when, it is built with Q1N1_SP11_WTAB=1.
 *
 * Evidence: EXPERIMENTAL. Host model only; hardware NOT RUN. Every address and bit a table carries is the table author's claim, and its
 * label (VERIFIED in a pinned source, OBSERVED on the unit, INFERRED) is in the document that approves it, never here. */
#pragma once
#include <stddef.h>
#include <stdint.h>

#define Q1N1_WTAB_TABLE_MAGIC UINT64_C(0x31425457314e3151)   /* "Q1N1WTB1", byte 0 first */
#define Q1N1_WTAB_OPS_MAGIC UINT64_C(0x31504f57314e3151)     /* "Q1N1WOP1" */
#define Q1N1_WTAB_TABLE_VERSION 1u
#define Q1N1_WTAB_ROWS_MAX 48u
#define Q1N1_WTAB_WINDOWS_MAX 8u
#define Q1N1_WTAB_STEPS_MAX 16u
#define Q1N1_WTAB_PAUSE_MAX_S 30u
#define Q1N1_WTAB_NAME_BYTES 16u
#define Q1N1_WTAB_TAG_BYTES 8u
/* One poll may last this long: past it the device is not slow, it is stuck, and the run stops and undoes. */
#define Q1N1_WTAB_POLL_MAX_US 100000u
#define Q1N1_WTAB_DELAY_MAX_US 1000u

/* Header flags. RESTORE_AT_END: the runner undoes every row still in force when the payload returns (a payload that forgot, or died on
 * its own error, cannot leave the device changed). ALLOW_IRREVERSIBLE: a row may have no undo; the approval note must then say so. */
#define Q1N1_WTAB_F_RESTORE_AT_END 0x1u
#define Q1N1_WTAB_F_ALLOW_IRREVERSIBLE 0x2u
#define Q1N1_WTAB_F_KNOWN (Q1N1_WTAB_F_RESTORE_AT_END | Q1N1_WTAB_F_ALLOW_IRREVERSIBLE)

/* How a row is undone. A row with mask 0 changes nothing and has none. */
enum {
    Q1N1_WTAB_UNDO_NONE = 0,        /* irreversible: only with Q1N1_WTAB_F_ALLOW_IRREVERSIBLE */
    Q1N1_WTAB_UNDO_RESTORE = 1,     /* the masked bits go back to what the runner read just before it wrote them */
    Q1N1_WTAB_UNDO_VALUE = 2,       /* the masked bits are set to undo_value */
};

/* 64 bytes. Everything is little-endian and every word is naturally aligned. */
struct q1n1_wtab_header {
    uint64_t magic;
    uint32_t version;
    uint32_t bytes;             /* the whole table: header, rows, windows. It is the length the SHA-256 covers */
    uint32_t rows, windows;
    uint32_t flags;
    uint32_t pause_s;           /* wait before the first store of every step that has one (0 to 30 s) */
    uint32_t steps;             /* number of distinct steps: the last row's step plus one */
    uint32_t reserved[3];       /* zero */
    char name[Q1N1_WTAB_NAME_BYTES];    /* page font only, NUL terminated: it is printed */
};

/* 88 bytes. A row is one 32-bit device word. The runner does, in this order:
 *   1. pre  = load(addr). (pre & found_mask) must equal found_value: the state the author saw and expects to find; anything else stops the
 *      run before this row writes (a unit or firmware that differs is an answer, not a license).
 *   2. mask == 0: a CHECK row, nothing is written. Otherwise, when (pre & mask) already equals value the store is skipped (the row is
 *      still read back and, if it was skipped, has nothing to undo); else new = (pre & ~mask) | value is stored once.
 *   3. After settle_us the runner polls load(rb_addr) until (v & rb_mask) == rb_value or rb_timeout_us has passed. A write row has one.
 *   4. after_us of delay before the next row (the hardware's own settle time, from the driver the row is derived from).
 * Undo (kind RESTORE or VALUE) reads the word, writes the masked bits back, waits undo_after_us... and then proves them: the same word read
 * again must show the restored bits, and, if undo_rb_mask is not 0, load(undo_rb_addr) must match undo_rb_value within undo_timeout_us. */
struct q1n1_wtab_row {
    uint32_t addr;
    uint32_t mask, value;
    uint32_t found_mask, found_value;
    uint32_t rb_addr, rb_mask, rb_value, rb_timeout_us;
    uint16_t settle_us, after_us;
    uint8_t undo_kind, reserved8[3];
    uint32_t undo_value;                /* UNDO_VALUE only */
    uint32_t undo_rb_addr, undo_rb_mask, undo_rb_value;
    uint16_t undo_timeout_us, undo_after_us;
    uint16_t step, flags;               /* step: 0, then non-decreasing in steps of at most one; flags: zero */
    char tag[Q1N1_WTAB_TAG_BYTES];      /* page font only, NUL padded: it is printed. The first byte is not NUL */
    uint32_t reserved[3];               /* zero */
};

/* 16 bytes. Words the payload may read (through ops.load32) only while the row `after_row` is complete, and never again once the run has
 * stopped or been undone: a block behind a power domain or a clock the table switches on. A read outside every window is not gated. */
struct q1n1_wtab_window {
    uint32_t base, size;
    uint32_t after_row;
    uint32_t reserved;
};

/* The table is laid out as header, then `rows` rows, then `windows` windows, with no padding. */
_Static_assert(sizeof(struct q1n1_wtab_header) == 64, "wtab ABI: header size");
_Static_assert(sizeof(struct q1n1_wtab_row) == 88, "wtab ABI: row size");
_Static_assert(sizeof(struct q1n1_wtab_window) == 16, "wtab ABI: window size");
_Static_assert(offsetof(struct q1n1_wtab_header, bytes) == 12, "wtab ABI: header.bytes");
_Static_assert(offsetof(struct q1n1_wtab_header, flags) == 24, "wtab ABI: header.flags");
_Static_assert(offsetof(struct q1n1_wtab_header, name) == 48, "wtab ABI: header.name");
_Static_assert(offsetof(struct q1n1_wtab_row, rb_addr) == 20, "wtab ABI: row.rb_addr");
_Static_assert(offsetof(struct q1n1_wtab_row, settle_us) == 36, "wtab ABI: row.settle_us");
_Static_assert(offsetof(struct q1n1_wtab_row, undo_kind) == 40, "wtab ABI: row.undo_kind");
_Static_assert(offsetof(struct q1n1_wtab_row, undo_value) == 44, "wtab ABI: row.undo_value");
_Static_assert(offsetof(struct q1n1_wtab_row, undo_timeout_us) == 60, "wtab ABI: row.undo_timeout_us");
_Static_assert(offsetof(struct q1n1_wtab_row, step) == 64, "wtab ABI: row.step");
_Static_assert(offsetof(struct q1n1_wtab_row, tag) == 68, "wtab ABI: row.tag");
_Static_assert(offsetof(struct q1n1_wtab_row, reserved) == 76, "wtab ABI: row.reserved");

#define Q1N1_WTAB_TABLE_BYTES(rows, windows) \
    (sizeof(struct q1n1_wtab_header) + (rows) * sizeof(struct q1n1_wtab_row) + (windows) * sizeof(struct q1n1_wtab_window))

/* Every outcome, once: the refusals of a table (the first rule that fails, in this order) and the stops of a run. The names are printed
 * (WTAB REFUSED=<NAME>, WTAB STOP WHY=<NAME>) and the host tool prints and tests the same list. A status is 0 for success. */
#define Q1N1_WTAB_REASONS(X) \
    X(OK) \
    /* table, header */ \
    X(SIZE_SHORT) X(MAGIC) X(VERSION) X(HEADER_RESERVED) X(COUNTS) X(BYTES) X(FLAGS) X(PAUSE) X(NAME) \
    /* table, rows (the first failing rule of the first failing row) */ \
    X(ROW_ADDR) X(ROW_MASK_VALUE) X(ROW_CHECK) X(ROW_FOUND) X(ROW_NO_FOUND) X(ROW_NEVER_WRITES) X(ROW_NO_READBACK) X(ROW_RB) X(ROW_RB_CONTRADICTS) \
    X(ROW_TIMES) X(ROW_UNDO) X(ROW_UNDO_RB) X(ROW_STEP) X(ROW_RESERVED) X(ROW_TAG) \
    /* table, windows and the whole */ \
    X(WIN_RANGE) X(WIN_AFTER) X(WIN_OVERLAP) X(WIN_ROW_READS) X(STEPS) X(LINES) X(DRAFT) \
    /* open, against the machine */ \
    X(NOT_IN_IMAGE) X(REOPEN) X(ROW_ADDR_TYPE) X(PLATFORM) X(ROW_ATTR) \
    /* a run */ \
    X(NOT_OPEN) X(INDEX) X(ORDER) X(STOPPED) X(FOUND) X(FAULT) X(SERROR) X(READBACK) X(COUNTER) X(BUDGET) X(WINDOW_READ) X(UNDO_FAILED)
enum {
#define X(name) Q1N1_WTAB_##name,
    Q1N1_WTAB_REASONS(X)
#undef X
    Q1N1_WTAB_REASON_COUNT
};
#define Q1N1_WTAB_OK_STATUS Q1N1_WTAB_OK

/* The ops the runner hands a payload, in args.reserved[0] of the unchanged ABI v1. Plain function pointers with no context, like the
 * four of the payload ABI: one payload runs at a time. */
struct q1n1_payload_wtab_ops {
    uint64_t magic;             /* Q1N1_WTAB_OPS_MAGIC */
    uint32_t version, size;     /* Q1N1_WTAB_TABLE_VERSION, sizeof this */
    /* Validates `table` (inside the payload's own image) and keeps a copy. Once per payload. Returns 0 or the refusal. */
    int32_t (*open)(const struct q1n1_wtab_header *table);
    /* Executes row `index`: it must be the next one, in table order. Returns 0 (done, or already as wanted) or the reason the run stopped;
     * on a stop the runner has already undone what it changed, printed why and ended the run, and every later call returns STOPPED. */
    int32_t (*row)(uint32_t index);
    /* Undoes every row still in force, in reverse, now. Returns 0 when each was put back and proven, else UNDO_FAILED. Idempotent. */
    int32_t (*unwind)(void);
    uint64_t reserved[2];       /* zero */
};
_Static_assert(offsetof(struct q1n1_payload_wtab_ops, open) == 16, "wtab ABI: ops.open");
_Static_assert(offsetof(struct q1n1_payload_wtab_ops, row) == 24, "wtab ABI: ops.row");
_Static_assert(offsetof(struct q1n1_payload_wtab_ops, unwind) == 32, "wtab ABI: ops.unwind");
_Static_assert(sizeof(struct q1n1_payload_wtab_ops) == 56, "wtab ABI: ops size");

/* The payload's typed view of the arguments of ABI v1 (sp11-payload-abi.h): the same bytes, with reserved[0] as the pointer the runner
 * fills. A payload reads it through this struct so that no integer ever becomes a pointer in its code. The runner's own struct is
 * unchanged; the assertions tie the two layouts together where the payload code is compiled. */
struct q1n1_payload_args_wtab {
    uint64_t head[15];                  /* magic .. stack_size: offsets 0 to 119 of struct q1n1_payload_args */
    uint64_t ops[4];                    /* the four ops of ABI v1, offsets 120 to 151 */
    const struct q1n1_payload_wtab_ops *wtab;       /* reserved[0]: offset 152 */
    uint64_t reserved[4];
};
_Static_assert(offsetof(struct q1n1_payload_args_wtab, wtab) == 152, "wtab ABI: args.reserved[0] is at 152");
_Static_assert(sizeof(struct q1n1_payload_args_wtab) == 192, "wtab ABI: size of the args of version 1");

/* The extra answer of load32 in a build with the write table: the word is in a window whose gate is closed, or the run has stopped. */
#define Q1N1_WTAB_LOAD_E_GATED 7
