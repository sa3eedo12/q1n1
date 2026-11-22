/* SPDX-License-Identifier: MIT */
/* The reference payload of the write-table tests (tools/test-q1n1-sp11-payload-wtab.py): the shape every payload with a table has, over the
 * fake device of the host model. It is never built into a bundle and its table writes nothing real: the addresses are the model's. The seeded
 * bugs of the tests are small changes of this file and of its table (tools/sp11_payload_wtab_mutants.py).
 *
 * Opens its table, runs the four rows in order, reads one word of the window the table opens, and returns the domain to how it was found. */
#include "payload-wtab.h"
#include "wtab-ref-table.h"

#define BLOCK_WORD 0x01008000u
/* The host harness points this at a page-aligned copy it loads as the payload's image; the target build opens the constant itself. */
#ifndef WTAB_TABLE_ADDRESS
#define WTAB_TABLE_ADDRESS ((const struct q1n1_wtab_header *)&wtab_wtabref)
#endif

/* The text goes through a line in the payload's own stack frame, as every payload's lines do: the runner of a write-table run reads a string for ops.puts only from the stack or
 * from the payload's image, and the host harness compiles this file into its own image, where a literal is not in the payload's. The append loop is its own function, so that its
 * stores with a register offset stay in the one function the policy names (tools/sp11_payload_wtab_audit.py, `wtabref`). */
static __attribute__((noinline)) void line_text(struct pl_line *line, const char *text)
{
    pl_text(line, text);
}

static void say(const struct q1n1_payload_args *a, const char *text)
{
    struct pl_line line;
    pl_begin(&line);
    line_text(&line, text);
    pl_emit(a, &line);
}

uint64_t payload_entry(const struct q1n1_payload_args *a)
{
    uint32_t word = 0;
    if (!pl_args_ok(a)) return Q1N1_PAYLOAD_RET_BAD_ARGS;
    if (!a->ops.load32 || !a->ops.counter) return Q1N1_PAYLOAD_RET_BAD_ARGS;
    const struct q1n1_payload_wtab_ops *wtab = pl_wtab_ops(a);
    if (!wtab) {
        say(a, "REF REFUSED=NO_WTAB_RUNNER");
        return 2;
    }
    if (wtab->open(WTAB_TABLE_ADDRESS)) {
        say(a, "REF REFUSED=OPEN");
        return 3;
    }
    if (wtab->row(WROW_GATE) || wtab->row(WROW_DOMAIN) || wtab->row(WROW_CLKA) || wtab->row(WROW_CLKB)) {
        say(a, "REF STOPPED");
        return 1;
    }
    if (a->ops.load32(BLOCK_WORD, &word)) {
        say(a, "REF READ REFUSED");
        return 1;
    }
    struct pl_line line;
    pl_begin(&line);
    line_text(&line, "REF BLOCK=");
    pl_hex(a, &line, word);
    pl_emit(a, &line);
    if (wtab->unwind()) {
        say(a, "REF UNDO FAILED");
        return 1;
    }
    say(a, "REF END");
    return 0;
}
