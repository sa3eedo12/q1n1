/* SPDX-License-Identifier: MIT */
/* Test fixture for the payload runner's chain under QEMU (tools/test-q1n1-sp11-payload-qemu.py), never installed on
 * a stick: says who it is, which base and size the runner called it with, and returns 0x100 plus its id, so that the
 * order of a chain, each payload's own base and size, and the value that came back are all on the page. Built several
 * times with -DFIXTURE_MARK_ID=n, which gives each copy bytes (and a hash) of its own. */
#include "payload-util.h"

#ifndef FIXTURE_MARK_ID
#define FIXTURE_MARK_ID 0
#endif

uint64_t payload_entry(const struct q1n1_payload_args *a);
uint64_t payload_entry(const struct q1n1_payload_args *a)
{
    if (!pl_args_ok(a)) return Q1N1_PAYLOAD_RET_BAD_ARGS;
    struct pl_line line;
    pl_begin(&line);
    pl_text(&line, "FIXTURE MARK ID=");
    pl_hex(a, &line, FIXTURE_MARK_ID);
    pl_text(&line, " BASE=");
    pl_hex(a, &line, a->payload_base);
    pl_text(&line, " SIZE=");
    pl_hex(a, &line, a->payload_size);
    pl_emit(a, &line);
    return 0x100 + FIXTURE_MARK_ID;
}
