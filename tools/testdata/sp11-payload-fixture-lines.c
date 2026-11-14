/* SPDX-License-Identifier: MIT */
/* Test fixture for the payload runner under QEMU (tools/test-q1n1-sp11-payload-qemu.py), never installed
 * on a stick: prints more lines than the budget of one call and returns a known value. The runner must
 * keep the first Q1N1_PAYLOAD_LINES_MAX, count the rest as dropped, and print what came back. */
#include "payload-util.h"

uint64_t payload_entry(const struct q1n1_payload_args *a);
uint64_t payload_entry(const struct q1n1_payload_args *a)
{
    if (!pl_args_ok(a)) return Q1N1_PAYLOAD_RET_BAD_ARGS;
    for (uint32_t i = 0; i < Q1N1_PAYLOAD_LINES_MAX + 5; i++) {
        struct pl_line line;
        pl_begin(&line);
        pl_text(&line, "FIXTURE LINE ");
        pl_hex(a, &line, i);
        pl_emit(a, &line);
    }
    return 0x1234;
}
