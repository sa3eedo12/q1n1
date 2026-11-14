/* SPDX-License-Identifier: MIT */
/* Test fixture for the payload runner's chain under QEMU (tools/test-q1n1-sp11-payload-qemu.py), never installed on
 * a stick: makes 4100 loads of its own first word, 4 more than the budget of one call, and says how many were
 * answered and how many refused. Two of these in one chain must each get the whole budget: the second says the same
 * as the first. Returns 0x4100. */
#include "payload-util.h"

uint64_t payload_entry(const struct q1n1_payload_args *a);
uint64_t payload_entry(const struct q1n1_payload_args *a)
{
    if (!pl_args_ok(a)) return Q1N1_PAYLOAD_RET_BAD_ARGS;
    /* Inside the stack and 16-byte aligned, below anything the ops put there. */
    uint32_t *slot = (uint32_t *)(uintptr_t)(a->stack_base + a->stack_size / 2);
    uint32_t answered = 0, refused = 0;
    for (uint32_t i = 0; i < Q1N1_PAYLOAD_LOADS_MAX + 4; i++) {
        if (a->ops.load32(a->payload_base, slot) == Q1N1_PAYLOAD_LOAD_OK) answered++;
        else refused++;
    }
    struct pl_line line;
    pl_begin(&line);
    pl_text(&line, "FIXTURE BUDGET ANSWERED=");
    pl_hex(a, &line, answered);
    pl_text(&line, " REFUSED=");
    pl_hex(a, &line, refused);
    pl_emit(a, &line);
    return 0x4100;
}
