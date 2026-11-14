/* SPDX-License-Identifier: MIT */
/* Test fixture for the payload runner under QEMU (tools/test-q1n1-sp11-payload-qemu.py), never installed
 * on a stick: writes the lowest word of its own stack, where the runner keeps its guard words, and
 * returns. The runner must say STACK=OVERFLOW. */
#include "payload-util.h"

uint64_t payload_entry(const struct q1n1_payload_args *a);
uint64_t payload_entry(const struct q1n1_payload_args *a)
{
    if (!pl_args_ok(a)) return Q1N1_PAYLOAD_RET_BAD_ARGS;
    *(volatile uint64_t *)(uintptr_t)a->stack_base = 0;
    a->ops.puts("FIXTURE OVERFLOW WROTE THE LOWEST STACK WORD");
    return 7;
}
