/* SPDX-License-Identifier: MIT */
/* Test fixture for the payload runner under QEMU (tools/test-q1n1-sp11-payload-qemu.py), never installed
 * on a stick: one call of load32 for each way the op can answer. The word it reads is the first of the
 * payload's own file, the start stub's BTI c (0xD503245F). Prints FIXTURE LOAD <case>=<result> lines. */
#include "payload-util.h"

static void result(const struct q1n1_payload_args *a, const char *key, int32_t value, uint32_t word)
{
    struct pl_line line;
    pl_begin(&line);
    pl_text(&line, "FIXTURE LOAD ");
    pl_text(&line, key);
    pl_text(&line, "=");
    pl_hex(a, &line, (uint32_t)value);
    pl_text(&line, " WORD=");
    pl_hex(a, &line, word);
    pl_emit(a, &line);
}

uint64_t payload_entry(const struct q1n1_payload_args *a);
uint64_t payload_entry(const struct q1n1_payload_args *a)
{
    if (!pl_args_ok(a)) return Q1N1_PAYLOAD_RET_BAD_ARGS;
    /* Inside the stack and 16-byte aligned, below anything the ops put there. */
    uint32_t *slot = (uint32_t *)(uintptr_t)(a->stack_base + a->stack_size / 2);
    *slot = 0xa5a5a5a5u;
    result(a, "OWN", a->ops.load32(a->payload_base, slot), *slot);
    *slot = 0xa5a5a5a5u;
    result(a, "ALIGN", a->ops.load32(a->payload_base + 2, slot), *slot);
    result(a, "RANGE", a->ops.load32(UINT64_C(1) << 48, slot), *slot);
    /* The destination is the payload's own code, not its stack: refused, and not written. */
    result(a, "OUT", a->ops.load32(a->payload_base, (uint32_t *)(uintptr_t)a->payload_base), *slot);
    /* Far inside the 48-bit space and mapped by nothing the firmware built: a translation fault the guard
     * recovers from. */
    result(a, "FAULT", a->ops.load32(UINT64_C(0x400000000000), slot), *slot);
    result(a, "AFTER", a->ops.load32(a->payload_base, slot), *slot);
    return 0;
}
