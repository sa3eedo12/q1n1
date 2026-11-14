/* SPDX-License-Identifier: MIT */
/* Test fixture for the payload runner under QEMU (tools/test-q1n1-sp11-payload-qemu.py), never installed
 * on a stick: executes an undefined instruction at EL2. It must end in q1n1's own fault page, which names
 * the exception and where it happened. */
#include "payload-util.h"

uint64_t payload_entry(const struct q1n1_payload_args *a);
uint64_t payload_entry(const struct q1n1_payload_args *a)
{
    (void)a;
    __asm__ volatile(".inst 0x00000000");
    return 0;
}
