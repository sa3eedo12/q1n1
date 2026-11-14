/* SPDX-License-Identifier: MIT */
/* Test fixture for the payload runner under QEMU (tools/test-q1n1-sp11-payload-qemu.py), never installed
 * on a stick: never returns. The last line the runner printed must be the one that names the call. */
#include "payload-util.h"

uint64_t payload_entry(const struct q1n1_payload_args *a);
uint64_t payload_entry(const struct q1n1_payload_args *a)
{
    (void)a;
    for (;;) __asm__ volatile("");
}
