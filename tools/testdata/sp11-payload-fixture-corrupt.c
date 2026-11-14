/* SPDX-License-Identifier: MIT */
/* Test fixture for the payload runner's chain under QEMU (tools/test-q1n1-sp11-payload-qemu.py), never installed on
 * a stick: flips one byte of a later payload of the chain, found through the preload table, as a payload that
 * scribbled on memory that was not its own would. The runner hashes every payload again right before its call, so
 * the chain must stop at the damaged payload, not before it and not after. Built with -DFIXTURE_CORRUPT_TARGET=n,
 * the manifest index of the file it damages. */
#include "payload-util.h"
#include "preload.h"

#ifndef FIXTURE_CORRUPT_TARGET
#define FIXTURE_CORRUPT_TARGET 2
#endif

uint64_t payload_entry(const struct q1n1_payload_args *a);
uint64_t payload_entry(const struct q1n1_payload_args *a)
{
    if (!pl_args_ok(a)) return Q1N1_PAYLOAD_RET_BAD_ARGS;
    const struct q1n1_preload_cache *table = (const void *)(uintptr_t)a->preload_table;
    if (table->count <= FIXTURE_CORRUPT_TARGET) return 2;
    volatile uint8_t *victim = (volatile uint8_t *)(uintptr_t)table->files[FIXTURE_CORRUPT_TARGET].base;
    victim[100] ^= 0x01;
    a->ops.puts("FIXTURE CORRUPT FLIPPED A BYTE OF A LATER PAYLOAD");
    return 0;
}
