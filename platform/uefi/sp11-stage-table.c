/* SPDX-License-Identifier: MIT */
/* See sp11-stage-table.h. Pure functions: no allocation, no I/O. Compiled only for
 * SNAP_PLATFORM_SP11. */
#include "sp11-stage-table.h"

#if SNAP_PLATFORM_SP11

#define PAGE_MASK 0xfffu

/* main.c's own stage_candidates[], the exact addresses an SP11 descriptor may never list (F02: "a
 * board-config table... refusing to fall back to the A16 addresses"). */
static const uint64_t a16_stage_candidates[] = {UINT64_C(0xb0000000), UINT64_C(0x4c000000), UINT64_C(0xa0000000)};

static int is_a16_candidate(uint64_t base)
{
    for (unsigned i = 0; i < sizeof a16_stage_candidates / sizeof a16_stage_candidates[0]; i++)
        if (a16_stage_candidates[i] == base) return 1;
    return 0;
}

int q1n1_sp11_stage_table_validate(const struct q1n1_sp11_stage_table *t)
{
    if (!t) return Q1N1_SP11_STAGE_ERR_NULL;
    if (t->magic != Q1N1_SP11_STAGE_MAGIC) return Q1N1_SP11_STAGE_ERR_MAGIC;
    if (t->version != Q1N1_SP11_STAGE_VERSION) return Q1N1_SP11_STAGE_ERR_VERSION;
    if (t->count < 1 || t->count > Q1N1_SP11_STAGE_MAX_CANDIDATES) return Q1N1_SP11_STAGE_ERR_COUNT;
    for (uint32_t i = t->count; i < Q1N1_SP11_STAGE_MAX_CANDIDATES; i++)
        if (t->candidate[i]) return Q1N1_SP11_STAGE_ERR_RESERVED;
    for (uint32_t i = 0; i < t->count; i++) {
        uint64_t base = t->candidate[i];
        if (!base || (base & PAGE_MASK)) return Q1N1_SP11_STAGE_ERR_ALIGN;
        if (is_a16_candidate(base)) return Q1N1_SP11_STAGE_ERR_A16_BASE;
    }
    for (uint32_t i = 0; i < t->count; i++)
        for (uint32_t j = i + 1; j < t->count; j++) {
            uint64_t a = t->candidate[i], b = t->candidate[j];
            if (a < b + Q1N1_SP11_STAGE_BYTES && b < a + Q1N1_SP11_STAGE_BYTES)
                return Q1N1_SP11_STAGE_ERR_OVERLAP;
        }
    return Q1N1_SP11_STAGE_OK;
}

const char *q1n1_sp11_stage_error_name(int code)
{
    static const char *const names[Q1N1_SP11_STAGE_ERR_COUNT_ALL] = {
        "OK", "NULL", "MAGIC", "VERSION", "COUNT", "RESERVED", "ALIGN", "A16_BASE", "OVERLAP"};
    return code >= 0 && code < Q1N1_SP11_STAGE_ERR_COUNT_ALL ? names[code] : "UNKNOWN";
}

#endif /* SNAP_PLATFORM_SP11 */
