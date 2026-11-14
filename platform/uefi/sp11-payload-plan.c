/* SPDX-License-Identifier: MIT */
/* The runner's declared ranges (sp11-payload.h): which ranges the scoped sweep is asked to clean, and
 * whether the paired slbounce will accept them. Pure: no EFI and no allocation, so the native tests
 * drive it against synthetic memory maps shaped like the unit's.
 *
 * q1n1_payload_map_check mirrors sp11_sweep_range in the slbounce fork (src/sp11_scoped_sweep.c) and
 * the per-range loop of its sp11_run_scoped_sweep (src/bounce_main.c), in the same order, so that a
 * range slbounce would refuse is refused here, on the firmware console and with a status the Shell
 * sees, rather than as the bare EFI_ABORTED that fails ExitBootServices and leaves q1n1 halted.
 * tools/test-q1n1-sp11-payload.py compiles slbounce's own file and compares the two verdicts over
 * random maps when SLBOUNCE_SP11_DIR names the fork (SKIP without). slbounce stays the authority: this
 * is a prediction, and the refusal ExitBootServices gives remains the backstop. */
#include "sp11-payload.h"

#if Q1N1_SP11_PAYLOAD

const char *q1n1_payload_plan_name(int status)
{
    switch (status) {
    case Q1N1_PLAN_OK: return "OK";
    case Q1N1_PLAN_NO_TABLE: return "NO_TABLE";
    case Q1N1_PLAN_TOO_MANY: return "TOO_MANY_RANGES";
    case Q1N1_PLAN_CHUNK_CAP: return "CHUNK_CAP";
    case Q1N1_PLAN_EMPTY: return "EMPTY_RANGE";
    case Q1N1_PLAN_WRAP: return "RANGE_WRAPS";
    case Q1N1_PLAN_FRAMEBUFFER: return "RANGE_IN_FRAMEBUFFER";
    case Q1N1_PLAN_OVERLAP: return "RANGES_OVERLAP";
    case Q1N1_PLAN_TOO_LARGE: return "RANGE_TOO_LARGE";
    case Q1N1_PLAN_NOT_CONTAINED: return "NOT_IN_ONE_DESCRIPTOR";
    case Q1N1_PLAN_WRONG_TYPE: return "TYPE_NOT_SWEPT";
    case Q1N1_PLAN_NOT_WB: return "NOT_WRITE_BACK";
    default: return "UNKNOWN";
    }
}

/* Chunks a range of `size` bytes splits into at a cap of `chunk_cap`, without overflowing. */
static uint64_t chunks_for(uint64_t size, uint32_t chunk_cap)
{
    return size / chunk_cap + (size % chunk_cap != 0);
}

static int ranges_overlap(const struct sp11_ebs_range *a, const struct sp11_ebs_range *b)
{
    return a->base < b->base + b->size && b->base < a->base + a->size;
}

int q1n1_payload_table_check(const struct sp11_ebs_ranges_table *t, uint64_t fb_base, uint64_t fb_bytes)
{
    if (!t || t->count == 0) return Q1N1_PLAN_NO_TABLE;
    if (t->count > SP11_EBS_MAX_RANGES) return Q1N1_PLAN_TOO_MANY;
    if (t->chunk_cap == 0) return Q1N1_PLAN_CHUNK_CAP;
    for (uint32_t i = 0; i < t->count; i++)
        if (t->range[i].size == 0) return Q1N1_PLAN_EMPTY;
    for (uint32_t i = 0; i < t->count; i++)
        if (t->range[i].base + t->range[i].size < t->range[i].base) return Q1N1_PLAN_WRAP;
    /* The framebuffer is RESERVED memory on the unit (type 0), which the scoped sweep refuses by design:
     * declaring any byte of it would fail every ExitBootServices. Nothing reads it after the bounce. */
    if (fb_bytes && fb_base + fb_bytes >= fb_base) {
        struct sp11_ebs_range fb = {fb_base, fb_bytes};
        for (uint32_t i = 0; i < t->count; i++)
            if (ranges_overlap(&t->range[i], &fb)) return Q1N1_PLAN_FRAMEBUFFER;
    }
    for (uint32_t i = 0; i < t->count; i++)
        for (uint32_t j = i + 1; j < t->count; j++)
            if (ranges_overlap(&t->range[i], &t->range[j])) return Q1N1_PLAN_OVERLAP;
    for (uint32_t i = 0; i < t->count; i++)
        if (chunks_for(t->range[i].size, t->chunk_cap) > Q1N1_PAYLOAD_SWEEP_MAX_OPS) return Q1N1_PLAN_TOO_LARGE;
    return Q1N1_PLAN_OK;
}

int q1n1_payload_plan_append(struct sp11_ebs_ranges_table *table, const char **labels,
                             const struct q1n1_payload_loaded *loaded, uint64_t fb_base, uint64_t fb_bytes)
{
    static const char *const file_label[Q1N1_PAYLOAD_MAX_FILES] = {"payload", "file1", "file2", "file3", "file4"};
    if (loaded->count > Q1N1_PAYLOAD_MAX_FILES || table->count + loaded->count > SP11_EBS_MAX_RANGES)
        return Q1N1_PLAN_TOO_MANY;
    struct sp11_ebs_ranges_table candidate = *table;
    for (uint32_t i = 0; i < loaded->count; i++) {
        candidate.range[candidate.count].base = loaded->file[i].base;
        candidate.range[candidate.count].size = loaded->file[i].alloc;
        candidate.count++;
    }
    int status = q1n1_payload_table_check(&candidate, fb_base, fb_bytes);
    if (status) return status;
    for (uint32_t i = 0; i < loaded->count; i++) labels[table->count + i] = file_label[i];
    *table = candidate;
    return Q1N1_PLAN_OK;
}

/* The memory types slbounce sweeps: loader, boot services and runtime services code and data, and ACPI
 * reclaim memory (its SP11_SWEEP_EFI_* values 1 to 6 and 9). */
static int type_is_swept(uint64_t type)
{
    return (type >= 1 && type <= 6) || type == 9;
}

#define ATTRIBUTE_WB (UINT64_C(1) << 3)

int q1n1_payload_map_check(const struct sp11_ebs_ranges_table *t, const struct q1n1_sp11_gop_map_entry *map,
                           uint32_t map_count, uint32_t *failing)
{
    *failing = 0;
    for (uint32_t r = 0; r < t->count; r++) {
        uint64_t base = t->range[r].base, size = t->range[r].size;
        *failing = r;
        if (t->chunk_cap == 0) return Q1N1_PLAN_CHUNK_CAP;
        if (size == 0) return Q1N1_PLAN_EMPTY;
        /* Exactly one descriptor must hold the whole range, checked before its type or attribute. */
        uint32_t covering = map_count, matches = 0;
        for (uint32_t i = 0; i < map_count; i++) {
            if (map[i].base <= base && base + size <= map[i].base + map[i].pages * 4096u) {
                if (matches == 0) covering = i;
                matches++;
            }
        }
        if (matches != 1) return Q1N1_PLAN_NOT_CONTAINED;
        if (!type_is_swept(map[covering].type)) return Q1N1_PLAN_WRONG_TYPE;
        if (!(map[covering].attribute & ATTRIBUTE_WB)) return Q1N1_PLAN_NOT_WB;
        if (chunks_for(size, t->chunk_cap) > Q1N1_PAYLOAD_SWEEP_MAX_OPS) return Q1N1_PLAN_TOO_LARGE;
    }
    *failing = 0;
    return Q1N1_PLAN_OK;
}

int q1n1_payload_precheck(int plan_status, uint64_t declared_status, uint64_t map_status, int map_parsed,
                          const struct sp11_ebs_ranges_table *table, const struct q1n1_sp11_gop_map_entry *map,
                          uint32_t map_count, struct q1n1_payload_diag *diag)
{
    uint32_t failing = 0;
    if (plan_status) {
        diag->plan = plan_status;
        return Q1N1_PAYLOAD_E_RANGES;
    }
    if (!table || !table->count) {
        diag->plan = Q1N1_PLAN_NO_TABLE;
        return Q1N1_PAYLOAD_E_RANGES;
    }
    if (declared_status) {
        diag->efi = declared_status;
        return Q1N1_PAYLOAD_E_DECLARE;
    }
    if (!map_parsed) {
        diag->efi = map_status;
        return Q1N1_PAYLOAD_E_MAP;
    }
    int status = q1n1_payload_map_check(table, map, map_count, &failing);
    if (status) {
        diag->plan = status;
        diag->range = failing;
        return Q1N1_PAYLOAD_E_RANGES;
    }
    return Q1N1_PAYLOAD_OK;
}

#endif /* Q1N1_SP11_PAYLOAD */
