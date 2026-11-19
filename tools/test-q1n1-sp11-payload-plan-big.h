/* SPDX-License-Identifier: MIT */
/* The big-file case of the plan program (tools/test-q1n1-sp11-payload-plan.c), compiled in only with Q1N1_SP11_BIGFILE=1 (docs/SP11-PAYLOAD-BIGFILE.md): the declared table
 * at the chunk cap the gate declares (8 MiB by default, 64 KiB in the small build), the 256-op budget at its edge in 64-bit arithmetic, the number of ops a range needs,
 * a range that spans two descriptors, and, with slbounce's source, its own verdicts on the same ranges. Nothing here runs on EFI or on hardware. Evidence: EXPERIMENTAL
 * (host model only). */

static struct sp11_ebs_ranges_table big_table(uint32_t count, const uint64_t sizes[])
{
    struct sp11_ebs_ranges_table t;
    memset(&t, 0, sizeof t);
    t.magic = SP11_EBS_RANGES_MAGIC; t.version = SP11_EBS_RANGES_VERSION; t.chunk_cap = Q1N1_PAYLOAD_CHUNK_BYTES;
    t.count = count;
    for (uint32_t i = 0; i < count; i++) t.range[i] = (struct sp11_ebs_range){UINT64_C(0x1000000000) * (i + 1) * 4 + UINT64_C(0x100000000), sizes[i]};
    return t;
}

static int suite_big(void)
{
    const uint64_t cap = Q1N1_PAYLOAD_CHUNK_BYTES, max = Q1N1_PAYLOAD_MAX_FILE_BYTES;
    CHECK(max == Q1N1_PAYLOAD_SWEEP_MAX_OPS * cap && sizeof(size_t) == 8);

    /* The budget at its edge: 256 ops is allowed, one page more is not, and a size whose low 32 bits would pass is not mistaken for one that does. */
    static const struct { uint64_t size; int want; } edge[] = {
        {Q1N1_PAYLOAD_MAX_FILE_BYTES, Q1N1_PLAN_OK}, {Q1N1_PAYLOAD_MAX_FILE_BYTES - 4096, Q1N1_PLAN_OK},
        {Q1N1_PAYLOAD_MAX_FILE_BYTES + 4096, Q1N1_PLAN_TOO_LARGE}, {Q1N1_PAYLOAD_MAX_FILE_BYTES + 1, Q1N1_PLAN_TOO_LARGE},
        {(UINT64_C(1) << 32) + Q1N1_PAYLOAD_CHUNK_BYTES, Q1N1_PLAN_TOO_LARGE}, {(UINT64_C(1) << 32) + 4096, Q1N1_PLAN_TOO_LARGE},
        {UINT64_C(1) << 33, Q1N1_PLAN_TOO_LARGE}, {(UINT64_C(2) << 30) + 4096, Q1N1_PLAN_TOO_LARGE}, {4096, Q1N1_PLAN_OK},
    };
    for (unsigned i = 0; i < sizeof edge / sizeof edge[0]; i++) {
        /* In the 2 GiB build a size of 2 GiB + a page is over the budget; in the 64 KiB build it is far over it. Either way it is refused. */
        uint64_t size = edge[i].size;
        struct sp11_ebs_ranges_table t = big_table(1, &size);
        CHECK(q1n1_payload_table_check(&t, fb_base, fb_bytes) == edge[i].want);
        CHECK(q1n1_payload_table_max_ops(&t) == size / cap + (size % cap != 0));
    }
    {
        uint64_t exact = max, over = max + 4096, sizes[2] = {exact, over};
        struct sp11_ebs_ranges_table t = big_table(2, sizes);
        CHECK(q1n1_payload_table_check(&t, fb_base, fb_bytes) == Q1N1_PLAN_TOO_LARGE);
        CHECK(q1n1_payload_table_max_ops(&t) == Q1N1_PAYLOAD_SWEEP_MAX_OPS + 1);
        CHECK(q1n1_payload_table_max_ops(NULL) == 0);
        t.chunk_cap = 0;
        CHECK(q1n1_payload_table_max_ops(&t) == 0);
    }

    /* The numbers of the root image: 1,862,270,976 bytes (1,776 MiB) and a GUEST.DAT of the size boot 25 had, at the default cap of 8 MiB. */
    if (cap == 8u << 20) {
        uint64_t sizes[5] = {64u << 20, 4096, 0x13a0, 1862270976u, 118908480u};
        struct sp11_ebs_ranges_table t = big_table(5, sizes);
        CHECK(q1n1_payload_table_check(&t, fb_base, fb_bytes) == Q1N1_PLAN_OK && q1n1_payload_table_max_ops(&t) == 222);
        sizes[3] = 1990000000u;
        t = big_table(5, sizes);
        CHECK(q1n1_payload_table_check(&t, fb_base, fb_bytes) == Q1N1_PLAN_OK && q1n1_payload_table_max_ops(&t) == 238);
        sizes[0] = 1; sizes[1] = 1; sizes[2] = 1; sizes[3] = 1; sizes[4] = 118908480u;
        t = big_table(5, sizes);
        CHECK(q1n1_payload_table_max_ops(&t) == 15);
        /* And one range of 2 GiB, the most one file may be: 256 ops of 8 MiB. */
        CHECK(max == UINT64_C(2) << 30);
    }

    /* Files of this size through the append: the plan accepts the ranges and keeps the cap the table had. */
    {
        struct sp11_ebs_ranges_table t = base_table();
        const char *labels[SP11_EBS_MAX_RANGES] = {"image", "map", "preload"};
        struct q1n1_payload_loaded l = loaded_files(2);
        t.chunk_cap = Q1N1_PAYLOAD_CHUNK_BYTES;
        l.file[1].base = UINT64_C(0xF80000000) - max;
        l.file[1].alloc = max;
        l.file[1].bytes = max - 7;
        CHECK(q1n1_payload_plan_append(&t, labels, &l, fb_base, fb_bytes) == Q1N1_PLAN_OK);
        CHECK(t.count == 5 && t.range[4].size == max && t.chunk_cap == Q1N1_PAYLOAD_CHUNK_BYTES);
        CHECK(q1n1_payload_table_max_ops(&t) == Q1N1_PAYLOAD_SWEEP_MAX_OPS);
        l.file[1].alloc = max + 4096;
        struct sp11_ebs_ranges_table again = base_table();
        again.chunk_cap = Q1N1_PAYLOAD_CHUNK_BYTES;
        CHECK(q1n1_payload_plan_append(&again, labels, &l, fb_base, fb_bytes) == Q1N1_PLAN_TOO_LARGE && again.count == 3);
    }

    /* Against a memory map: the file's range is inside ONE descriptor of a swept type with write-back (a firmware that lists the same allocation as two adjacent
     * descriptors is refused by name, not swept in part), and the budget is asked last. */
    {
        const uint64_t base = UINT64_C(0xF00000000);
        uint64_t size = max;
        struct sp11_ebs_ranges_table t = big_table(1, &size);
        struct q1n1_sp11_gop_map_entry one[3];
        uint32_t at = 9;
        t.range[0].base = base;
        one[0] = (struct q1n1_sp11_gop_map_entry){2, base, size / 4096, UINT64_C(0xf)};
        CHECK(q1n1_payload_map_check(&t, one, 1, &at) == Q1N1_PLAN_OK && at == 0);
        one[0].pages = size / 4096 - 1;
        CHECK(q1n1_payload_map_check(&t, one, 1, &at) == Q1N1_PLAN_NOT_CONTAINED);
        one[0] = (struct q1n1_sp11_gop_map_entry){2, base, size / 8192, UINT64_C(0xf)};
        one[1] = (struct q1n1_sp11_gop_map_entry){2, base + size / 2, size / 8192, UINT64_C(0xf)};
        CHECK(q1n1_payload_map_check(&t, one, 2, &at) == Q1N1_PLAN_NOT_CONTAINED);
        one[0] = (struct q1n1_sp11_gop_map_entry){7, base, size / 4096, UINT64_C(0xf)};
        CHECK(q1n1_payload_map_check(&t, one, 1, &at) == Q1N1_PLAN_WRONG_TYPE);
        one[0] = (struct q1n1_sp11_gop_map_entry){2, base, size / 4096, UINT64_C(0x7)};
        CHECK(q1n1_payload_map_check(&t, one, 1, &at) == Q1N1_PLAN_NOT_WB);
        size = max + 4096;
        t = big_table(1, &size);
        t.range[0].base = base;
        one[0] = (struct q1n1_sp11_gop_map_entry){2, base, size / 4096, UINT64_C(0xf)};
        CHECK(q1n1_payload_map_check(&t, one, 1, &at) == Q1N1_PLAN_TOO_LARGE && at == 0);
        size = (UINT64_C(1) << 32) + Q1N1_PAYLOAD_CHUNK_BYTES;
        t = big_table(1, &size);
        t.range[0].base = base;
        one[0] = (struct q1n1_sp11_gop_map_entry){2, base, size / 4096, UINT64_C(0xf)};
        CHECK(q1n1_payload_map_check(&t, one, 1, &at) == Q1N1_PLAN_TOO_LARGE);
    }

#ifdef HAVE_SLBOUNCE_SWEEP
    /* slbounce's own verdict on the same ranges, and its number of ops where it accepts: the same as the runner's. */
    {
        static const uint64_t sizes[] = {Q1N1_PAYLOAD_MAX_FILE_BYTES, Q1N1_PAYLOAD_MAX_FILE_BYTES - 4096, Q1N1_PAYLOAD_MAX_FILE_BYTES + 4096,
                                         (UINT64_C(1) << 32) + Q1N1_PAYLOAD_CHUNK_BYTES, 4096, 1862270976u};
        for (unsigned i = 0; i < sizeof sizes / sizeof sizes[0]; i++) {
            const uint64_t base = UINT64_C(0xF00000000), size = sizes[i];
            struct sp11_sweep_descriptor desc = {2, 0xf, base, (size + 4095) / 4096};
            struct sp11_sweep_op ops[256];
            uint32_t n_ops = 0, at = 0;
            int rc = sp11_sweep_range(&desc, 1, base, size, Q1N1_PAYLOAD_CHUNK_BYTES, ops, 256, &n_ops);
            struct sp11_ebs_ranges_table t = big_table(1, &size);
            struct q1n1_sp11_gop_map_entry entry = {2, base, (size + 4095) / 4096, UINT64_C(0xf)};
            t.range[0].base = base;
            CHECK(q1n1_payload_map_check(&t, &entry, 1, &at) == mapped_status(rc));
            if (rc == SP11_SWEEP_OK) {
                CHECK(n_ops == q1n1_payload_table_max_ops(&t));
                uint64_t sum = 0;
                for (uint32_t k = 0; k < n_ops; k++) {
                    CHECK(ops[k].size <= Q1N1_PAYLOAD_CHUNK_BYTES);
                    sum += ops[k].size;
                }
                CHECK(sum == size);
            }
        }
    }
#endif
    return 0;
}
