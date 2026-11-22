/* SPDX-License-Identifier: MIT */
/* The rules of the write table, judged by the runner's own validator (platform/uefi/sp11-payload-wtab.c): one damaged field at a time against the reference table
 * and the reason and row each must give, the line budget with its reserve, the draft name, and the budget a run keeps (the worst case fits in the lines). The
 * differential test of the Python mirror (tools/test-q1n1-sp11-payload-wtab.py) feeds `--validate FILE` and `--validate-many FILE` of the main file the same bytes.
 * Hardware: NOT RUN. Evidence: EXPERIMENTAL (host model only). */
#include "test-q1n1-sp11-payload-wtab-fixture.h"

struct mut { const char *name; void (*apply)(void); const char *reason; uint32_t index; uint32_t avail; };

#define MUT(fn, body) static void fn(void) { body; }
MUT(m_magic, tab()->magic ^= 1)
MUT(m_version, tab()->version = 2)
MUT(m_hres, tab()->reserved[1] = 1)
MUT(m_rows0, tab()->rows = 0)
MUT(m_rows49, tab()->rows = 49)
MUT(m_win9, tab()->windows = 9)
MUT(m_steps0, tab()->steps = 0)
MUT(m_steps17, tab()->steps = 17)
MUT(m_bytes, tab()->bytes += 8)
MUT(m_flags, tab()->flags |= 4)
MUT(m_pause, tab()->pause_s = 31)
MUT(m_name_empty, tab()->name[0] = 0)
MUT(m_name_font, tab()->name[1] = 'a')
MUT(m_name_nonul, memset(tab()->name, 'A', 16))
MUT(m_name_tail, tab()->name[12] = 'X')
MUT(m_addr0, tab_row(1)->addr = 0)
MUT(m_addr_odd, tab_row(2)->addr |= 2)
MUT(m_value_mask, tab_row(1)->value = 0x2)
MUT(m_check_value, tab_row(0)->value = 0x1)
MUT(m_check_empty, { tab_row(0)->found_mask = 0; tab_row(0)->found_value = 0; tab_row(0)->rb_mask = 0; tab_row(0)->rb_addr = 0; tab_row(0)->rb_value = 0; })
MUT(m_check_undo, tab_row(0)->undo_kind = 1)
MUT(m_found_value, tab_row(1)->found_value |= 0x01000000)
MUT(m_no_found, { tab_row(2)->found_mask = 0; tab_row(2)->found_value = 0; })
MUT(m_found_short, { tab_row(1)->found_mask &= ~1u; tab_row(1)->found_value &= ~1u; })
MUT(m_found_part, { tab_row(2)->mask = 0x3; tab_row(2)->value = 0x3; })
MUT(m_never_writes, { tab_row(1)->found_mask |= 1; tab_row(1)->found_value &= ~1u; })
MUT(m_no_readback, { struct q1n1_wtab_row *r = tab_row(2); r->rb_mask = 0; r->rb_addr = 0; r->rb_value = 0; r->rb_timeout_us = 0; })
MUT(m_rb_addr, tab_row(2)->rb_addr = 0)
MUT(m_rb_unaligned, tab_row(2)->rb_addr |= 1)
MUT(m_rb_value, tab_row(2)->rb_value |= 0x1)
MUT(m_rb_contradicts, tab_row(2)->rb_mask |= 1)
MUT(m_rb_timeout_nomask, { struct q1n1_wtab_row *r = tab_row(0); r->rb_mask = 0; r->rb_addr = 0; r->rb_value = 0; r->rb_timeout_us = 5; })
MUT(m_times_rb, tab_row(2)->rb_timeout_us = 100001)
MUT(m_times_settle, tab_row(1)->settle_us = 1001)
MUT(m_times_after, tab_row(1)->after_us = 1001)
MUT(m_times_undo, tab_row(1)->undo_after_us = 1001)
MUT(m_undo_kind, tab_row(1)->undo_kind = 3)
MUT(m_undo_none, tab_row(2)->undo_kind = 0)
MUT(m_undo_value_noop, { tab_row(2)->undo_kind = 2; tab_row(2)->undo_value = 1; })
MUT(m_undo_value_mask, { tab_row(2)->undo_kind = 2; tab_row(2)->undo_value = 2; })
MUT(m_undo_restore_value, tab_row(2)->undo_value = 1)
MUT(m_undo_rb, { tab_row(1)->undo_rb_addr = 0; })
MUT(m_step_skip, { tab_row(2)->step = 4; tab_row(3)->step = 4; tab()->steps = 5; })
MUT(m_step_first, tab_row(0)->step = 1)
MUT(m_row_flags, tab_row(1)->flags = 1)
MUT(m_row_reserved, tab_row(1)->reserved[2] = 1)
MUT(m_tag_empty, tab_row(1)->tag[0] = 0)
MUT(m_tag_font, tab_row(1)->tag[0] = '#')
MUT(m_tag_tail, { memset(tab_row(1)->tag, 0, 8); tab_row(1)->tag[0] = 'A'; tab_row(1)->tag[5] = 'B'; })
MUT(m_win_size0, tab_win(0)->size = 0)
MUT(m_win_odd, tab_win(0)->base |= 1)
MUT(m_win_wrap, { tab_win(0)->base = 0xfffffff0u; tab_win(0)->size = 0x20; })
MUT(m_win_res, tab_win(0)->reserved = 1)
MUT(m_win_after, tab_win(0)->after_row = 9)
MUT(m_win_reads, { tab_win(0)->base = A_CLKA & ~0xfu; tab_win(0)->size = 0x40; })
MUT(m_steps_last, tab()->steps = 2)

static const struct mut mutations[] = {
    {"magic", m_magic, "MAGIC", 0xffffffffu, 0}, {"version", m_version, "VERSION", 0xffffffffu, 0}, {"header reserved", m_hres, "HEADER_RESERVED", 0xffffffffu, 0},
    {"rows 0", m_rows0, "COUNTS", 0xffffffffu, 0}, {"rows 49", m_rows49, "COUNTS", 0xffffffffu, 0}, {"windows 9", m_win9, "COUNTS", 0xffffffffu, 0},
    {"steps 0", m_steps0, "COUNTS", 0xffffffffu, 0}, {"steps 17", m_steps17, "COUNTS", 0xffffffffu, 0}, {"bytes", m_bytes, "BYTES", 0xffffffffu, 0},
    {"flags", m_flags, "FLAGS", 0xffffffffu, 0}, {"pause", m_pause, "PAUSE", 0xffffffffu, 0}, {"name empty", m_name_empty, "NAME", 0xffffffffu, 0},
    {"name font", m_name_font, "NAME", 0xffffffffu, 0}, {"name no NUL", m_name_nonul, "NAME", 0xffffffffu, 0}, {"name tail", m_name_tail, "NAME", 0xffffffffu, 0},
    {"addr 0", m_addr0, "ROW_ADDR", 1, 0}, {"addr odd", m_addr_odd, "ROW_ADDR", 2, 0}, {"value outside mask", m_value_mask, "ROW_MASK_VALUE", 1, 0},
    {"check with a value", m_check_value, "ROW_MASK_VALUE", 0, 0}, {"check that checks nothing", m_check_empty, "ROW_CHECK", 0, 0},
    {"check with an undo", m_check_undo, "ROW_CHECK", 0, 0}, {"found value outside mask", m_found_value, "ROW_FOUND", 1, 0},
    {"write row with no found mask", m_no_found, "ROW_NO_FOUND", 2, 0}, {"found mask short of the mask", m_found_short, "ROW_NO_FOUND", 1, 0},
    {"found mask covering part of the mask", m_found_part, "ROW_NO_FOUND", 2, 0},
    {"row that never writes", m_never_writes, "ROW_NEVER_WRITES", 1, 0}, {"write without read-back", m_no_readback, "ROW_NO_READBACK", 2, 0},
    {"read-back address 0", m_rb_addr, "ROW_RB", 2, 0}, {"read-back unaligned", m_rb_unaligned, "ROW_RB", 2, 0}, {"read-back value outside mask", m_rb_value, "ROW_RB", 2, 0},
    {"read-back contradicts the value", m_rb_contradicts, "ROW_RB_CONTRADICTS", 2, 0}, {"timeout without a mask", m_rb_timeout_nomask, "ROW_RB", 0, 0},
    {"read-back timeout", m_times_rb, "ROW_TIMES", 2, 0}, {"settle", m_times_settle, "ROW_TIMES", 1, 0}, {"after", m_times_after, "ROW_TIMES", 1, 0},
    {"undo after", m_times_undo, "ROW_TIMES", 1, 0}, {"undo kind", m_undo_kind, "ROW_UNDO", 1, 0}, {"no undo", m_undo_none, "ROW_UNDO", 2, 0},
    {"undo value is the value", m_undo_value_noop, "ROW_UNDO", 2, 0}, {"undo value outside mask", m_undo_value_mask, "ROW_UNDO", 2, 0},
    {"restore with a value", m_undo_restore_value, "ROW_UNDO", 2, 0}, {"undo read-back", m_undo_rb, "ROW_UNDO_RB", 1, 0}, {"step skipped", m_step_skip, "ROW_STEP", 2, 0},
    {"first step", m_step_first, "ROW_STEP", 0, 0}, {"row flags", m_row_flags, "ROW_RESERVED", 1, 0}, {"row reserved", m_row_reserved, "ROW_RESERVED", 1, 0},
    {"tag empty", m_tag_empty, "ROW_TAG", 1, 0}, {"tag font", m_tag_font, "ROW_TAG", 1, 0}, {"tag tail", m_tag_tail, "ROW_TAG", 1, 0},
    {"window empty", m_win_size0, "WIN_RANGE", 0, 0}, {"window odd", m_win_odd, "WIN_RANGE", 0, 0}, {"window wraps", m_win_wrap, "WIN_RANGE", 0, 0},
    {"window reserved", m_win_res, "WIN_RANGE", 0, 0}, {"window after", m_win_after, "WIN_AFTER", 0, 0}, {"row reads its window", m_win_reads, "WIN_ROW_READS", 0, 0},
    {"steps of the last row", m_steps_last, "STEPS", 0xffffffffu, 0},
};

void suite_validate(void)
{
    struct q1n1_wtab_diag diag;
    CHECK("good.accepted", q1n1_wtab_validate(good, good_bytes, &diag) == Q1N1_WTAB_OK);
    CHECK("good.short_avail", q1n1_wtab_validate(good, 10, &diag) == Q1N1_WTAB_SIZE_SHORT);
    CHECK("good.bytes_beyond_avail", q1n1_wtab_validate(good, good_bytes - 8, &diag) == Q1N1_WTAB_BYTES);
    CHECK("names.count", Q1N1_WTAB_REASON_COUNT == 49);
    CHECK("names.ok", !strcmp(q1n1_wtab_reason_name(0), "OK") && !strcmp(q1n1_wtab_reason_name(Q1N1_WTAB_UNDO_FAILED), "UNDO_FAILED"));
    CHECK("names.unknown", !strcmp(q1n1_wtab_reason_name(999), "UNKNOWN"));
    for (unsigned i = 0; i < sizeof mutations / sizeof mutations[0]; i++) {
        table_from(good, good_bytes);
        mutations[i].apply();
        int reason = q1n1_wtab_validate(tab(), good_bytes, &diag);
        char name[96];
        snprintf(name, sizeof name, "refuses.%s", mutations[i].name);
        CHECK(name, !strcmp(q1n1_wtab_reason_name(reason), mutations[i].reason) && diag.index == mutations[i].index);
        if (strcmp(q1n1_wtab_reason_name(reason), mutations[i].reason))
            fprintf(stderr, "  %s: got %s index %u, wanted %s %u\n", mutations[i].name, q1n1_wtab_reason_name(reason), diag.index, mutations[i].reason, mutations[i].index);
    }
    /* a window overlapping another */
    {
        struct { struct q1n1_wtab_header h; struct q1n1_wtab_row r[4]; struct q1n1_wtab_window w[2]; } t;
        memcpy(&t, good, sizeof t - sizeof t.w + sizeof t.w[0]);
        t.h.windows = 2; t.h.bytes = sizeof t;
        t.w[0] = ((const struct q1n1_wtab_window *)((const struct q1n1_wtab_row *)(good + 1) + 4))[0];
        t.w[1] = t.w[0]; t.w[1].base += 0x80;
        CHECK("refuses.windows_overlap", q1n1_wtab_validate(&t, sizeof t, &diag) == Q1N1_WTAB_WIN_OVERLAP && diag.index == 1);
    }
    /* the line budget: what a table costs plus what it keeps back for the stop, the undo and the end must fit in the 32 lines */
    {
        struct budget_table t;
        budget_build(&t, 4, 5);
        CHECK("refuses.too_many_lines", q1n1_wtab_validate(&t, budget_bytes(&t), &diag) == Q1N1_WTAB_LINES);
        budget_build(&t, 6, 0);
        CHECK("refuses.too_many_lines_of_writes", q1n1_wtab_validate(&t, budget_bytes(&t), &diag) == Q1N1_WTAB_LINES);
        budget_build(&t, 4, 4);
        CHECK("accepts.exactly_the_line_budget", q1n1_wtab_validate(&t, budget_bytes(&t), &diag) == Q1N1_WTAB_OK);
        CHECK("line_cost.exact_table", q1n1_wtab_line_cost(&t.h, t.r) == 22 && q1n1_wtab_line_reserve(&t.h, t.r) == 10 &&
              q1n1_wtab_line_cost(&t.h, t.r) + q1n1_wtab_line_reserve(&t.h, t.r) == Q1N1_WTAB_LINES_MAX);
        CHECK("line_cost.reference_table", q1n1_wtab_line_cost(good, (const struct q1n1_wtab_row *)(good + 1)) == 14 &&
              q1n1_wtab_line_reserve(good, (const struct q1n1_wtab_row *)(good + 1)) == 10);
    }
    /* a table named as a draft is refused unless the runner was built to take one (the harness is built both ways) */
    {
        table_from(good, good_bytes);
        memset(tab()->name, 0, sizeof tab()->name);
        memcpy(tab()->name, "WTABREF-DRAFT", 13);
        CHECK("draft.suffix_is_the_rule", q1n1_wtab_validate(tab(), good_bytes, &diag) == (Q1N1_WTAB_ALLOW_DRAFT ? Q1N1_WTAB_OK : Q1N1_WTAB_DRAFT));
        memset(tab()->name, 0, sizeof tab()->name);
        memcpy(tab()->name, "WTABREF-DRAFTS", 14);
        CHECK("draft.only_the_suffix", q1n1_wtab_validate(tab(), good_bytes, &diag) == Q1N1_WTAB_OK);
        memset(tab()->name, 0, sizeof tab()->name);
        memcpy(tab()->name, "-DRAFT", 6);
        CHECK("draft.short_name", q1n1_wtab_validate(tab(), good_bytes, &diag) == (Q1N1_WTAB_ALLOW_DRAFT ? Q1N1_WTAB_OK : Q1N1_WTAB_DRAFT));
    }
}

/* A table at the exact edge of the budget (22 ordinary lines and a reserve of 10) with all four of its writes in force and every undo failing: the stop, a U line and a
 * U FAIL line for each write row and the END line all fit in the 32 lines, and the END line is the last. */
void suite_lines(void)
{
    struct budget_table t;
    for (unsigned variant = 0; variant < 2; variant++) {
        char name[64];
        const char *how = variant ? "stop" : "finish";
        budget_build(&t, 4, 4);
        const struct q1n1_payload_wtab_ops *o = begin_budget_run(&t);
        snprintf(name, sizeof name, "worst_case_%s.rows", how);
        CHECK(name, do_open(o) == 0 && rows_ok(o, 8) && D.nstores == 4 && all_lines() == 22);
        D.ignore_all = 1;            /* from here every store is acknowledged and dropped: each undo prints its U line and then fails */
        struct q1n1_wtab_result res;
        if (variant) o->row(8);      /* an index past the table: STOP INDEX, then the undo */
        else q1n1_wtab_finish(&res);
        snprintf(name, sizeof name, "worst_case_%s.thirty_two_lines", how);
        CHECK(name, all_lines() == Q1N1_WTAB_LINES_MAX);
        snprintf(name, sizeof name, "worst_case_%s.nothing_dropped", how);
        CHECK(name, q1n1_wtab_last()->dropped == 0);
        snprintf(name, sizeof name, "worst_case_%s.one_u_and_one_fail_for_each_write", how);
        CHECK(name, lines_with("U ") == 8 && lines_with("U 0 P0") + lines_with("U 1 P1") + lines_with("U 2 P2") + lines_with("U 3 P3") == 4 &&
              lines_with("U 3 FAIL VERIFY") == 1 && lines_with("U 2 FAIL VERIFY") == 1 && lines_with("U 1 FAIL VERIFY") == 1 && lines_with("U 0 FAIL VERIFY") == 1);
        snprintf(name, sizeof name, "worst_case_%s.end_is_last", how);
        CHECK(name, !strncmp(ev[nev - 1].text, "WTAB END RESULT=UNDO_FAILED", 27) && ev[nev - 1].kind == EV_LINE);
        snprintf(name, sizeof name, "worst_case_%s.stop_or_auto_unwind_line", how);
        CHECK(name, variant ? lines_with("WTAB STOP WHY=INDEX") == 1 : lines_with("WTAB AUTO_UNWIND IN_FORCE=4") == 1);
    }
}

int validate_file(const char *path)
{
    FILE *f = fopen(path, "rb");
    if (!f) { perror(path); return 2; }
    static uint64_t buf[2048];
    size_t n = fread(buf, 1, sizeof buf, f);
    fclose(f);
    struct q1n1_wtab_diag diag;
    int reason = q1n1_wtab_validate(buf, n, &diag);
    printf("REASON %s %d\n", q1n1_wtab_reason_name(reason), diag.index == 0xffffffffu ? -1 : (int)diag.index);
    return 0;
}

int validate_many(const char *path)
{
    FILE *f = fopen(path, "rb");
    if (!f) { perror(path); return 2; }
    static uint64_t buf[2048];
    uint32_t n;
    while (fread(&n, 4, 1, f) == 1) {
        if (n > sizeof buf || fread(buf, 1, n, f) != n) { fprintf(stderr, "bad record\n"); return 2; }
        struct q1n1_wtab_diag diag;
        int reason = q1n1_wtab_validate(buf, n, &diag);
        printf("%s %d\n", q1n1_wtab_reason_name(reason), diag.index == 0xffffffffu ? -1 : (int)diag.index);
    }
    fclose(f);
    return 0;
}
