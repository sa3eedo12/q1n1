/* SPDX-License-Identifier: MIT */
/* What the runner asks before a table runs (platform/uefi/sp11-payload-wtab.c, op_open): the table must be in the payload's image, once, over device memory in the
 * firmware's memory map; the platform must offer what the table needs; the mapping of every row's page is printed and a row that writes needs Device memory; a table
 * named as a draft is refused. Hardware: NOT RUN. Evidence: EXPERIMENTAL (host model only). */
#include "test-q1n1-sp11-payload-wtab-fixture.h"

void suite_open(void)
{
    const struct q1n1_payload_wtab_ops *o;
    uint32_t outside[4] = {0};
    o = begin_run();
    CHECK("before_open.row_refused", o->row(0) == Q1N1_WTAB_NOT_OPEN && o->row(0) == Q1N1_WTAB_NOT_OPEN && lines_with("WTAB REFUSED=NOT_OPEN") == 1);
    CHECK("before_open.nothing_touched", D.nreads == 0 && D.nstores == 0);
    CHECK("before_open.unwind", o->unwind() == Q1N1_WTAB_NOT_OPEN);
    CHECK("outside.refused", o->open((const struct q1n1_wtab_header *)outside) == Q1N1_WTAB_NOT_IN_IMAGE && lines_with("WTAB REFUSED=NOT_IN_IMAGE") == 1);
    CHECK("null.refused", o->open(0) == Q1N1_WTAB_NOT_IN_IMAGE);
    CHECK("misaligned.refused", o->open((const struct q1n1_wtab_header *)(image + TABLE_AT + 4)) == Q1N1_WTAB_NOT_IN_IMAGE);
    CHECK("past_end.refused", o->open((const struct q1n1_wtab_header *)(image + IMAGE_BYTES - 16)) != Q1N1_WTAB_OK);
    CHECK("then_open.ok", do_open(o) == 0 && do_open(o) == Q1N1_WTAB_REOPEN && lines_with("WTAB REFUSED=REOPEN") == 1);
    CHECK("reopen.keeps_the_first", o->row(0) == 0);

    /* the run follows the copy it validated, not the payload's image: a word of the image changed after open changes nothing */
    o = begin_run();
    CHECK("copy.open", do_open(o) == 0);
    tab_row(1)->addr = A_CLKA;
    CHECK("copy.is_private", o->row(0) == 0 && o->row(1) == 0 && stores_of(A_DCTL) == 1 && stores_of(A_CLKA) == 0);

    /* the last bytes of the image: a table that would run past it is refused by the size rule, not read */
    o = begin_run();
    memcpy(image + IMAGE_BYTES - good_bytes, good, good_bytes);
    machine.image_bytes = IMAGE_BYTES - 8;
    q1n1_wtab_begin(&wenv, &machine);
    o = q1n1_wtab_ops();
    CHECK("tail.refused", o->open((const struct q1n1_wtab_header *)(image + IMAGE_BYTES - good_bytes)) == Q1N1_WTAB_BYTES);

    /* the memory map: a row over RAM, over reserved memory, over nothing known, and no map at all */
    o = begin_run();
    put_desc(1, 7, 0x01000000u, 0x10);
    CHECK("ram.refused", do_open(o) == Q1N1_WTAB_ROW_ADDR_TYPE && lines_with("WTAB REFUSED=ROW_ADDR_TYPE AT=1") == 1);
    CHECK("ram.nothing_runs", o->row(0) == Q1N1_WTAB_NOT_OPEN && D.nreads == 0);
    o = begin_run();
    put_desc(1, 0, 0x01001000u, 1);
    CHECK("reserved.refused", do_open(o) == Q1N1_WTAB_ROW_ADDR_TYPE);
    o = begin_run();
    put_desc(1, 6, 0x01002000u, 1);
    CHECK("runtime_memory_over_one_row.refused", do_open(o) == Q1N1_WTAB_ROW_ADDR_TYPE);
    o = begin_run();
    put_desc(1, 7, 0x01008000u, 1);         /* RAM over the read window only: reads are not stores */
    CHECK("ram_over_a_read_window.accepted", do_open(o) == 0);
    o = begin_run();
    memset(mapbuf, 0, sizeof mapbuf);       /* a map with nothing in it: every row is in no descriptor */
    put_desc(0, 7, 0x80000000u, 1);
    machine.map_size = 48;
    q1n1_wtab_begin(&wenv, &machine);
    CHECK("map_without_the_device.accepted", do_open(o) == 0);
    o = begin_run();
    machine.map_base = 0;
    q1n1_wtab_begin(&wenv, &machine);
    CHECK("no_map.refused", do_open(o) == Q1N1_WTAB_ROW_ADDR_TYPE);
    o = begin_run();
    machine.map_stride = 36;
    q1n1_wtab_begin(&wenv, &machine);
    CHECK("bad_stride.refused", do_open(o) == Q1N1_WTAB_ROW_ADDR_TYPE);
    o = begin_run();
    machine.map_size = 100;
    q1n1_wtab_begin(&wenv, &machine);
    CHECK("bad_size.refused", do_open(o) == Q1N1_WTAB_ROW_ADDR_TYPE);
    o = begin_run();
    put_desc(2, 7, 0xffffffffffff0000ull, 0xffffffffffffull);     /* a descriptor whose end overflows: it covers everything above its start */
    CHECK("overflowing_descriptor.low_rows_unaffected", do_open(o) == 0);

    /* check rows over RAM are fine: a check row stores nothing */
    o = begin_run();
    tab_row(0)->addr = 0x80000000u;
    CHECK("check_row_over_ram.accepted", do_open(o) == 0);

    /* a refused table leaves nothing open, and the next one can be opened */
    o = begin_run();
    tab()->magic = 0;
    CHECK("bad_table.refused", do_open(o) == Q1N1_WTAB_MAGIC && lines_with("WTAB REFUSED=MAGIC") == 1);
    table_from(good, good_bytes);
    CHECK("bad_table.then_good_opens", do_open(o) == 0);

    /* the mapping of every row's page is printed, check rows included; only a row that writes needs Device memory, and an answer that is not Device is a refusal */
    o = begin_run();
    attr_page = A_GATE; attr_class = Q1N1_WTAB_ATTR_NORMAL;
    CHECK("attr.check_row_on_normal_is_printed_and_opens", do_open(o) == 0 && lines_with("WTAB ATTR GATE NORMAL") == 1 && lines_with("WTAB ATTR DOMAIN DEVICE") == 1 &&
          lines_with("WTAB REFUSED") == 0);
    CHECK("attr.runs_on", rows_ok(o, 4));

    static const struct { int cls; const char *name; } bad[] = {
        {Q1N1_WTAB_ATTR_NORMAL, "NORMAL"}, {Q1N1_WTAB_ATTR_NONE, "NONE"}, {Q1N1_WTAB_ATTR_UNKNOWN, "UNKNOWN"},
    };
    for (unsigned i = 0; i < sizeof bad / sizeof bad[0]; i++) {
        char name[64], line[48];
        o = begin_run();
        attr_page = A_DCTL; attr_class = bad[i].cls;        /* the page of the DOMAIN row, which writes */
        snprintf(name, sizeof name, "attr.write_row_on_%s.refused", bad[i].name);
        CHECK(name, do_open(o) == Q1N1_WTAB_ROW_ATTR && lines_with("WTAB REFUSED=ROW_ATTR AT=1") == 1);
        snprintf(line, sizeof line, "WTAB ATTR DOMAIN %s", bad[i].name);
        snprintf(name, sizeof name, "attr.write_row_on_%s.named", bad[i].name);
        CHECK(name, lines_with(line) == 1 && lines_with("WTAB ATTR ") == 4 && line_index("WTAB REFUSED") > line_index(line));
        snprintf(name, sizeof name, "attr.write_row_on_%s.nothing_runs", bad[i].name);
        CHECK(name, o->row(0) == Q1N1_WTAB_NOT_OPEN && D.nreads == 0 && D.nstores == 0 && lines_with("WTAB OPEN") == 0);
    }
    o = begin_run();
    attr_all = Q1N1_WTAB_ATTR_NORMAL;
    CHECK("attr.names_the_first_write_row", do_open(o) == Q1N1_WTAB_ROW_ATTR && lines_with("WTAB REFUSED=ROW_ATTR AT=1") == 1);
    {
        static struct q1n1_wtab_env no_attr;
        no_attr = wenv; no_attr.attr = 0;
        o = begin_run();
        q1n1_wtab_begin(&no_attr, &machine);
        CHECK("attr.no_callback_is_unknown", do_open(o) == Q1N1_WTAB_ROW_ATTR && lines_with("WTAB ATTR DOMAIN UNKNOWN") == 1 && lines_with("WTAB ATTR GATE UNKNOWN") == 1);
    }
    {
        struct budget_table t;
        budget_build(&t, 0, 3);          /* a table of checks only (the dry run of a live table) */
        o = begin_budget_run(&t);
        attr_all = Q1N1_WTAB_ATTR_NORMAL;
        CHECK("attr.checks_only_table_opens_on_normal_pages", do_open(o) == 0 && lines_with("WTAB ATTR GATE NORMAL") == 3 && rows_ok(o, 3));
        CHECK("attr.checks_only_table_stores_nothing", D.nstores == 0 && o->unwind() == 0 &&
              !strcmp(end_line(), "WTAB END RESULT=RESTORED WHY=OK ROWS=3 STORES=0 UNDOS=0 RESTORED=0 OF=0"));
    }

    /* what the table needs of the platform is asked before anything runs */
    {
        static struct q1n1_wtab_env cut;
        cut = wenv; cut.store32 = 0;
        o = begin_run(); q1n1_wtab_begin(&cut, &machine);
        CHECK("platform.no_store32_refused", do_open(o) == Q1N1_WTAB_PLATFORM && lines_with("WTAB REFUSED=PLATFORM") == 1 && D.nreads == 0);
        cut = wenv; cut.serror_poll = 0;
        o = begin_run(); q1n1_wtab_begin(&cut, &machine);
        CHECK("platform.no_serror_poll_refused", do_open(o) == Q1N1_WTAB_PLATFORM);
        cut = wenv; cut.counter = 0;
        o = begin_run(); q1n1_wtab_begin(&cut, &machine);
        CHECK("platform.no_counter_refused", do_open(o) == Q1N1_WTAB_PLATFORM);
        cut = wenv; cut.counter_hz = 1000;
        o = begin_run(); q1n1_wtab_begin(&cut, &machine);
        CHECK("platform.bad_counter_rate_refused", do_open(o) == Q1N1_WTAB_PLATFORM);
        o = begin_run(); counter_mode = 1;
        CHECK("platform.stuck_counter_refused", do_open(o) == Q1N1_WTAB_PLATFORM && D.nreads == 0 && D.nstores == 0);
        o = begin_run(); counter_mode = 2; counter_calls = 100;
        CHECK("platform.counter_running_backwards_refused", do_open(o) == Q1N1_WTAB_PLATFORM);
        struct budget_table t;
        budget_build(&t, 0, 2);
        cut = wenv; cut.store32 = 0; cut.serror_poll = 0; cut.counter = 0;
        dev_found(); machine_default(); table_from(&t, budget_bytes(&t));
        q1n1_wtab_begin(&cut, &machine);
        o = q1n1_wtab_ops();
        CHECK("platform.checks_only_table_needs_only_read32", do_open(o) == 0);
    }

    /* a table named as a draft is not opened by a runner built without the allowance (the harness is built both ways) */
    o = begin_run();
    memset(tab()->name, 0, sizeof tab()->name);
    memcpy(tab()->name, "WTABREF-DRAFT", 13);
    CHECK("draft.open", do_open(o) == (Q1N1_WTAB_ALLOW_DRAFT ? 0 : Q1N1_WTAB_DRAFT) && lines_with("WTAB REFUSED=DRAFT") == (Q1N1_WTAB_ALLOW_DRAFT ? 0u : 1u));
    CHECK("draft.nothing_read_or_written", Q1N1_WTAB_ALLOW_DRAFT || (D.nreads == 0 && D.nstores == 0 && lines_with("WTAB ATTR") == 0));
}
