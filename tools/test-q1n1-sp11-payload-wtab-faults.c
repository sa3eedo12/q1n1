/* SPDX-License-Identifier: MIT */
/* The faults of a run that the other suites of the host test (tools/test-q1n1-sp11-payload-wtab.c) do not reach: an error response found only by the poll after a
 * read-back, an undo that must wait before it proves a word, a counter that stops being one between the open and a timed poll, an undo whose store faults while other
 * rows are still to be put back, the mapping asked for the page of the row and not of its read-back, a settle time that matters, and a line that cannot be printed
 * before its store. Each check fails when the line of the runner that it is about is removed (tools/sp11_payload_wtab_mutants.py names the removal for each).
 * Hardware: NOT RUN. Evidence: EXPERIMENTAL (host model only). */
#include "test-q1n1-sp11-payload-wtab-fixture.h"

void suite_faults(void)
{
    const struct q1n1_payload_wtab_ops *o;

    /* an error response that only the third poll of the row finds (before the store: clean; after the store: clean; after the read-back: found) */
    o = begin_run();
    CHECK("late_serror.open", do_open(o) == 0 && o->row(0) == 0);
    D.serror_on_poll = 3;
    CHECK("late_serror.stops", o->row(1) == Q1N1_WTAB_SERROR);
    CHECK("late_serror.names_the_readback_word", lines_with("WTAB STOP WHY=SERROR ROW=1 A=0X1001004") == 1);
    CHECK("late_serror.the_row_was_in_force_and_is_undone", stores_of(A_DCTL) == 2 && D.dctl == 0x0022f801 && lines_with("U 1 DOMAIN") == 1);
    CHECK("late_serror.end", !strncmp(end_line(), "WTAB END RESULT=RESTORED WHY=SERROR", 35));

    /* the undo waits undo_after_us before it proves the word: this device settles 50 us after the undo store and the proof is one read */
    o = begin_run();
    tab_row(1)->undo_after_us = 100;
    tab_row(1)->undo_timeout_us = 0;
    D.dom_off_us = 50;
    CHECK("undo_waits.rows", do_open(o) == 0 && o->row(0) == 0 && o->row(1) == 0);
    CHECK("undo_waits.proven_after_the_wait", o->unwind() == 0 && lines_with("U 1 FAIL") == 0 && D.dctl == 0x0022f801);

    /* a counter that is no longer one when a timed poll starts: the poll is a stop, never a poll without a clock */
    o = begin_run();
    tab_row(0)->rb_timeout_us = 50;
    CHECK("counter_unusable.open", do_open(o) == 0);
    wenv.counter_hz = 0;
    CHECK("counter_unusable.no_frequency_stops", o->row(0) == Q1N1_WTAB_COUNTER && lines_with("WTAB STOP WHY=COUNTER ROW=0") == 1);
    o = begin_run();
    tab_row(0)->rb_timeout_us = 50;
    CHECK("counter_unusable.open_again", do_open(o) == 0);
    wenv.counter = 0;
    CHECK("counter_unusable.no_counter_stops", o->row(0) == Q1N1_WTAB_COUNTER);

    /* the store of one undo faults: the rows before it in the undo order and the rows after it are still put back and proven */
    o = begin_run();
    CHECK("undo_store_fault.rows", do_open(o) == 0 && rows_ok(o, 4) && D.nstores == 3);
    D.fault_store = A_CLKA;
    CHECK("undo_store_fault.unwind_reports_it", o->unwind() == Q1N1_WTAB_UNDO_FAILED);
    CHECK("undo_store_fault.the_row_is_named", lines_with("U 2 FAIL FAULT") == 1);
    CHECK("undo_store_fault.the_others_are_undone_and_proven", lines_with("U 3 FAIL") == 0 && lines_with("U 1 FAIL") == 0 && D.clkb == 0 && D.dctl == 0x0022f801);
    CHECK("undo_store_fault.end", !strcmp(end_line(), "WTAB END RESULT=UNDO_FAILED WHY=OK ROWS=4 STORES=3 UNDOS=3 RESTORED=2 OF=3"));

    /* the mapping asked for is that of the row's own address: DOMAIN reads back from a page of its own */
    o = begin_run();
    tab_row(1)->rb_addr = A_PLAIN;
    attr_page = A_PLAIN & ~0xfffu;
    attr_class = Q1N1_WTAB_ATTR_NORMAL;
    CHECK("attr_of_the_row.a_normal_readback_page_opens", do_open(o) == 0 && lines_with("WTAB ATTR DOMAIN DEVICE") == 1);
    o = begin_run();
    tab_row(1)->rb_addr = A_PLAIN;
    attr_page = A_DCTL & ~0xfffu;
    attr_class = Q1N1_WTAB_ATTR_NORMAL;
    CHECK("attr_of_the_row.a_normal_row_page_is_refused", do_open(o) == Q1N1_WTAB_ROW_ATTR && lines_with("WTAB ATTR DOMAIN NORMAL") == 1);

    /* the settle time of a row is waited before its read-back, which here is a single read of a word that is right only 50 us after the store */
    o = begin_run();
    tab_row(1)->rb_timeout_us = 0;
    tab_row(1)->settle_us = 100;
    D.dom_on_us = 50;
    CHECK("settle_waits.rows", do_open(o) == 0 && o->row(0) == 0 && o->row(1) == 0);
    CHECK("settle_waits.result_line", lines_with("R 1 OK") == 1);

    /* a line that cannot be printed is a stop before its store: nothing is written that the page did not announce */
    o = begin_run();
    D.emit_off_after = "R 1 OK";
    CHECK("no_line_no_store.rows_before", do_open(o) == 0 && o->row(0) == 0 && o->row(1) == 0);
    CHECK("no_line_no_store.stops", o->row(2) == Q1N1_WTAB_BUDGET);
    CHECK("no_line_no_store.nothing_stored", stores_of(A_CLKA) == 0 && D.clka == 0 && lines_with("W 2 CLKA") == 0);
    CHECK("no_line_no_store.the_domain_is_undone", D.dctl == 0x0022f801 && stores_of(A_DCTL) == 2 && q1n1_wtab_last()->stopped &&
          q1n1_wtab_last()->reason == Q1N1_WTAB_BUDGET && q1n1_wtab_last()->dropped > 0);
}
