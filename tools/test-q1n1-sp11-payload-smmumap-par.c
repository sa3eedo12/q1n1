/* SPDX-License-Identifier: MIT */
/* Host test for how the mapping step (platform/uefi/sp11-smmumap.c, docs/SP11-PAYLOAD-SMMUMAP.md) reads PAR_EL1 after an AT. When F (bit 0) is set the translation
 * FAILED and the rest of the register is a fault status; the architecture does not promise that its address field is zero, so a step that judged the address field
 * alone would take a faulting translation that happens to echo the page for a hit. The model of tools/test-q1n1-sp11-payload-smmumap-world.h answers a fault with an
 * empty address field, so its suites cannot tell a step that looks at F from one that does not; the forced answers here carry the echo. Two levels: par_page() called
 * on crafted values (by including the source, as the walk program does), and the whole step in the model, where the three places that judge a PAR (the table page's
 * write test, and the page's read and write checks after the store) are each given a faulting translation that echoes the address they ask for. Driven by
 * tools/test-q1n1-sp11-payload-smmumap-ops.py under ASan and UBSan, which also proves that a step that ignores F fails this program. Evidence: EXPERIMENTAL (host
 * model only); hardware NOT RUN. */
#include <stdio.h>
#include <string.h>

#include "sp11-smmumap.c"

#pragma clang diagnostic ignored "-Wunused-function"
#include "test-q1n1-sp11-payload-smmumap-world.h"

#define ECHO_ATTR (UINT64_C(0xFF) << 56)        /* the memory type of the ordinary memory a table page is, so that only F can refuse the echo */

static void suite_par_page(void)
{
    const uint64_t page = UINT64_C(0x15400000);
    static const unsigned fst[] = {0x04, 0x05, 0x06, 0x07, 0x0B, 0x0D, 0x0F};
    CHECK(par_page(page | UINT64_C(0xB00), page), "a translation that succeeded is not accepted");
    CHECK(!par_page(UINT64_C(0x15401B00), page), "another page is accepted");
    for (unsigned i = 0; i < sizeof fst / sizeof fst[0]; i++) {
        CHECK(!par_page(fault_par(fst[i]), page), "a faulting PAR (FST %#x) with an empty address field is accepted", fst[i]);
        CHECK(!par_page(page | fault_par(fst[i]), page), "a faulting PAR (FST %#x) whose address field echoes the page is accepted", fst[i]);
        CHECK(!par_page(ECHO_ATTR | page | UINT64_C(0xB00) | fault_par(fst[i]), page), "a faulting PAR with memory type and shareability bits and the page's address is accepted");
    }
}

/* The AT of the table page for a write is what says that the descriptor can be stored. A fault that echoes the table's address and says ordinary memory must still refuse. */
static void suite_table_page_fault_echo(void)
{
    static const unsigned fst[] = {0x0D, 0x0F, 0x07};
    for (unsigned i = 0; i < sizeof fst / sizeof fst[0]; i++) {
        NEWWORLD(w);
        force_at(&w, T_L3A, 1, 0, ECHO_ATTR | T_L3A | fault_par(fst[i]));
        GO(w, REFUSED, R(TABLE_NOT_WRITABLE), 0, "the table page's write AT faults and echoes its address: faulting PAR");
        CHECK(has_line(&w, "PAYLOAD SMMUMAP DONE MAPPED=0 STORES=0") && W(w, SLOT0) == 0, "faulting PAR echo: the step wrote, or did not say it did not: %s", last_line(&w));
    }
}

/* After the store the page must translate to itself, for a read and for a write. A fault that echoes the page and carries the template's attributes (so that nothing
 * but F is wrong) must end in the put-back, not in a mapped page. */
static void suite_page_check_fault_echo(void)
{
    const uint64_t echo = PAGE | UINT64_C(0xB00) | fault_par(7);         /* the template's own PAR is 0x70000B00: bit 11, NS and outer shareable */
    for (int write = 0; write < 2; write++) {
        NEWWORLD(w);
        force_at(&w, PAGE, write, 2, echo);
        GO(w, REFUSED, R(CHECK_FAILED), 2, write ? "after the store the write AT faults and echoes the page: faulting PAR"
                                                 : "after the store the read AT faults and echoes the page: faulting PAR");
        CHECK(W(w, SLOT0) == 0 && has_line(&w, "PAYLOAD SMMUMAP REFUSED=CHECK_FAILED UNDONE=1"), "faulting PAR echo: the descriptor was not put back: %llx", LL(W(w, SLOT0)));
    }
}

int main(void)
{
    g_suite = "par_page";
    suite_par_page();
    g_suite = "table-page";
    suite_table_page_fault_echo();
    g_suite = "page-check";
    suite_page_check_fault_echo();
    printf("%u checks, %u failures\n", g_checks, g_fail);
    return g_fail ? 1 : 0;
}
