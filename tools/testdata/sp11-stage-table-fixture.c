/* SPDX-License-Identifier: MIT */
/* TEST FIXTURE ONLY. Not a Surface Pro 11 fact and not generated from any descriptor: the addresses are invented,
 * chosen so that they are nobody's hardware and are not the A16's own stage_candidates[] (main.c, 0xb0000000/
 * 0x4c000000/0xa0000000). tools/test-q1n1-sp11-entry.py uses it to prove that the SP11=1 build wiring
 * (platform/uefi/Makefile) compiles and links. No generator exists yet for a real one (docs/SP11-Q1N1-BOOT-STUDY.md
 * section 12 item 3; this patch's REPORT.md records it as an open question, same as sp11-usb-table-fixture.c's own
 * precedent for the USB table before Snapintosh's tools/sp11_usb_ports.py existed). */
#include "sp11-stage-table.h"

static const struct q1n1_sp11_stage_table table = {
    .magic = Q1N1_SP11_STAGE_MAGIC, .version = Q1N1_SP11_STAGE_VERSION, .count = 2,
    .candidate = {UINT64_C(0x90000000), UINT64_C(0x94000000)}};

const struct q1n1_sp11_stage_table *q1n1_sp11_stage_table_get(void) { return &table; }
