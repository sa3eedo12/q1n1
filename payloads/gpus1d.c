/* SPDX-License-Identifier: MIT */
/* Payload "gpus1d": the dry run of gpus1 (payloads/gpus1.c). The same code over the table with no write (payloads/gpus1d.wtab.json): the four checks of step 0 and the CX
 * GDSC found-check, each with a settle and a read-back of its own word, the three snapshots, and the runner's whole open, row, unwind and END flow, with nothing stored to any
 * device word. It is the first run of the framework on the unit, and it answers whether the register path the table assumes (the GCC AHB branch, the GPUCC roots, the CX GDSC
 * word) reads as boot 30 read it, and what mapping attribute the runner reports for the page of each word (the WTAB ATTR lines, the CXGDSC one above all). */
#define GPUS1_DRY 1
#include "gpus1.c"
