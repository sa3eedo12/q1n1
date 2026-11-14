/* SPDX-License-Identifier: MIT */
/* The start stub of every payload (docs/SP11-PAYLOAD.md). The linker script puts .text.start first, so
 * this is offset 0 of the flat binary, which is where the runner enters: x0 = the arguments, SP = the
 * top of the payload stack, and a BLR from q1n1.
 *
 * hint #34 is BTI c: a landing pad for an indirect call on a core and a page that enforce branch target
 * identification, and a NOP everywhere else. The B is PC-relative, so the stub needs no relocation and
 * does not depend on where the firmware put the file. */
.section .text.start,"ax",%progbits
.globl _start
_start:
    hint #34
    b payload_entry
