/* SPDX-License-Identifier: MIT */
/* The payload runner's two assembly helpers (sp11-payload.h). Compiled only into the payload image
 * (Q1N1_SP11_PAYLOAD=1); with the gate at 0 this file is empty. */
#if Q1N1_SP11_PAYLOAD
#if !SNAP_PLATFORM_SP11
#error "Q1N1_SP11_PAYLOAD=1 needs SNAP_PLATFORM_SP11=1: the runner loads from the Surface Pro 11's boot stick and declares ranges to its slbounce"
#endif
.text
.p2align 4

/* uint64_t q1n1_payload_call(uint64_t entry, const void *args, uint64_t stack_top)
 *
 * Calls entry(args) with SP at stack_top and returns what it returns. q1n1's callee-saved registers
 * (and x18, the platform register, which q1n1 never uses but a payload might) are kept on q1n1's own
 * stack and q1n1's SP is kept in memory rather than in a register, so a payload that breaks AAPCS64
 * and returns with x19-x30 changed still gives control back intact. A payload that never returns, or
 * that corrupts memory, is not recovered: this is a runner, not a sandbox. */
.globl q1n1_payload_call
q1n1_payload_call:
    stp x29, x30, [sp, #-112]!
    mov x29, sp
    stp x18, x19, [sp, #16]
    stp x20, x21, [sp, #32]
    stp x22, x23, [sp, #48]
    stp x24, x25, [sp, #64]
    stp x26, x27, [sp, #80]
    str x28, [sp, #96]
    adrp x9, q1n1_payload_saved_sp
    add x9, x9, :lo12:q1n1_payload_saved_sp
    mov x10, sp
    str x10, [x9]
    and x2, x2, #0xfffffffffffffff0
    mov x16, x0
    mov x0, x1
    mov sp, x2
    blr x16
    adrp x9, q1n1_payload_saved_sp
    add x9, x9, :lo12:q1n1_payload_saved_sp
    ldr x10, [x9]
    mov sp, x10
    ldp x18, x19, [sp, #16]
    ldp x20, x21, [sp, #32]
    ldp x22, x23, [sp, #48]
    ldp x24, x25, [sp, #64]
    ldp x26, x27, [sp, #80]
    ldr x28, [sp, #96]
    ldp x29, x30, [sp], #112
    ret

/* void q1n1_payload_sync_code(uint64_t base, uint64_t bytes)
 *
 * The code was written as data (by the firmware's file read) and is about to be fetched as
 * instructions: clean the data cache to the point of unification, then invalidate the instruction
 * cache, each by virtual address, with the barriers the architecture asks for. The line sizes come from
 * CTR_EL0 (DminLine and IminLine, log2 of words), so nothing assumes a core. */
.globl q1n1_payload_sync_code
q1n1_payload_sync_code:
    mrs x9, ctr_el0
    ubfx x10, x9, #16, #4
    and x11, x9, #15
    mov x12, #4
    lsl x10, x12, x10
    lsl x11, x12, x11
    add x13, x0, x1
    sub x14, x10, #1
    bic x15, x0, x14
1:  cmp x15, x13
    b.hs 2f
    dc cvau, x15
    add x15, x15, x10
    b 1b
2:  dsb ish
    sub x14, x11, #1
    bic x15, x0, x14
3:  cmp x15, x13
    b.hs 4f
    ic ivau, x15
    add x15, x15, x11
    b 3b
4:  dsb ish
    isb
    ret

.bss
.p2align 3
q1n1_payload_saved_sp:
    .space 8
#endif /* Q1N1_SP11_PAYLOAD */
