/* SPDX-License-Identifier: MIT */
/* Payload "el1trap" (T-HW2 of the Surface Pro 11 monitor port, docs/SP11-PAYLOAD-EL1TRAP.md): are the EL1 traps the monitor relies on
 * EFFECTIVE? A tiny EL1 excursion: with CNTHCTL_EL2 set to the monitor's value (bits 14 EL1TVCT and 13 EL1TVT; the first payload,
 * cnthctl, says whether they stick), an EL1 stub reads CNTVCT_EL0, CNTV_CTL_EL0 and CNTFRQ_EL0, plus CNTPCT_EL0 as a control, and
 * returns to EL2 by HVC. Each read either TRAPS to EL2 (ESR_EL2 class 0x18) or returns its value; the payload prints which, and
 * puts everything back. It is the first payload that runs code below EL2. EXPERIMENTAL; hardware NOT RUN.
 *
 * The question behind it. A register can hold bits that do nothing: with SCR_EL3.ECVEn clear the ECV-gated fields of CNTHCTL_EL2 are
 * expected to be RES0 for what they DO while a direct read may still show them (INFERRED; the Arm ARM text was not re-read and no
 * section is quoted). Only an access made at EL1 shows whether the traps work. Expected if they do: the reads of CNTVCT_EL0 and of
 * CNTV_CTL_EL0 trap (EL1TVCT and EL1TVT, FEAT_ECV level 1), the read of CNTFRQ_EL0 does not (no bit of CNTHCTL_EL2 traps it: the
 * frequency register is always readable at EL1, and the monitor's own notes say its guest sees the host frequency), and the control, a
 * read of CNTPCT_EL0 with CNTHCTL_EL2.EL1PCTEN clear (bit 0 of the monitor's value: an Armv8.0 trap that needs no ECV), traps whatever
 * ECV does. The control separates "the ECV traps are inert" from "no trap of this setup ever reaches EL2".
 *
 * The excursion, in the order it is done (each step after the first fails closed: it ends the payload with a reason and puts back
 * what it changed):
 *   1. Context and refusals, before anything is written: not at EL2 (one line), no counter op, an image whose stub or vector tables
 *      are not 2 KiB aligned inside it, E2H set (EL1-named registers would then be EL2's: a write of SCTLR_EL1 would write SCTLR_EL2),
 *      no AArch64 EL1, DAIF not all masked, SPSel not 1 (the handler runs on the SP the payload had), CNTHCTL_EL2 with bit 12, 13 or 14
 *      already set, too little stack.
 *   2. NEXT EL1 EXCURSION AFTER 8 S and eight seconds on the runner's counter, so that a hang or a reset leaves a photographed page.
 *   3. The image is cleaned to the point of coherency (DC CIVAC) and its instruction cache lines invalidated (IC IVAU), behind DSBs
 *      and an ISB. EL1 runs with its MMU and caches off (below), so its instruction fetches see physical memory, not this core's
 *      data cache; cpuon's rule for a core that starts with the caches off, for the same reason. The identity mapping of the image
 *      (VA = PA) is OBSERVED on the unit by cpuon (its CPU_ON entry address is a pointer to its own stub).
 *   4. A probe: HVC #2 at EL2 under the payload's own vectors. HVC is enabled by SCR_EL3.HCE (INFERRED), and an UNDEFINED HVC at EL1
 *      would send the EL1 vectors (which return by HVC) into a loop nothing could end; the probe finds out first, with nothing but
 *      VBAR_EL2 changed. A failed probe ends the payload: no EL1 code runs. The handler of a probe that worked also keeps SPSR_EL2,
 *      which that exception entry filled with the caller's PSTATE: the excursion's last ERET gives five bits of it back (below).
 *   5. NEXT EL1 EXCURSION, then the writes, and no line is printed from the first write to the last read-back:
 *        VBAR_EL1  = the payload's EL1 vector table (every entry reports its number and returns by HVC #1),
 *        SCTLR_EL1 = 0x30500800: M, C, I, A, SA, SA0, WXN, EE and E0E clear (MMU and caches off, no alignment checks, little endian)
 *                    and the bits that are RES1 or "legacy" in the architecture set, as Linux's INIT_SCTLR_EL1_MMU_OFF has them
 *                    (LSMAOE, nTLSMD, EIS, TSCXT, EOS; VERIFIED against that name in Linux 7475ea8b5861, GPL-2.0-only, facts only),
 *        CNTHCTL_EL2 = (OLD & ~3) | (1 << 14) | (1 << 13), the monitor's value, ECV (bit 12) never set,
 *        HCR_EL2   = RW only (0x80000000): EL1 is AArch64; VM, TGE and E2H are clear (no stage 2, no routing of EL1 to EL2, the
 *                    non-VHE layout); IMO, FMO and AMO are clear, so that no physical interrupt is routed to EL2 while EL1 runs (and
 *                    none is taken at EL1: SPSR_EL2 masks D, A, I and F, and the runner left them pending-masked at EL2 too); HCD is
 *                    clear (HVC enabled); every trap bit is clear, so that only what CNTHCTL_EL2 traps reaches EL2.
 *      The four registers are read back; if one of the bits that matters (RW, DC, TGE, E2H, VM, HCD, IMO, FMO, AMO of HCR_EL2; M, C, I,
 *      A, WXN, EE, E0E of SCTLR_EL1; the whole of VBAR_EL1) is not as written, nothing is run: REFUSED=WRITE_NOT_HELD, and everything is
 *      put back. (DC is among them because DC set behaves as VM set, with whatever VTTBR_EL2 the firmware left.)
 *   6. el1trap_run (assembly, below): saves x19-x30, SP, SPSR_EL2, ELR_EL2 and VBAR_EL2, installs the payload's EL2 vector table
 *      before the first ERET, ERETs to the stub at EL1h with DAIF masked. Every exception to EL2 enters one handler. For each trapped
 *      MRS (class 0x18) it records ESR_EL2 and ELR_EL2, advances ELR_EL2 by 4 and returns to the stub; an HVC #0 from EL1 ends the
 *      excursion (the stub finished); an HVC #1 (an EL1 vector reported an exception) ends it with ESR_EL1, ELR_EL1 and FAR_EL1; any
 *      other entry ends it with a reason. Ending is an ERET to the code after the first ERET, at EL2h with D, A, I and F masked and
 *      with the caller's SSBS, PAN, UAO, DIT and TCO as the probe saw them (all five clear if it saw none): a C caller may rely on
 *      those, not on the flags or on the bits no payload here knows. It restores the saved registers and returns. The bound: the stub
 *      is five instructions with no branch and each EL1 vector entry is two, so EL1 can run at most five instructions between
 *      entries; the handler counts its entries in x28 and ends the excursion at the ninth, ends it
 *      if CNTPCT_EL0 passes the deadline (one second) at an entry, and after 24 entries (a handler that faults again and again)
 *      puts the saved VBAR_EL2 back and executes UDF, so that q1n1's own fault page shows it. What nothing here can bound is an
 *      instruction that never completes, or EL1 code that never reaches an entry (no timer interrupt is armed): the last line on the
 *      page, NEXT EL1 EXCURSION, names it, as for every payload.
 *   7. Everything is put back in the reverse order (HCR_EL2, CNTHCTL_EL2, SCTLR_EL1, VBAR_EL1; VBAR_EL2, SPSR_EL2 and ELR_EL2 by
 *      el1trap_run), read back, and a register that differs gets one more write. A register that still differs is NOT_RESTORED,
 *      loudly, and the payload returns 3. SPSR_EL2 and ELR_EL2 are the exception: they hold nothing at EL2 outside an exception, the
 *      next entry overwrites both, and they are neither read back nor among the five registers RESTORED=YES speaks for.
 *
 * Registers written: HCR_EL2, CNTHCTL_EL2, SCTLR_EL1, VBAR_EL1, and in el1trap_run VBAR_EL2, SPSR_EL2, ELR_EL2. Never touched:
 * CNTPOFF_EL2 (a read of it never returns on this unit), CNTVOFF_EL2, CNTKCTL_EL1, CNTHCTL_EL2.ECV, SP_EL1, the timer control
 * registers, any device. The EL1 stub reads CNTVCT_EL0, CNTV_CTL_EL0, CNTFRQ_EL0 and CNTPCT_EL0 and nothing else.
 *
 * Return value: 0 if the excursion ended at the stub's HVC and everything was put back; 2 if it did not run, or ended otherwise, and
 * everything was put back; 3 if a register could not be put back.
 *
 * Lines: at most 40 (the ABI's limit; a failure prints its raw trap records, so the host test measures the most), each at most 100
 * characters in the page font and never cut. */
#include "payload-util.h"

#define PREFIX "PAYLOAD EL1TRAP "
/* Every helper is out of line: the reviewed binary stays small and each instruction kind that matters sits in one helper. */
#define OUT_OF_LINE static __attribute__((noinline))
#define STR_(x) #x
#define STR(x) STR_(x)

/* ---- The record the EL2 handler fills ------------------------------------------------------------------------------------ */

#define TRAPS_MAX 8
#define ENTRIES_BUDGET 8            /* handler entries one excursion may have: the stub makes at most five */
#define ENTRIES_FATAL 24            /* a handler that keeps faulting: UDF under q1n1's own VBAR_EL2 */
#define EXCURSION_MAGIC UINT64_C(0x31454c5450415250)
#define MODE_EXCURSION 0u
#define MODE_PROBE 1u

/* Why an excursion ended. Macros, not an enum: the assembly stringifies them. */
#define END_NONE 0
#define END_HVC 1                   /* the stub's own HVC #0: it finished */
#define END_BUDGET 2
#define END_DEADLINE 3
#define END_VECTOR 4                /* an entry at a vector the stub cannot reach: an interrupt, an SError, a lower EL in AArch32 */
#define END_CLASS 5                 /* a synchronous entry from EL1 that is neither a trapped system register access nor an HVC */
#define END_HVC_IMM 6
#define END_EL1_EXCEPTION 7         /* an EL1 vector reported an exception by HVC #1 */
#define END_EL2_EXCEPTION 8
#define END_COUNT 9

struct trap_record {
    uint64_t esr, elr;
};

/* Written by the handler through the offsets below: the layout is part of the assembly, pinned by the static assertions. */
struct excursion {
    uint64_t magic;
    uint64_t mode;
    uint64_t deadline;          /* CNTPCT_EL0 after which an entry ends the excursion */
    uint64_t entries;
    uint64_t traps;             /* trap records stored */
    uint64_t reason;            /* END_*, 0 while it runs */
    uint64_t vector;            /* the vector of the entry that ended it, 0 to 15 */
    uint64_t end_esr, end_elr, end_far, end_spsr;
    uint64_t x[4];              /* the stub's x0 to x3 when it ended */
    uint64_t el1_esr, el1_elr, el1_far, el1_vector;     /* what an EL1 vector reported with HVC #1 */
    uint64_t probe_ok;
    uint64_t saved_vbar;        /* VBAR_EL2 as found: put back before el1trap_run returns */
    struct trap_record trap[TRAPS_MAX];
    uint64_t caller_spsr;       /* SPSR_EL2 as the probe's HVC #2 entered EL2 with it, which is the caller's PSTATE; 0 if none was taken */
};
#define E_MODE 8
#define E_DEADLINE 16
#define E_ENTRIES 24
#define E_TRAPS 32
#define E_REASON 40
#define E_VECTOR 48
#define E_END_ESR 56
#define E_END_FAR 72
#define E_X0 88
#define E_X2 104
#define E_EL1_ESR 120
#define E_EL1_FAR 136
#define E_PROBE_OK 152
#define E_SAVED_VBAR 160
#define E_TRAP0 168
#define E_CALLER_SPSR 296
_Static_assert(__builtin_offsetof(struct excursion, mode) == E_MODE && __builtin_offsetof(struct excursion, deadline) == E_DEADLINE &&
               __builtin_offsetof(struct excursion, entries) == E_ENTRIES && __builtin_offsetof(struct excursion, traps) == E_TRAPS &&
               __builtin_offsetof(struct excursion, reason) == E_REASON && __builtin_offsetof(struct excursion, vector) == E_VECTOR &&
               __builtin_offsetof(struct excursion, end_esr) == E_END_ESR && __builtin_offsetof(struct excursion, end_far) == E_END_FAR &&
               __builtin_offsetof(struct excursion, x) == E_X0 && __builtin_offsetof(struct excursion, x[2]) == E_X2 &&
               __builtin_offsetof(struct excursion, el1_esr) == E_EL1_ESR && __builtin_offsetof(struct excursion, el1_far) == E_EL1_FAR &&
               __builtin_offsetof(struct excursion, probe_ok) == E_PROBE_OK && __builtin_offsetof(struct excursion, saved_vbar) == E_SAVED_VBAR &&
               __builtin_offsetof(struct excursion, trap) == E_TRAP0 && __builtin_offsetof(struct excursion, caller_spsr) == E_CALLER_SPSR &&
               sizeof(struct excursion) == E_CALLER_SPSR + 8 && E_CALLER_SPSR == E_TRAP0 + 16 * TRAPS_MAX,
               "the handler reaches the record at these offsets");

/* What the end of an excursion returns to EL2 with: D, A, I and F masked, AArch64, EL2h (0x3c9), plus the bits of the caller's PSTATE
 * that are kept: SSBS (bit 12) and PAN, UAO, DIT and TCO (bits 22 to 25), each of which a caller may be using. As two immediates of the
 * assembly: the low halfword and the halfword of bits 16 to 31. Nothing else of the caller's PSTATE is passed on (the flags are not
 * part of a C call; a bit nothing here knows is not this payload's to set). */
#define SPSR_EL2H_MASKED 0x3c9
#define SPSR_KEPT_LOW 0x1000
#define SPSR_KEPT_HIGH 0x3c0
_Static_assert(((SPSR_KEPT_HIGH << 16) | SPSR_KEPT_LOW) == ((1 << 12) | (1 << 22) | (1 << 23) | (1 << 24) | (1 << 25)) &&
               !(((SPSR_KEPT_HIGH << 16) | SPSR_KEPT_LOW) & SPSR_EL2H_MASKED), "the kept bits are the five of the comment and none of the forced ones");

#ifdef Q1N1_PAYLOAD_HOST_TEST
/* The host test replaces what a build machine cannot run: MRS, the four MSRs, cache maintenance, ISB, the stack pointer, and the whole
 * of el1trap_run (the assembly), which it models. The image is one object so that the payload's checks on it have addresses; the test
 * adds pl_host_skew to the two tables and the stub, to hand the payload addresses that are not aligned (nothing here dereferences them). */
uint64_t pl_host_sysreg(const char *name);
void pl_host_write(const char *name, uint64_t value);
void pl_host_cache(const char *operation, uint64_t address);
uint64_t pl_host_stack_pointer(void);
uint64_t pl_host_run(struct excursion *e, uint64_t stub);
extern uint64_t pl_host_skew[3];
struct host_image {
    char vectors_el2[2048];
    char vectors_el1[2048];
    char stub[32];
};
struct host_image el1trap_host_image __attribute__((aligned(2048)));
#define SYSREG(name) pl_host_sysreg(#name)
#define EL2_VECTORS ((uintptr_t)el1trap_host_image.vectors_el2 + pl_host_skew[0])
#define EL1_VECTORS ((uintptr_t)el1trap_host_image.vectors_el1 + pl_host_skew[1])
#define EL1_STUB ((uintptr_t)el1trap_host_image.stub + pl_host_skew[2])
#define EL1_STUB_BYTES 20u
#else
#define SYSREG(name) ({ uint64_t value_; __asm__ volatile("mrs %0, " #name : "=r"(value_)); value_; })
extern const char el1trap_vectors_el2[], el1trap_vectors_el1[], el1trap_stub[], el1trap_stub_end[];
uint64_t el1trap_run(struct excursion *e, uint64_t stub);
#define EL2_VECTORS ((uintptr_t)el1trap_vectors_el2)
#define EL1_VECTORS ((uintptr_t)el1trap_vectors_el1)
#define EL1_STUB ((uintptr_t)el1trap_stub)
#define EL1_STUB_BYTES ((unsigned)(el1trap_stub_end - el1trap_stub))
#endif

/* ---- The assembly ---------------------------------------------------------------------------------------------------- */
#ifndef Q1N1_PAYLOAD_HOST_TEST
/* One vector entry, 128 bytes apart, each saying which one it was. The EL2 entries go to the one handler with the number in x15;
 * the EL1 entries report by HVC #1 with the number in x16 (neither register is one the stub uses). */
#define VECTOR_EL2(n) "    .balign 128\n    mov x15, #" #n "\n    b el1trap_el2_common\n"
#define VECTOR_EL1(n) "    .balign 128\n    mov x16, #" #n "\n    hvc #1\n"
#define FRAME_BYTES 128
#define FRAME_E 96
#define FRAME_SPSR 104          /* SPSR_EL2 here, ELR_EL2 eight bytes on */

__asm__(
    ".pushsection .text.el1trap_machine,\"ax\",%progbits\n"
    /* VBAR_ELx keeps bits 10:0 reserved: both tables are 2 KiB aligned. */
    "    .balign 2048\n"
    "    .globl el1trap_vectors_el2\n"
    "    .hidden el1trap_vectors_el2\n"
    "el1trap_vectors_el2:\n"
    VECTOR_EL2(0) VECTOR_EL2(1) VECTOR_EL2(2) VECTOR_EL2(3) VECTOR_EL2(4) VECTOR_EL2(5) VECTOR_EL2(6) VECTOR_EL2(7)
    VECTOR_EL2(8) VECTOR_EL2(9) VECTOR_EL2(10) VECTOR_EL2(11) VECTOR_EL2(12) VECTOR_EL2(13) VECTOR_EL2(14) VECTOR_EL2(15)
    "    .balign 2048\n"
    "    .globl el1trap_vectors_el1\n"
    "    .hidden el1trap_vectors_el1\n"
    "el1trap_vectors_el1:\n"
    VECTOR_EL1(0) VECTOR_EL1(1) VECTOR_EL1(2) VECTOR_EL1(3) VECTOR_EL1(4) VECTOR_EL1(5) VECTOR_EL1(6) VECTOR_EL1(7)
    VECTOR_EL1(8) VECTOR_EL1(9) VECTOR_EL1(10) VECTOR_EL1(11) VECTOR_EL1(12) VECTOR_EL1(13) VECTOR_EL1(14) VECTOR_EL1(15)
    /* The EL1 stub: position independent, no branch, no memory access, no stack. The destination registers say which read it was. */
    "    .balign 16\n"
    "    .globl el1trap_stub\n"
    "    .hidden el1trap_stub\n"
    "el1trap_stub:\n"
    "    mrs x0, cntvct_el0\n"
    "    mrs x1, cntv_ctl_el0\n"
    "    mrs x2, cntfrq_el0\n"
    "    mrs x3, cntpct_el0\n"
    "    hvc #0\n"
    "    .globl el1trap_stub_end\n"
    "    .hidden el1trap_stub_end\n"
    "el1trap_stub_end:\n"

    /* uint64_t el1trap_run(struct excursion *e, uint64_t stub), e in x0 and the stub's address in x1: the excursion, or the HVC probe
     * if e->mode says so. x27 keeps VBAR_EL2 as found and x28 counts the handler's entries: neither is touched by the stub or by
     * the EL1 vectors. */
    "    .balign 16\n"
    "    .globl el1trap_run\n"
    "    .hidden el1trap_run\n"
    "el1trap_run:\n"
    "    sub sp, sp, #" STR(FRAME_BYTES) "\n"
    "    stp x19, x20, [sp, #0]\n"
    "    stp x21, x22, [sp, #16]\n"
    "    stp x23, x24, [sp, #32]\n"
    "    stp x25, x26, [sp, #48]\n"
    "    stp x27, x28, [sp, #64]\n"
    "    stp x29, x30, [sp, #80]\n"
    "    str x0, [sp, #" STR(FRAME_E) "]\n"
    "    mrs x2, spsr_el2\n"
    "    mrs x3, elr_el2\n"
    "    stp x2, x3, [sp, #" STR(FRAME_SPSR) "]\n"
    "    mrs x27, vbar_el2\n"
    "    str x27, [x0, #" STR(E_SAVED_VBAR) "]\n"
    "    mov x28, xzr\n"
    /* The payload's vectors go in before the first ERET (or HVC), so that any exception from here is taken by the handler. */
    "    adr x2, el1trap_vectors_el2\n"
    "    msr vbar_el2, x2\n"
    "    isb\n"
    "    ldr x2, [x0, #" STR(E_MODE) "]\n"
    "    cbnz x2, el1trap_probe\n"
    "    msr elr_el2, x1\n"
    "    mov x2, #0x3c5\n"                          /* SPSR_EL2: D, A, I, F masked, AArch64, EL1h */
    "    msr spsr_el2, x2\n"
    "    eret\n"
    "el1trap_probe:\n"
    "    hvc #2\n"
    /* The handler's ERET lands here, at EL2h with DAIF masked and SP as it was: put everything back. */
    "el1trap_resume:\n"
    "    ldr x0, [sp, #" STR(FRAME_E) "]\n"
    "    ldr x2, [x0, #" STR(E_SAVED_VBAR) "]\n"
    "    msr vbar_el2, x2\n"
    "    isb\n"
    "    ldp x2, x3, [sp, #" STR(FRAME_SPSR) "]\n"
    "    msr spsr_el2, x2\n"
    "    msr elr_el2, x3\n"
    "    ldr x0, [x0, #" STR(E_REASON) "]\n"
    "    ldp x19, x20, [sp, #0]\n"
    "    ldp x21, x22, [sp, #16]\n"
    "    ldp x23, x24, [sp, #32]\n"
    "    ldp x25, x26, [sp, #48]\n"
    "    ldp x27, x28, [sp, #64]\n"
    "    ldp x29, x30, [sp, #80]\n"
    "    add sp, sp, #" STR(FRAME_BYTES) "\n"
    "    ret\n"

    /* The handler. x15 = the vector, sp = the frame of el1trap_run (SP_EL2 does not change while EL1 runs), x9 = ESR_EL2, x10 = ELR_EL2,
     * x11 = the record, x12 = the reason an end is given; x13, x14 scratch. The stub's x0 to x3 are never touched but by the stores that
     * report them, and the handler uses no stack. */
    "    .balign 16\n"
    "el1trap_el2_common:\n"
    "    add x28, x28, #1\n"
    "    cmp x28, #" STR(ENTRIES_FATAL) "\n"
    "    b.hi el1trap_fatal\n"
    "    mrs x9, esr_el2\n"
    "    mrs x10, elr_el2\n"
    "    ldr x11, [sp, #" STR(FRAME_E) "]\n"
    "    mov x12, #" STR(END_BUDGET) "\n"
    "    cmp x28, #" STR(ENTRIES_BUDGET) "\n"
    "    b.hi el1trap_end\n"
    "    mrs x13, cntpct_el0\n"
    "    ldr x14, [x11, #" STR(E_DEADLINE) "]\n"
    "    mov x12, #" STR(END_DEADLINE) "\n"
    "    cmp x13, x14\n"
    "    b.hi el1trap_end\n"
    "    ubfx x13, x9, #26, #6\n"                   /* the exception class, ESR_EL2[31:26]: ISS2 above it is RES0 here, but not assumed to read 0 */
    "    cmp x15, #4\n"
    "    b.eq el1trap_from_el2\n"
    "    mov x12, #" STR(END_VECTOR) "\n"
    "    cmp x15, #8\n"                              /* lower EL, AArch64, synchronous: the only entry an EL1 stub makes */
    "    b.ne el1trap_end\n"
    "    cmp x13, #0x18\n"                           /* a trapped MSR, MRS or system instruction */
    "    b.eq el1trap_trapped\n"
    "    cmp x13, #0x16\n"                           /* HVC from AArch64 */
    "    b.eq el1trap_hvc\n"
    "    mov x12, #" STR(END_CLASS) "\n"
    "    b el1trap_end\n"
    /* Vector 4: the probe's HVC #2, or any exception of EL2 itself. */
    "el1trap_from_el2:\n"
    "    mov x12, #" STR(END_EL2_EXCEPTION) "\n"
    "    cmp x13, #0x16\n"
    "    b.ne el1trap_end\n"
    "    and x14, x9, #0xffff\n"
    "    cmp x14, #2\n"
    "    b.ne el1trap_end\n"
    "    mov x14, #1\n"
    "    str x14, [x11, #" STR(E_PROBE_OK) "]\n"
    "    mrs x14, spsr_el2\n"                        /* this entry saved the caller's PSTATE here; the end of an excursion gives five bits back */
    "    str x14, [x11, #" STR(E_CALLER_SPSR) "]\n"
    "    eret\n"                                     /* to the instruction after the HVC, as it was */
    /* A trapped read: record ESR_EL2 and ELR_EL2, skip the instruction, go on. */
    "el1trap_trapped:\n"
    "    ldr x14, [x11, #" STR(E_TRAPS) "]\n"
    "    mov x12, #" STR(END_BUDGET) "\n"
    "    cmp x14, #" STR(TRAPS_MAX) "\n"
    "    b.hs el1trap_end\n"
    "    add x13, x11, #" STR(E_TRAP0) "\n"
    "    add x13, x13, x14, lsl #4\n"
    "    stp x9, x10, [x13]\n"
    "    add x14, x14, #1\n"
    "    str x14, [x11, #" STR(E_TRAPS) "]\n"
    "    add x10, x10, #4\n"
    "    msr elr_el2, x10\n"
    "    eret\n"
    /* HVC from EL1: #0 is the stub finishing, #1 an EL1 vector reporting an exception (x16 = its number), another is an end. */
    "el1trap_hvc:\n"
    "    and x14, x9, #0xffff\n"
    "    mov x12, #" STR(END_HVC) "\n"
    "    cbz x14, el1trap_end\n"
    "    mov x12, #" STR(END_HVC_IMM) "\n"
    "    cmp x14, #1\n"
    "    b.ne el1trap_end\n"
    "    mrs x13, esr_el1\n"
    "    mrs x14, elr_el1\n"
    "    stp x13, x14, [x11, #" STR(E_EL1_ESR) "]\n"
    "    mrs x13, far_el1\n"
    "    stp x13, x16, [x11, #" STR(E_EL1_FAR) "]\n"
    "    mov x12, #" STR(END_EL1_EXCEPTION) "\n"
    /* The end: x12 is the reason. Report it and what the stub held, then ERET to el1trap_resume at EL2h. */
    "el1trap_end:\n"
    "    str x12, [x11, #" STR(E_REASON) "]\n"
    "    str x28, [x11, #" STR(E_ENTRIES) "]\n"
    "    str x15, [x11, #" STR(E_VECTOR) "]\n"
    "    stp x9, x10, [x11, #" STR(E_END_ESR) "]\n"
    "    mrs x13, far_el2\n"
    "    mrs x14, spsr_el2\n"
    "    stp x13, x14, [x11, #" STR(E_END_FAR) "]\n"
    "    stp x0, x1, [x11, #" STR(E_X0) "]\n"
    "    stp x2, x3, [x11, #" STR(E_X2) "]\n"
    "    adr x13, el1trap_resume\n"
    "    msr elr_el2, x13\n"
    /* SPSR_EL2 for the return to EL2h: the five bits of the caller's PSTATE the probe saw (0 if it saw none), then D, A, I, F masked,
     * AArch64, EL2h. x0 to x3 have been reported and are free; the handler uses x13 and x14 as scratch. */
    "    ldr x13, [x11, #" STR(E_CALLER_SPSR) "]\n"
    "    mov x14, #" STR(SPSR_KEPT_LOW) "\n"
    "    movk x14, #" STR(SPSR_KEPT_HIGH) ", lsl #16\n"
    "    and x13, x13, x14\n"
    "    mov x14, #" STR(SPSR_EL2H_MASKED) "\n"
    "    orr x13, x13, x14\n"
    "    msr spsr_el2, x13\n"
    "    eret\n"
    /* Too many entries: the handler itself is failing. Put the VBAR_EL2 found back and fault under it, so that q1n1's page shows it. */
    "el1trap_fatal:\n"
    "    msr vbar_el2, x27\n"
    "    isb\n"
    "    udf #0\n"
    ".popsection\n");
#endif /* !Q1N1_PAYLOAD_HOST_TEST */

/* ---- The registers --------------------------------------------------------------------------------------------------- */

/* What the excursion writes (docs/SP11-PAYLOAD-EL1TRAP.md has the table). */
#define HCR_EXCURSION (UINT64_C(1) << 31)
#define HCR_BITS_CHECKED ((UINT64_C(1) << 31) | (UINT64_C(1) << 34) | (UINT64_C(1) << 27) | (UINT64_C(1) << 29) | UINT64_C(1) | \
                          (UINT64_C(1) << 12) | (UINT64_C(7) << 3))        /* RW, E2H, TGE, HCD, VM, DC, FMO, IMO, AMO */
#define SCTLR_EL1_EXCURSION UINT64_C(0x30500800)
#define SCTLR_EL1_BITS_CHECKED (UINT64_C(0x1) | UINT64_C(0x2) | UINT64_C(0x4) | UINT64_C(0x1000) | UINT64_C(0x80000) | UINT64_C(0x1000000) | \
                                UINT64_C(0x2000000))  /* M, A, C, I, WXN, E0E, EE */
#define EL1_PHYSICAL_BITS UINT64_C(3)
#define ECV_BIT (UINT64_C(1) << 12)
#define EL1TVT_BIT (UINT64_C(1) << 13)
#define EL1TVCT_BIT (UINT64_C(1) << 14)
#define OLD_REFUSED_BITS (ECV_BIT | EL1TVT_BIT | EL1TVCT_BIT)
#define DAIF_MASKED UINT64_C(0x3c0)
#define WAIT_BEFORE_EXCURSION_S 8u
#define DEADLINE_S 1u
#define COUNTER_HZ_DEFAULT 19200000u
#define COUNTER_HZ_MIN 1000000u
#define COUNTER_HZ_MAX 1000000000u
#define COUNTER_STUCK_READS 2000000u
#define STACK_KEPT_BYTES (16u * 1024u)
#define RET_NOT_RESTORED 3u
#define RET_NOT_OK 2u

enum { R_HCR, R_CNTHCTL, R_SCTLR, R_VBAR1, R_VBAR2, R_COUNT };
static const char register_name[R_COUNT][12] = {"HCR_EL2", "CNTHCTL_EL2", "SCTLR_EL1", "VBAR_EL1", "VBAR_EL2"};

OUT_OF_LINE void write_hcr_el2(uint64_t value)
{
#ifdef Q1N1_PAYLOAD_HOST_TEST
    pl_host_write("HCR_EL2", value);
#else
    __asm__ volatile("msr hcr_el2, %0" : : "r"(value) : "memory");
#endif
}

OUT_OF_LINE void write_cnthctl_el2(uint64_t value)
{
#ifdef Q1N1_PAYLOAD_HOST_TEST
    pl_host_write("CNTHCTL_EL2", value);
#else
    __asm__ volatile("msr cnthctl_el2, %0" : : "r"(value) : "memory");
#endif
}

OUT_OF_LINE void write_sctlr_el1(uint64_t value)
{
#ifdef Q1N1_PAYLOAD_HOST_TEST
    pl_host_write("SCTLR_EL1", value);
#else
    __asm__ volatile("msr sctlr_el1, %0" : : "r"(value) : "memory");
#endif
}

OUT_OF_LINE void write_vbar_el1(uint64_t value)
{
#ifdef Q1N1_PAYLOAD_HOST_TEST
    pl_host_write("VBAR_EL1", value);
#else
    __asm__ volatile("msr vbar_el1, %0" : : "r"(value) : "memory");
#endif
}

/* The one write of VBAR_EL2 the C code has: the retry for a restore that did not hold. el1trap_run puts it back itself. */
OUT_OF_LINE void write_vbar_el2(uint64_t value)
{
#ifdef Q1N1_PAYLOAD_HOST_TEST
    pl_host_write("VBAR_EL2", value);
#else
    __asm__ volatile("msr vbar_el2, %0" : : "r"(value) : "memory");
#endif
}

OUT_OF_LINE void write_register(unsigned which, uint64_t value)
{
    switch (which) {
    case R_HCR: write_hcr_el2(value); break;
    case R_CNTHCTL: write_cnthctl_el2(value); break;
    case R_SCTLR: write_sctlr_el1(value); break;
    case R_VBAR1: write_vbar_el1(value); break;
    default: write_vbar_el2(value); break;
    }
}

OUT_OF_LINE uint64_t read_register(unsigned which)
{
    switch (which) {
    case R_HCR: return SYSREG(hcr_el2);
    case R_CNTHCTL: return SYSREG(cnthctl_el2);
    case R_SCTLR: return SYSREG(sctlr_el1);
    case R_VBAR1: return SYSREG(vbar_el1);
    default: return SYSREG(vbar_el2);
    }
}

OUT_OF_LINE void isb(void)
{
#ifdef Q1N1_PAYLOAD_HOST_TEST
    pl_host_cache("isb", 0);
#else
    __asm__ volatile("isb" : : : "memory");
#endif
}

OUT_OF_LINE void dsb_sy(void)
{
#ifdef Q1N1_PAYLOAD_HOST_TEST
    pl_host_cache("dsb", 0);
#else
    __asm__ volatile("dsb sy" : : : "memory");
#endif
}

OUT_OF_LINE void dc_civac(uint64_t address)
{
#ifdef Q1N1_PAYLOAD_HOST_TEST
    pl_host_cache("civac", address);
#else
    __asm__ volatile("dc civac, %0" : : "r"(address) : "memory");
#endif
}

OUT_OF_LINE void ic_ivau(uint64_t address)
{
#ifdef Q1N1_PAYLOAD_HOST_TEST
    pl_host_cache("ivau", address);
#else
    __asm__ volatile("ic ivau, %0" : : "r"(address) : "memory");
#endif
}

OUT_OF_LINE uint64_t stack_pointer(void)
{
#ifdef Q1N1_PAYLOAD_HOST_TEST
    return pl_host_stack_pointer();
#else
    uint64_t sp;
    __asm__ volatile("mov %0, sp" : "=r"(sp));
    return sp;
#endif
}

#ifdef Q1N1_PAYLOAD_HOST_TEST
#define RUN(e, stub) pl_host_run(e, stub)
#else
#define RUN(e, stub) el1trap_run(e, stub)
#endif

/* 16 bytes is the smallest cache line the architecture allows, so a step of 16 reaches every line whatever the unit's line size is. */
#define CACHE_STEP 16u

/* The image is made visible to a core that fetches without its caches, and its instruction cache lines are dropped. */
OUT_OF_LINE void make_image_visible(uint64_t start, uint64_t bytes)
{
    for (uint64_t at = start & ~(uint64_t)(CACHE_STEP - 1); at < start + bytes; at += CACHE_STEP) dc_civac(at);
    dsb_sy();
    for (uint64_t at = start & ~(uint64_t)(CACHE_STEP - 1); at < start + bytes; at += CACHE_STEP) ic_ivau(at);
    dsb_sy();
    isb();
}

/* ---- Output ---------------------------------------------------------------------------------------------------------- */

struct out {
    const struct q1n1_payload_args *a;
    unsigned used;
};

/* PAYLOAD EL1TRAP <text> */
OUT_OF_LINE void say(struct out *o, const char *text)
{
    struct pl_line line;
    pl_begin(&line);
    pl_text(&line, PREFIX);
    pl_text(&line, text);
    o->used++;
    pl_emit(o->a, &line);
}

OUT_OF_LINE void row(struct pl_line *line)
{
    pl_begin(line);
    pl_text(line, PREFIX);
}

/* ` KEY=0XVALUE` appended to a line, the first one without the space. */
OUT_OF_LINE void field(const struct q1n1_payload_args *a, struct pl_line *line, const char *key, uint64_t value)
{
    if (line->len > sizeof PREFIX - 1) pl_text(line, " ");
    pl_text(line, key);
    pl_text(line, "=");
    pl_hex(a, line, value);
}

OUT_OF_LINE void word(struct pl_line *line, const char *text)
{
    if (line->len > sizeof PREFIX - 1) pl_text(line, " ");
    pl_text(line, text);
}

OUT_OF_LINE void emit(struct out *o, const struct pl_line *line)
{
    o->used++;
    pl_emit(o->a, line);
}

/* ---- The wait -------------------------------------------------------------------------------------------------------- */

/* Waits `seconds` on the runner's counter at `hz` ticks a second; 0 if the counter does not run or runs backwards (a read below the
 * first would make now - start huge and end the wait at once: the photograph window is not given up for a counter that lies). */
OUT_OF_LINE int wait_seconds(const struct q1n1_payload_args *a, uint64_t hz, unsigned seconds)
{
    uint64_t start = a->ops.counter(), last = start;
    uint32_t same = 0;
    for (;;) {
        uint64_t now = a->ops.counter();
        if (now < start) return 0;
        if (now - start >= hz * seconds) return 1;
        if (now == last) {
            if (++same >= COUNTER_STUCK_READS) return 0;
        } else {
            last = now;
            same = 0;
        }
    }
}

/* ---- The run --------------------------------------------------------------------------------------------------------- */

struct run {
    const struct q1n1_payload_args *a;
    struct out out;
    uint64_t hz;
    uint64_t saved[R_COUNT];        /* HCR_EL2, CNTHCTL_EL2, SCTLR_EL1, VBAR_EL1 and VBAR_EL2 as found */
    uint64_t wanted[R_COUNT - 1];   /* what the excursion writes to the first four */
};

struct window {
    struct excursion probe, e;
    uint64_t readback[R_COUNT - 1];     /* after the writes */
    uint64_t restored[R_COUNT];         /* after the put-back, and the retry */
    uint32_t held;                      /* the writes were as written where it matters: the excursion ran */
    uint32_t ran;
    uint32_t retried;                   /* bit per register that needed the one more write */
    uint32_t probe_done;
};

OUT_OF_LINE void clear_bytes(void *start, unsigned bytes)
{
    for (unsigned i = 0; i < bytes; i++) ((volatile uint8_t *)start)[i] = 0;
}

OUT_OF_LINE void prepare(const struct run *r, struct excursion *e, uint64_t mode)
{
    clear_bytes(e, sizeof *e);
    e->magic = EXCURSION_MAGIC;
    e->mode = mode;
    e->deadline = r->a->ops.counter() + r->hz * DEADLINE_S;
}

/* Whether the bits of the four registers that decide whether EL1 can be entered and left are as written. */
OUT_OF_LINE int writes_held(const struct run *r, const uint64_t readback[R_COUNT - 1])
{
    return (readback[R_HCR] & HCR_BITS_CHECKED) == (r->wanted[R_HCR] & HCR_BITS_CHECKED) &&
           (readback[R_SCTLR] & SCTLR_EL1_BITS_CHECKED) == (r->wanted[R_SCTLR] & SCTLR_EL1_BITS_CHECKED) &&
           readback[R_VBAR1] == r->wanted[R_VBAR1] && !(readback[R_CNTHCTL] & ECV_BIT);
}

/* The whole window in which anything but the payload's own VBAR_EL2 differs from what was found: no line is printed inside it. */
OUT_OF_LINE void excursion_window(const struct run *r, struct window *w)
{
    write_vbar_el1(r->wanted[R_VBAR1]);
    write_sctlr_el1(r->wanted[R_SCTLR]);
    write_cnthctl_el2(r->wanted[R_CNTHCTL]);
    write_hcr_el2(r->wanted[R_HCR]);
    isb();
    for (unsigned i = 0; i < R_VBAR2; i++) w->readback[i] = read_register(i);
    w->held = (uint32_t)writes_held(r, w->readback);
    if (w->held) {
        prepare(r, &w->e, MODE_EXCURSION);
        w->e.caller_spsr = w->probe.caller_spsr;        /* what the probe's HVC #2 saw of the caller: the last ERET returns five bits of it */
        RUN(&w->e, EL1_STUB);
        w->ran = 1;
    }
    for (unsigned i = 0; i <= R_VBAR1; i++) write_register(i, r->saved[i]);    /* HCR_EL2 first: the reverse of the order it was set in */
    isb();
    for (unsigned i = 0; i < R_COUNT; i++) w->restored[i] = read_register(i);
    for (unsigned i = 0; i < R_COUNT; i++) {
        if (w->restored[i] == r->saved[i]) continue;
        write_register(i, r->saved[i]);
        isb();
        w->restored[i] = read_register(i);
        w->retried |= 1u << i;
    }
}

/* ---- Reporting ------------------------------------------------------------------------------------------------------- */

static const char reason_name[END_COUNT][20] = {
    "NONE", "OK", "BUDGET", "DEADLINE", "UNEXPECTED_VECTOR", "UNEXPECTED_CLASS", "UNEXPECTED_HVC_IMM", "EL1_EXCEPTION", "EL2_EXCEPTION",
};
/* The four reads of the stub, in its order: the name, then op0, op1, CRn, CRm, op2 of the register, which are the fields of the ISS of
 * a trapped MRS. The first two are the ECV traps, the third is never trapped, the last is the control. */
static const char access_name[4][13] = {"CNTVCT_EL0", "CNTV_CTL_EL0", "CNTFRQ_EL0", "CNTPCT_EL0"};
static const uint8_t access_encoding[4][5] = {{3, 3, 14, 0, 2}, {3, 3, 14, 3, 1}, {3, 3, 14, 0, 0}, {3, 3, 14, 0, 1}};
#define ACCESS_VCT 0u
#define ACCESS_VTIMER 1u
#define ACCESS_FRQ 2u
#define ACCESS_CONTROL 3u
#define EC_TRAPPED_SYSREG 0x18u
#define ISS_MASK 0x1ffffffu

/* The ISS of a trapped MRS of access i into x<i>: Op0, Op2, Op1, CRn, Rt, CRm, and Direction 1 (a read). */
OUT_OF_LINE uint64_t expected_iss(unsigned i)
{
    const uint8_t *e = access_encoding[i];
    return ((uint64_t)e[0] << 20) | ((uint64_t)e[4] << 17) | ((uint64_t)e[1] << 14) | ((uint64_t)e[2] << 10) | ((uint64_t)i << 5) |
           ((uint64_t)e[3] << 1) | 1u;
}

/* The trap record for the instruction of access i, or NULL: the one whose ELR_EL2 is that instruction. */
OUT_OF_LINE const struct trap_record *trap_of(const struct excursion *e, unsigned i)
{
    uint64_t at = EL1_STUB + 4u * i;
    for (unsigned k = 0; k < e->traps && k < TRAPS_MAX; k++)
        if (e->trap[k].elr == at) return &e->trap[k];
    return 0;
}

OUT_OF_LINE void report_accesses(struct run *r, const struct excursion *e, const uint64_t readback_cnthctl)
{
    struct pl_line line;
    unsigned trapped[4] = {0, 0, 0, 0};
    for (unsigned i = 0; i < 4; i++) {
        const struct trap_record *t = trap_of(e, i);
        row(&line);
        word(&line, access_name[i]);
        if (i == ACCESS_CONTROL) word(&line, "CONTROL");
        if (t) {
            trapped[i] = 1;
            word(&line, "TRAPPED");
            field(r->a, &line, "EC", t->esr >> 26 & 63);
            field(r->a, &line, "ISS", t->esr & ISS_MASK);
            word(&line, (t->esr >> 26 & 63) == EC_TRAPPED_SYSREG && (t->esr & ISS_MASK) == expected_iss(i) ? "ISS_OK=YES" : "ISS_OK=NO");
        } else {
            word(&line, "NOT_TRAPPED");
            field(r->a, &line, "VALUE", e->x[i]);
        }
        emit(&r->out, &line);
    }
    {
        unsigned bits = (unsigned)(readback_cnthctl >> 13 & 1) + (unsigned)(readback_cnthctl >> 14 & 1);
        const char *verdict = !trapped[ACCESS_CONTROL] ? "CONTROL_NOT_TRAPPED"
                              : trapped[ACCESS_VCT] && trapped[ACCESS_VTIMER] ? "TRAPS_EFFECTIVE"
                              : !trapped[ACCESS_VCT] && !trapped[ACCESS_VTIMER] ? "TRAPS_INERT" : "TRAPS_PARTIAL";
        row(&line);
        pl_text(&line, "VERDICT=");
        pl_text(&line, verdict);
        word(&line, bits == 2 ? "BITS13_14_IN_READBACK=YES" : bits == 0 ? "BITS13_14_IN_READBACK=NO" : "BITS13_14_IN_READBACK=PARTIAL");
        if (trapped[ACCESS_FRQ]) word(&line, "CNTFRQ_EL0_TRAPPED");
        emit(&r->out, &line);
    }
}

OUT_OF_LINE void report_end(struct run *r, const struct excursion *e)
{
    struct pl_line line;
    row(&line);
    word(&line, "EXCURSION");
    word(&line, e->reason < END_COUNT ? reason_name[e->reason] : "UNKNOWN_REASON");
    field(r->a, &line, "ENTRIES", e->entries);
    field(r->a, &line, "TRAPS", e->traps);
    field(r->a, &line, "VECTOR", e->vector);
    emit(&r->out, &line);
    row(&line);
    field(r->a, &line, "ESR_EL2", e->end_esr);
    field(r->a, &line, "ELR_EL2", e->end_elr);
    emit(&r->out, &line);
    row(&line);
    field(r->a, &line, "FAR_EL2", e->end_far);
    field(r->a, &line, "SPSR_EL2", e->end_spsr);
    emit(&r->out, &line);
    if (e->reason == END_EL1_EXCEPTION) {
        row(&line);
        field(r->a, &line, "ESR_EL1", e->el1_esr);
        field(r->a, &line, "ELR_EL1", e->el1_elr);
        emit(&r->out, &line);
        row(&line);
        field(r->a, &line, "FAR_EL1", e->el1_far);
        field(r->a, &line, "EL1_VECTOR", e->el1_vector);
        emit(&r->out, &line);
    }
    for (unsigned k = 0; k < e->traps && k < TRAPS_MAX; k++) {
        row(&line);
        word(&line, "TRAP");
        field(r->a, &line, "ESR_EL2", e->trap[k].esr);
        field(r->a, &line, "ELR_EL2", e->trap[k].elr);
        emit(&r->out, &line);
    }
    say(&r->out, "ACCESSES_NOT_CLASSIFIED");
}

OUT_OF_LINE void report_registers(struct run *r, const char *label, uint64_t first, uint64_t second, const char *first_name, const char *second_name)
{
    struct pl_line line;
    row(&line);
    word(&line, label);
    field(r->a, &line, first_name, first);
    field(r->a, &line, second_name, second);
    emit(&r->out, &line);
}

/* RESTORED=YES, or what differs, loudly. Returns 1 when every register is as found. */
OUT_OF_LINE int report_restore(struct run *r, const struct window *w)
{
    struct pl_line line;
    unsigned bad = 0;
    for (unsigned i = 0; i < R_COUNT; i++) bad += w->restored[i] != r->saved[i];
    for (unsigned i = 0; i < R_COUNT; i++) {
        if (!(w->retried >> i & 1)) continue;
        row(&line);
        word(&line, "RESTORE_RETRY");
        word(&line, register_name[i]);
        field(r->a, &line, "NOW", w->restored[i]);
        emit(&r->out, &line);
    }
    if (!bad) {
        say(&r->out, "RESTORED=YES");
        return 1;
    }
    say(&r->out, "RESTORED=NO");
    for (unsigned i = 0; i < R_COUNT; i++) {
        if (w->restored[i] == r->saved[i]) continue;
        row(&line);
        word(&line, "NOT_RESTORED");
        word(&line, register_name[i]);
        field(r->a, &line, "WANT", r->saved[i]);
        field(r->a, &line, "NOW", w->restored[i]);
        emit(&r->out, &line);
    }
    say(&r->out, "POWER_CYCLE_BEFORE_ANY_OTHER_PAYLOAD");
    return 0;
}

/* The refusals that come before anything is written, in order; NULL if there is none. */
OUT_OF_LINE const char *refusal_of(const struct run *r, uint64_t hcr, uint64_t pfr0, uint64_t daif, uint64_t spsel, uint64_t cnthctl)
{
    uint64_t sp = stack_pointer();
    if (hcr >> 34 & 1) return "REFUSED=E2H";
    if ((pfr0 >> 4 & 15) == 0) return "REFUSED=NO_EL1_AARCH64";
    if ((daif & DAIF_MASKED) != DAIF_MASKED) return "REFUSED=DAIF_NOT_MASKED";
    if (!(spsel & 1)) return "REFUSED=SPSEL_NOT_EL2H";
    if (cnthctl & OLD_REFUSED_BITS) return "REFUSED=OLD_HAS_BITS_12_TO_14";
    if (sp < r->a->stack_base + STACK_KEPT_BYTES || sp > r->a->stack_base + r->a->stack_size) return "REFUSED=STACK";
    return 0;
}

/* Whether the stub, the two tables and the frame they need are inside the image and aligned as VBAR_ELx and an instruction need. */
OUT_OF_LINE int layout_ok(const struct q1n1_payload_args *a)
{
    uint64_t base = a->payload_base, end = base + a->payload_size;
    uint64_t el2 = EL2_VECTORS, el1 = EL1_VECTORS, stub = EL1_STUB;
    if (a->payload_size >= (UINT64_C(1) << 32) || end < base) return 0;
    if ((el2 & 2047) || (el1 & 2047) || (stub & 3)) return 0;
    if (el2 < base || el2 + 2048 > end || el1 < base || el1 + 2048 > end || stub < base || stub + EL1_STUB_BYTES > end) return 0;
    return EL1_STUB_BYTES == 20;
}

uint64_t payload_entry(const struct q1n1_payload_args *a);
uint64_t payload_entry(const struct q1n1_payload_args *a)
{
    struct run r;
    struct window w;
    struct pl_line line;
    uint64_t current_el, mmfr0, pfr0, cntfrq, daif, spsel, hcr, cnthctl;
    const char *refusal;
    if (!pl_args_ok(a)) return Q1N1_PAYLOAD_RET_BAD_ARGS;
    r.a = r.out.a = a;
    r.out.used = 0;
    current_el = SYSREG(CurrentEL);
    if ((current_el >> 2 & 3) != 2) {
        say(&r.out, "SKIPPED_NOT_AT_EL2");
        return 0;
    }
    if (!a->ops.counter) {
        say(&r.out, "REFUSED=NO_COUNTER");
        return 0;
    }

    hcr = SYSREG(hcr_el2);
    daif = SYSREG(daif);
    spsel = SYSREG(SPSel);
    cntfrq = SYSREG(cntfrq_el0);
    mmfr0 = SYSREG(id_aa64mmfr0_el1);
    pfr0 = SYSREG(id_aa64pfr0_el1);
    for (unsigned i = 0; i < R_COUNT; i++) r.saved[i] = read_register(i);
    cnthctl = r.saved[R_CNTHCTL];
    r.hz = cntfrq >= COUNTER_HZ_MIN && cntfrq <= COUNTER_HZ_MAX ? cntfrq : COUNTER_HZ_DEFAULT;

    row(&line);
    field(a, &line, "CURRENTEL", current_el);
    field(a, &line, "HCR_EL2", hcr);
    field(a, &line, "E2H", hcr >> 34 & 1);
    emit(&r.out, &line);
    row(&line);
    field(a, &line, "DAIF", daif);
    field(a, &line, "SPSEL", spsel);
    field(a, &line, "CNTFRQ_EL0", cntfrq);
    if (r.hz != cntfrq) word(&line, "FREQ=DEFAULT");
    emit(&r.out, &line);
    row(&line);
    field(a, &line, "ID_AA64MMFR0_EL1", mmfr0);
    field(a, &line, "ECV", mmfr0 >> 60 & 15);
    emit(&r.out, &line);
    row(&line);
    field(a, &line, "ID_AA64PFR0_EL1", pfr0);
    field(a, &line, "EL1", pfr0 >> 4 & 15);
    emit(&r.out, &line);
    report_registers(&r, "OLD", cnthctl, r.saved[R_SCTLR], "CNTHCTL_EL2", "SCTLR_EL1");
    report_registers(&r, "OLD", r.saved[R_VBAR1], r.saved[R_VBAR2], "VBAR_EL1", "VBAR_EL2");
    if (!layout_ok(a)) {
        say(&r.out, "REFUSED=ENTRY");
        return 0;
    }
    row(&line);
    field(a, &line, "STUB_OFFSET", EL1_STUB - a->payload_base);
    field(a, &line, "EL1_VECTORS_OFFSET", EL1_VECTORS - a->payload_base);
    field(a, &line, "EL2_VECTORS_OFFSET", EL2_VECTORS - a->payload_base);
    emit(&r.out, &line);
    if ((refusal = refusal_of(&r, hcr, pfr0, daif, spsel, cnthctl))) {
        say(&r.out, refusal);
        return 0;
    }

    r.wanted[R_HCR] = HCR_EXCURSION;
    r.wanted[R_CNTHCTL] = (cnthctl & ~EL1_PHYSICAL_BITS) | EL1TVCT_BIT | EL1TVT_BIT;
    r.wanted[R_SCTLR] = SCTLR_EL1_EXCURSION;
    r.wanted[R_VBAR1] = EL1_VECTORS;
    say(&r.out, "NEXT EL1 EXCURSION AFTER 8 S");
    if (!wait_seconds(a, r.hz, WAIT_BEFORE_EXCURSION_S)) {
        say(&r.out, "REFUSED=COUNTER_STUCK");
        return 0;
    }

    clear_bytes(&w, sizeof w);
    make_image_visible(a->payload_base, a->payload_size);
    prepare(&r, &w.probe, MODE_PROBE);
    RUN(&w.probe, EL1_STUB);
    w.probe_done = 1;
    w.restored[R_VBAR2] = read_register(R_VBAR2);
    if (w.restored[R_VBAR2] != r.saved[R_VBAR2]) {      /* el1trap_run puts it back; one more write if that did not hold */
        write_register(R_VBAR2, r.saved[R_VBAR2]);
        isb();
        w.restored[R_VBAR2] = read_register(R_VBAR2);
        w.retried |= 1u << R_VBAR2;
    }
    if (!w.probe.probe_ok || w.probe.reason || w.restored[R_VBAR2] != r.saved[R_VBAR2]) {
        row(&line);
        word(&line, "HVC_AT_EL2=FAILED");
        word(&line, w.probe.reason < END_COUNT ? reason_name[w.probe.reason] : "UNKNOWN_REASON");
        field(a, &line, "ENTRIES", w.probe.entries);
        field(a, &line, "VECTOR", w.probe.vector);
        emit(&r.out, &line);
        report_registers(&r, "HVC_AT_EL2", w.probe.end_esr, w.probe.end_elr, "ESR_EL2", "ELR_EL2");
        say(&r.out, "REFUSED=HVC_AT_EL2");
        for (unsigned i = 0; i < R_VBAR2; i++) w.restored[i] = r.saved[i];     /* nothing but VBAR_EL2 was ever changed */
        if (!report_restore(&r, &w)) return RET_NOT_RESTORED;
        return RET_NOT_OK;
    }
    say(&r.out, "HVC_AT_EL2=OK");
    row(&line);
    word(&line, "WRITES");
    field(a, &line, "HCR_EL2", r.wanted[R_HCR]);
    field(a, &line, "CNTHCTL_EL2", r.wanted[R_CNTHCTL]);
    field(a, &line, "SCTLR_EL1", r.wanted[R_SCTLR]);
    emit(&r.out, &line);
    say(&r.out, "NEXT EL1 EXCURSION");

    excursion_window(&r, &w);

    report_registers(&r, "READBACK", w.readback[R_HCR], w.readback[R_CNTHCTL], "HCR_EL2", "CNTHCTL_EL2");
    /* VBAR_EL1 as an offset from the image: an address would differ from run to run, and the runner prints the base. */
    report_registers(&r, "READBACK", w.readback[R_SCTLR], w.readback[R_VBAR1] - a->payload_base, "SCTLR_EL1", "VBAR_EL1_OFFSET");
    if (!w.held) {
        say(&r.out, "REFUSED=WRITE_NOT_HELD");
    } else if (w.e.reason == END_HVC) {
        report_accesses(&r, &w.e, w.readback[R_CNTHCTL]);
        row(&line);
        word(&line, "EXCURSION OK");
        field(a, &line, "ENTRIES", w.e.entries);
        field(a, &line, "TRAPS", w.e.traps);
        emit(&r.out, &line);
    } else {
        report_end(&r, &w.e);
    }
    if (!report_restore(&r, &w)) return RET_NOT_RESTORED;
    return w.held && w.e.reason == END_HVC ? 0 : RET_NOT_OK;
}
