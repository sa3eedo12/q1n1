/* SPDX-License-Identifier: MIT */
/* The instructions behind q1n1_smmumap_env (sp11-smmumap.h): the five translation registers, AT S1E2R and AT S1E2W with
 * their ISB and the read of PAR_EL1, DC CVAC, DSB ISH, TLBI VALE2IS, ISB, and the read of ISR_EL1. EL2 only; the runner calls it
 * only after the bounce, at EL2. Kept apart from the logic so that the native tests, which have no EL2, build the logic alone.
 * Nothing here stores: the one store is the caller's guarded store64. */
#include "sp11-smmumap.h"

#if Q1N1_SP11_SMMUMAP

static void op_regs(struct q1n1_smmumap_regs *r)
{
    __asm__ volatile("mrs %0, ttbr0_el2" : "=r"(r->ttbr0));
    __asm__ volatile("mrs %0, tcr_el2" : "=r"(r->tcr));
    __asm__ volatile("mrs %0, mair_el2" : "=r"(r->mair));
    __asm__ volatile("mrs %0, sctlr_el2" : "=r"(r->sctlr));
    __asm__ volatile("mrs %0, hcr_el2" : "=r"(r->hcr));
}

/* The translation of `va` by EL2's stage 1 for a read or a write, with no access at it: PAR_EL1 says the result or the fault.
 * The ISB orders the AT before the read of PAR_EL1, as the payloads do it. */
static int op_at(uint64_t va, int write, uint64_t *par)
{
    uint64_t value;
    if (write) __asm__ volatile("at s1e2w, %0" : : "r"(va) : "memory");
    else __asm__ volatile("at s1e2r, %0" : : "r"(va) : "memory");
    __asm__ volatile("isb\n mrs %0, par_el1" : "=r"(value) : : "memory");
    *par = value;
    return 0;
}

static void op_clean(uint64_t va)
{
    __asm__ volatile("dc cvac, %0" : : "r"(va) : "memory");
}

static void op_dsb(void)
{
    __asm__ volatile("dsb ish" : : : "memory");
}

/* TLBI VALE2IS takes VA[55:12] in bits 43:0 (bits 47:44 are the translation table level hint, left zero: no hint). */
static void op_tlbi(uint64_t va)
{
    uint64_t operand = (va >> 12) & ((UINT64_C(1) << 44) - 1);
    __asm__ volatile("tlbi vale2is, %0" : : "r"(operand) : "memory");
}

static void op_isb(void)
{
    __asm__ volatile("isb" : : : "memory");
}

/* ISR_EL1.A, bit 8: an asynchronous SError is pending. A read: it takes nothing and clears nothing. */
static int op_serror_pending(void)
{
    uint64_t isr;
    __asm__ volatile("mrs %0, isr_el1" : "=r"(isr));
    return (int)((isr >> 8) & 1u);
}

void q1n1_smmumap_el2_ops(struct q1n1_smmumap_env *env)
{
    env->regs = op_regs;
    env->at = op_at;
    env->clean = op_clean;
    env->dsb = op_dsb;
    env->tlbi = op_tlbi;
    env->isb = op_isb;
    env->serror_pending = op_serror_pending;
}

#endif /* Q1N1_SP11_SMMUMAP */
