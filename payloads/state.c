/* SPDX-License-Identifier: MIT */
/* Reference payload "state": prints the EL2 state the boot CPU is in, and nothing else. READ ONLY: it
 * executes MRS and nothing that writes a system register, a cache, a TLB or a device (the tests
 * disassemble the binary and refuse anything but an MRS from the list below). It never touches memory
 * other than its own stack, and does not use the load32 op.
 *
 * Lines are PAYLOAD STATE KEY=VALUE, one register each, values as 0X hex. The registers, and why each is
 * allowed (docs/SP11-PAYLOAD.md has the table with the evidence label of each):
 *
 *   always readable at EL1 and EL2:   CurrentEL, MIDR_EL1, MPIDR_EL1, ID_AA64MMFR0..4_EL1,
 *                                     ID_AA64PFR0_EL1, ID_AA64PFR1_EL1, CNTFRQ_EL0, DAIF, SPSel
 *   read only when CurrentEL says 2:  HCR_EL2, SCTLR_EL2, TCR_EL2, TTBR0_EL2, MAIR_EL2, VBAR_EL2,
 *                                     CPTR_EL2, CNTHCTL_EL2, and TTBR1_EL2 only when HCR_EL2.E2H is set
 *
 * Reading an EL2 register at EL1 is UNDEFINED, so CurrentEL is read first and the EL2 block is skipped
 * unless it is 2. The runner only calls a payload at EL2, so the guard is for a payload run any other
 * way. E2H is expected to read 0 on this unit (OBSERVED through q1n1's own page), but nothing here
 * depends on it: TTBR1_EL2 is the only register whose meaning depends on E2H, and it is read exactly when
 * E2H says it is part of the translation regime. CNTVOFF_EL2 and CNTPOFF_EL2 are never read (an earlier
 * test that touched them stalled this core), and nothing writes CNTKCTL_EL1 or any other register.
 *
 * ID_AA64MMFR3_EL1 and ID_AA64MMFR4_EL1 are spelled by encoding (S3_0_C0_C7_3 and _4) because an
 * assembler accepts their names only with a newer architecture in the target. They sit in the ID
 * register space, where Arm defines an unallocated encoding as read-as-zero, not UNDEFINED. */
#include "payload-util.h"

#ifdef Q1N1_PAYLOAD_HOST_TEST
/* The host test replaces the register file: no MRS can run at EL0 on a build machine. */
uint64_t pl_host_sysreg(const char *name);
#define SYSREG(name) pl_host_sysreg(#name)
#else
#define SYSREG(name) ({ uint64_t value_; __asm__ volatile("mrs %0, " #name : "=r"(value_)); value_; })
#endif

#define SHOW(key, reg) show(a, key, SYSREG(reg))

/* Out of line, so that the twenty-odd uses are calls and the binary stays a few hundred bytes. */
static __attribute__((noinline)) void show(const struct q1n1_payload_args *a, const char *key, uint64_t value)
{
    pl_keyed_hex(a, "PAYLOAD STATE ", key, value);
}

uint64_t payload_entry(const struct q1n1_payload_args *a);
uint64_t payload_entry(const struct q1n1_payload_args *a)
{
    if (!pl_args_ok(a)) return Q1N1_PAYLOAD_RET_BAD_ARGS;
    uint64_t current_el = SYSREG(CurrentEL);
    show(a, "CURRENTEL", current_el);
    SHOW("MIDR_EL1", midr_el1);
    SHOW("MPIDR_EL1", mpidr_el1);
    SHOW("ID_AA64MMFR0_EL1", id_aa64mmfr0_el1);
    SHOW("ID_AA64MMFR1_EL1", id_aa64mmfr1_el1);
    SHOW("ID_AA64MMFR2_EL1", id_aa64mmfr2_el1);
    SHOW("ID_AA64MMFR3_EL1", S3_0_C0_C7_3);
    SHOW("ID_AA64MMFR4_EL1", S3_0_C0_C7_4);
    SHOW("ID_AA64PFR0_EL1", id_aa64pfr0_el1);
    SHOW("ID_AA64PFR1_EL1", id_aa64pfr1_el1);
    if (current_el >> 2 == 2) {
        uint64_t hcr = SYSREG(hcr_el2);
        show(a, "HCR_EL2", hcr);
        SHOW("SCTLR_EL2", sctlr_el2);
        SHOW("TCR_EL2", tcr_el2);
        SHOW("TTBR0_EL2", ttbr0_el2);
        if (hcr >> 34 & 1) SHOW("TTBR1_EL2", S3_4_C2_C0_1);
        SHOW("MAIR_EL2", mair_el2);
        SHOW("VBAR_EL2", vbar_el2);
        SHOW("CPTR_EL2", cptr_el2);
        SHOW("CNTHCTL_EL2", cnthctl_el2);
    } else {
        pl_keyed_text(a, "PAYLOAD STATE ", "EL2REGS", "SKIPPED_NOT_AT_EL2");
    }
    SHOW("CNTFRQ_EL0", cntfrq_el0);
    SHOW("DAIF", daif);
    SHOW("SPSEL", SPSel);
    return 0;
}
