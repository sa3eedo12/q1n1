/* SPDX-License-Identifier: MIT */
/* Payload "psci": asks the firmware's PSCI implementation what it supports, with SMC at EL2, and prints the
 * answers. READ ONLY in the PSCI sense: it issues exactly five function ids and no id that changes the
 * machine, and the tests refuse a binary or a source that does otherwise.
 *
 * Ids it may issue (SMCCC fast calls; Arm DEN0022 PSCI and DEN0028 SMCCC, the numbers cross-checked against
 * Linux's include/uapi/linux/psci.h and include/linux/arm-smccc.h; labelled VERIFIED in the documentation):
 *
 *   PSCI_VERSION        0x84000000   no argument
 *   MIGRATE_INFO_TYPE   0x84000006   no argument
 *   PSCI_FEATURES       0x8400000A   x1 = one of the ten ids in feature_id[] below
 *   AFFINITY_INFO       0xC4000004   x1 = one of the twelve MPIDR affinities in cpu_affinity[], x2 = 0
 *   SMCCC_VERSION       0x80000000   no argument, asked last and alone (see payload_entry)
 *
 * It NEVER issues CPU_ON, CPU_OFF, CPU_SUSPEND, SYSTEM_OFF, SYSTEM_RESET, SYSTEM_RESET2, SYSTEM_SUSPEND, MIGRATE
 * or any other id: the ids in feature_id[] are only ever the ARGUMENT of PSCI_FEATURES, a query about whether
 * the function exists, which has no effect. smc_query() below is the only place an `smc` appears. It takes a
 * kind of query and an index into a table, never a function id, so no other id can be expressed through it,
 * and an index outside its table issues nothing.
 *
 * Calling convention, SMCCC 1.1: x0 = function id, x1..x3 = arguments (zero when unused), results in x0..x3,
 * x4..x17 and memory clobbered. The conduit is SMC: the unit's FADT has ARM_BOOT_ARCH 0x1, PSCI_COMPLIANT=1
 * and PSCI_USE_HVC=0 (OBSERVED). Whether the firmware's PSCI answers an SMC from EL2 after the Secure-Launch
 * bounce is UNKNOWN until this runs. The twelve MPIDR affinities are the MADT's GICC entries (OBSERVED on the
 * unit); the boot CPU reads MPIDR_EL1 0x80000000, whose bit 31 is RES1, so its affinity is 0.
 *
 * CurrentEL is read first and nothing else is done unless it says EL2, like state.c. The only system registers
 * read are CurrentEL and MPIDR_EL1; CNTVOFF_EL2 and CNTPOFF_EL2 are never touched (an earlier test that touched
 * them stalled this core).
 *
 * A hang must be nameable, so every group of calls is announced with a NEXT line before its first call, and
 * each group's results are printed as soon as the group is complete. Results are PAYLOAD PSCI lines of
 * KEY=RAW[:DECODE] entries, RAW being x0 as the runner's hex op prints it. An entry that would not fit in a
 * line starts the next one, so no line is ever cut. DECODE appears only where the value is certain:
 *   - a result is an error code when it is -1..-9, read as the 32-bit w0 of an SMC32 call (the upper half of
 *     x0 is not defined then) and as the whole 64-bit x0 of an SMC64 call: NAME(-N);
 *   - PSCI_VERSION and SMCCC_VERSION: V<major>.<minor>, both encoded major << 16 | minor;
 *   - MIGRATE_INFO_TYPE: 0 TOS_UP_MIGRATE, 1 TOS_UP_NO_MIGRATE, 2 TOS_MP;
 *   - AFFINITY_INFO: 0 ON, 1 OFF, 2 ON_PENDING;
 *   - a PSCI_FEATURES result that is not an error is the feature flags, shown raw (0 is supported, none).
 * Any other value, all ones in the upper half of a version included, is shown raw. The upper bound on the
 * lines is 1 + 3 + 11 + 13 + 2 = 30 for any answers at all, within the 40 of the ABI. */
#include "payload-util.h"

#ifdef Q1N1_PAYLOAD_HOST_TEST
/* The host test replaces both: no MRS and no SMC can run at EL0 on a build machine. */
uint64_t pl_host_sysreg(const char *name);
void pl_host_smc(uint64_t regs[4]);
#define SYSREG(name) pl_host_sysreg(#name)
#else
#define SYSREG(name) ({ uint64_t value_; __asm__ volatile("mrs %0, " #name : "=r"(value_)); value_; })
#endif

#define PREFIX "PAYLOAD PSCI "
/* Every helper is out of line: the reviewed binary stays a third smaller than with the compiler's inlining, and
 * smc_query has to be, to keep the `smc` instruction unique. */
#define OUT_OF_LINE static __attribute__((noinline))

#define FUNCTION_PSCI_VERSION 0x84000000u
#define FUNCTION_MIGRATE_INFO_TYPE 0x84000006u
#define FUNCTION_PSCI_FEATURES 0x8400000Au
#define FUNCTION_AFFINITY_INFO 0xC4000004u
#define FUNCTION_SMCCC_VERSION 0x80000000u

#define FEATURE_COUNT 10u
#define CPU_COUNT 12u

/* The functions PSCI_FEATURES is asked about: CPU_SUSPEND, CPU_OFF, CPU_ON, AFFINITY_INFO, MIGRATE_INFO_TYPE,
 * SYSTEM_OFF, SYSTEM_RESET, PSCI_FEATURES, SYSTEM_SUSPEND and SYSTEM_RESET2. Only ever an argument. */
static const uint32_t feature_id[FEATURE_COUNT] = {
    0xC4000001u, 0x84000002u, 0xC4000003u, 0xC4000004u, 0x84000006u,
    0x84000008u, 0x84000009u, 0x8400000Au, 0xC400000Eu, 0xC4000012u,
};
/* Arrays of characters, not of pointers: an absolute pointer table would depend on the load address. */
static const char feature_name[FEATURE_COUNT][18] = {
    "CPU_SUSPEND", "CPU_OFF", "CPU_ON", "AFFINITY_INFO", "MIGRATE_INFO_TYPE",
    "SYSTEM_OFF", "SYSTEM_RESET", "PSCI_FEATURES", "SYSTEM_SUSPEND", "SYSTEM_RESET2",
};
/* The MADT's GICC MPIDR affinities, in CPU order (OBSERVED on the one unit). */
static const uint64_t cpu_affinity[CPU_COUNT] = {
    0x0, 0x100, 0x200, 0x300, 0x10000, 0x10100, 0x10200, 0x10300, 0x20000, 0x20100, 0x20200, 0x20300,
};
/* PSCI return codes -1 to -9. */
static const char error_name[9][19] = {
    "NOT_SUPPORTED", "INVALID_PARAMETERS", "DENIED", "ALREADY_ON", "ON_PENDING",
    "INTERNAL_FAILURE", "NOT_PRESENT", "DISABLED", "INVALID_ADDRESS",
};
static const char tos_name[3][19] = {"TOS_UP_MIGRATE", "TOS_UP_NO_MIGRATE", "TOS_MP"};
static const char state_name[3][11] = {"ON", "OFF", "ON_PENDING"};

enum query {
    QUERY_PSCI_VERSION,
    QUERY_MIGRATE_INFO_TYPE,
    QUERY_PSCI_FEATURES,
    QUERY_AFFINITY_INFO,
    QUERY_SMCCC_VERSION,
};
/* What smc_query returns when its arguments name nothing it may ask: no SMC was issued. "NOT_ISSE" in ASCII;
 * it is a bug of the caller and never an answer, and it decodes as nothing. */
#define NOT_ISSUED UINT64_C(0x4e4f545f49535345)

/* The one SMC. Out of line, so that there is exactly one `smc` instruction in the binary whatever the
 * compiler would do with an inline copy at each of the call sites. */
OUT_OF_LINE uint64_t smc_query(enum query which, unsigned index)
{
    uint64_t regs[4] = {0, 0, 0, 0};
    if (which == QUERY_PSCI_VERSION) {
        regs[0] = FUNCTION_PSCI_VERSION;
    } else if (which == QUERY_MIGRATE_INFO_TYPE) {
        regs[0] = FUNCTION_MIGRATE_INFO_TYPE;
    } else if (which == QUERY_SMCCC_VERSION) {
        regs[0] = FUNCTION_SMCCC_VERSION;
    } else if (which == QUERY_PSCI_FEATURES && index < FEATURE_COUNT) {
        regs[0] = FUNCTION_PSCI_FEATURES;
        regs[1] = feature_id[index];
    } else if (which == QUERY_AFFINITY_INFO && index < CPU_COUNT) {
        regs[0] = FUNCTION_AFFINITY_INFO;
        regs[1] = cpu_affinity[index];
        regs[2] = 0;                    /* lowest affinity level: the CPU itself */
    } else {
        return NOT_ISSUED;
    }
#ifdef Q1N1_PAYLOAD_HOST_TEST
    pl_host_smc(regs);
#else
    register uint64_t x0 __asm__("x0") = regs[0];
    register uint64_t x1 __asm__("x1") = regs[1];
    register uint64_t x2 __asm__("x2") = regs[2];
    register uint64_t x3 __asm__("x3") = regs[3];
    __asm__ volatile("smc #0" : "+r"(x0), "+r"(x1), "+r"(x2), "+r"(x3)
                     :
                     : "x4", "x5", "x6", "x7", "x8", "x9", "x10", "x11", "x12", "x13", "x14", "x15", "x16", "x17",
                       "memory");
    regs[0] = x0;
    regs[1] = x1;
    regs[2] = x2;
    regs[3] = x3;
#endif
    return regs[0];
}

/* ---- Printing ---------------------------------------------------------------------------------------- */

OUT_OF_LINE void pl_dec(struct pl_line *line, uint32_t value)
{
    char digits[10];
    unsigned n = 0;
    do {
        digits[n++] = (char)('0' + value % 10);
        value /= 10;
    } while (value);
    while (n && line->len < Q1N1_PAYLOAD_LINE_MAX) line->buf[line->len++] = digits[--n];
    line->buf[line->len] = 0;
}

OUT_OF_LINE void say(const struct q1n1_payload_args *a, const char *text)
{
    struct pl_line line;
    pl_begin(&line);
    pl_text(&line, PREFIX);
    pl_text(&line, text);
    pl_emit(a, &line);
}

enum decode {
    DECODE_VERSION32,   /* PSCI_VERSION, SMCCC_VERSION: SMC32 */
    DECODE_TOS32,       /* MIGRATE_INFO_TYPE: SMC32 */
    DECODE_FLAGS32,     /* PSCI_FEATURES: SMC32 */
    DECODE_STATE64,     /* AFFINITY_INFO: SMC64 */
};

/* 1 to 9 when `negated` is the magnitude of a PSCI error code, else 0. */
static unsigned error_code(uint64_t negated)
{
    return negated - 1 < 9 ? (unsigned)negated : 0;
}

/* ":DECODE" for a value that has a certain meaning, nothing otherwise. */
OUT_OF_LINE void add_decode(struct pl_line *item, enum decode how, uint64_t x0)
{
    uint32_t w0 = (uint32_t)x0;
    unsigned error = how == DECODE_STATE64 ? error_code(UINT64_C(0) - x0) : error_code((uint32_t)(0u - w0));
    if (error) {
        char digit[2] = {(char)('0' + error), 0};
        pl_text(item, ":");
        pl_text(item, error_name[error - 1]);
        pl_text(item, "(-");
        pl_text(item, digit);
        pl_text(item, ")");
    } else if (how == DECODE_VERSION32 && !(w0 >> 31)) {
        pl_text(item, ":V");
        pl_dec(item, w0 >> 16);
        pl_text(item, ".");
        pl_dec(item, w0 & 0xffff);
    } else if (how == DECODE_TOS32 && w0 <= 2) {
        pl_text(item, ":");
        pl_text(item, tos_name[w0]);
    } else if (how == DECODE_STATE64 && x0 <= 2) {
        pl_text(item, ":");
        pl_text(item, state_name[x0]);
    }
}

/* One group's results: the lines PAYLOAD PSCI <GROUP> <entries>, filled greedily. */
struct report {
    const struct q1n1_payload_args *a;
    const char *group;
    struct pl_line line;
    struct pl_line item;
};

OUT_OF_LINE void report_line(struct report *r)
{
    pl_begin(&r->line);
    pl_text(&r->line, PREFIX);
    pl_text(&r->line, r->group);
}

OUT_OF_LINE void report_begin(struct report *r, const struct q1n1_payload_args *a, const char *group)
{
    r->a = a;
    r->group = group;
    report_line(r);
}

/* KEY=RAW[:DECODE], the key being text or, when `key` is NULL, the number `key_value` in hex. */
OUT_OF_LINE void report_result(struct report *r, const char *key, uint64_t key_value, uint64_t x0, enum decode how)
{
    pl_begin(&r->item);
    if (key) pl_text(&r->item, key);
    else pl_hex(r->a, &r->item, key_value);
    pl_text(&r->item, "=");
    pl_hex(r->a, &r->item, x0);
    add_decode(&r->item, how, x0);
    if (r->line.len + 1 + r->item.len > Q1N1_PAYLOAD_LINE_MAX) {
        pl_emit(r->a, &r->line);
        report_line(r);
    }
    pl_text(&r->line, " ");
    pl_text(&r->line, r->item.buf);
}

OUT_OF_LINE void report_end(struct report *r)
{
    pl_emit(r->a, &r->line);
}

uint64_t payload_entry(const struct q1n1_payload_args *a);
uint64_t payload_entry(const struct q1n1_payload_args *a)
{
    if (!pl_args_ok(a)) return Q1N1_PAYLOAD_RET_BAD_ARGS;
    if ((SYSREG(CurrentEL) >> 2 & 3) != 2) {
        say(a, "SKIPPED_NOT_AT_EL2");
        return 0;
    }
    pl_keyed_hex(a, PREFIX, "MPIDR_EL1", SYSREG(mpidr_el1));

    struct report r;
    say(a, "NEXT VERSION");
    uint64_t psci_version = smc_query(QUERY_PSCI_VERSION, 0);
    uint64_t migrate = smc_query(QUERY_MIGRATE_INFO_TYPE, 0);
    report_begin(&r, a, "VERSION");
    report_result(&r, "PSCI_VERSION", 0, psci_version, DECODE_VERSION32);
    report_result(&r, "MIGRATE_INFO_TYPE", 0, migrate, DECODE_TOS32);
    report_end(&r);

    say(a, "NEXT FEATURES");
    uint64_t features[FEATURE_COUNT];
    for (unsigned i = 0; i < FEATURE_COUNT; i++) features[i] = smc_query(QUERY_PSCI_FEATURES, i);
    report_begin(&r, a, "FEATURES");
    for (unsigned i = 0; i < FEATURE_COUNT; i++) report_result(&r, feature_name[i], 0, features[i], DECODE_FLAGS32);
    report_end(&r);

    say(a, "NEXT AFFINITY");
    uint64_t state[CPU_COUNT];
    for (unsigned i = 0; i < CPU_COUNT; i++) state[i] = smc_query(QUERY_AFFINITY_INFO, i);
    report_begin(&r, a, "AFFINITY");
    for (unsigned i = 0; i < CPU_COUNT; i++) report_result(&r, 0, cpu_affinity[i], state[i], DECODE_STATE64);
    report_end(&r);

    /* Last and alone. It is the one id that is not a PSCI function: a firmware that implements only PSCI may
     * answer it with -1 (SMCCC 1.0), or not as expected, and Linux asks PSCI_FEATURES whether it exists first,
     * which the fixed table of ids does not allow here. Whatever it does, the PSCI answers are on the page. */
    say(a, "NEXT SMCCC");
    uint64_t smccc = smc_query(QUERY_SMCCC_VERSION, 0);
    report_begin(&r, a, "SMCCC");
    report_result(&r, "SMCCC_VERSION", 0, smccc, DECODE_VERSION32);
    report_end(&r);
    return 0;
}
