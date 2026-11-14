/* SPDX-License-Identifier: MIT */
/* Host test for the reference payload "state" (payloads/state.c), built natively with
 * Q1N1_PAYLOAD_HOST_TEST so that its register reads come from a scripted register file instead of MRS.
 * Driven by tools/test-q1n1-sp11-payload.py under ASan and UBSan.
 *
 * What it pins: the exact lines for an EL2 core with E2H clear (what the unit is expected to be), with
 * E2H set, and for a core that is not at EL2; that no EL2 register is read when CurrentEL says it is
 * not 2; that TTBR1_EL2 is read exactly when E2H is set; that the set of registers read is exactly the
 * documented one; and that a payload handed bad arguments reads and prints nothing. The test cannot show
 * what the binary does on a core: tools/test-q1n1-sp11-payload.py disassembles the real binary for that.
 *
 * Nothing here runs at EL2 or on hardware. Evidence: EXPERIMENTAL (host model only). */
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SNAP_PLATFORM_SP11 1
#define Q1N1_SP11_PAYLOAD 1
#include "sp11-payload.h"

uint64_t payload_entry(const struct q1n1_payload_args *a);

static unsigned checks;
#define CHECK(x) do { \
        if (!(x)) { fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #x); return 1; } \
        checks++; \
    } while (0)

/* ---- The scripted register file ------------------------------------------------------------------------ */

static const struct { const char *name; uint64_t value; } registers[] = {
    {"CurrentEL", 0}, {"midr_el1", 0x512f0011}, {"mpidr_el1", 0x80000000},
    {"id_aa64mmfr0_el1", 0x2100032310201126}, {"id_aa64mmfr1_el1", 0x110112010312122},
    {"id_aa64mmfr2_el1", 0x1201011112101011}, {"S3_0_C0_C7_3", 0x1000000011001111}, {"S3_0_C0_C7_4", 0},
    {"id_aa64pfr0_el1", 0x1301001121110222}, {"id_aa64pfr1_el1", 0x10101012000121},
    {"hcr_el2", 0}, {"sctlr_el2", 0x100030c5183d}, {"tcr_el2", 0x80843514}, {"ttbr0_el2", 0xa7f2e000},
    {"S3_4_C2_C0_1", 0x12345000}, {"mair_el2", 0xffbb4400}, {"vbar_el2", 0xce399800}, {"cptr_el2", 0x22ff},
    {"cnthctl_el2", 3}, {"cntfrq_el0", 1000000000}, {"daif", 0x3c0}, {"SPSel", 1},
};
#define REGISTER_COUNT (sizeof registers / sizeof registers[0])
static uint64_t scenario_el, scenario_hcr;
static const char *reads[64];
static unsigned read_count;

uint64_t pl_host_sysreg(const char *name);
uint64_t pl_host_sysreg(const char *name)
{
    if (read_count < sizeof reads / sizeof reads[0]) reads[read_count++] = name;
    if (!strcmp(name, "CurrentEL")) return scenario_el << 2;
    if (!strcmp(name, "hcr_el2")) return scenario_hcr;
    for (unsigned i = 0; i < REGISTER_COUNT; i++) if (!strcmp(registers[i].name, name)) return registers[i].value;
    fprintf(stderr, "FAIL: the payload read a register the test does not know: %s\n", name);
    exit(3);
}
static int was_read(const char *name)
{
    for (unsigned i = 0; i < read_count; i++) if (!strcmp(reads[i], name)) return 1;
    return 0;
}

/* ---- The fake ops ---------------------------------------------------------------------------------------- */

static char lines[64][128];
static unsigned line_count;
static void fake_puts(const char *line)
{
    if (line_count < 64) snprintf(lines[line_count++], sizeof lines[0], "%s", line);
}
static uint32_t fake_hex(char *dst, uint32_t cap, uint64_t value) { return (uint32_t)q1n1_payload_fmt_hex(dst, cap, value); }
static int32_t fake_load32(uint64_t addr, uint32_t *out) { (void)addr; (void)out; fprintf(stderr, "FAIL: state used load32\n"); exit(3); }
static uint64_t fake_counter(void) { fprintf(stderr, "FAIL: state used counter\n"); exit(3); }

static struct q1n1_payload_args args(void)
{
    struct q1n1_payload_args a;
    memset(&a, 0, sizeof a);
    a.magic = Q1N1_PAYLOAD_ABI_MAGIC;
    a.version = Q1N1_PAYLOAD_ABI_VERSION;
    a.size = sizeof a;
    a.ops.puts = fake_puts; a.ops.hex = fake_hex; a.ops.load32 = fake_load32; a.ops.counter = fake_counter;
    return a;
}
static uint64_t go(const struct q1n1_payload_args *a, uint64_t el, uint64_t hcr)
{
    scenario_el = el;
    scenario_hcr = hcr;
    read_count = 0;
    line_count = 0;
    return payload_entry(a);
}
static int has_line(const char *text)
{
    for (unsigned i = 0; i < line_count; i++) if (!strcmp(lines[i], text)) return 1;
    return 0;
}

/* The registers the payload is documented to read, in docs/SP11-PAYLOAD.md and in the file's header. */
static const char *const documented[] = {
    "CurrentEL", "midr_el1", "mpidr_el1", "id_aa64mmfr0_el1", "id_aa64mmfr1_el1", "id_aa64mmfr2_el1", "S3_0_C0_C7_3",
    "S3_0_C0_C7_4", "id_aa64pfr0_el1", "id_aa64pfr1_el1", "hcr_el2", "sctlr_el2", "tcr_el2", "ttbr0_el2", "S3_4_C2_C0_1",
    "mair_el2", "vbar_el2", "cptr_el2", "cnthctl_el2", "cntfrq_el0", "daif", "SPSel",
};
static const char *const el2_only[] = {"hcr_el2", "sctlr_el2", "tcr_el2", "ttbr0_el2", "S3_4_C2_C0_1", "mair_el2",
                                       "vbar_el2", "cptr_el2", "cnthctl_el2"};

static int suite_el2(void)
{
    struct q1n1_payload_args a = args();
    /* The unit as q1n1's own page saw it: HCR_EL2 0x88000010, E2H clear. */
    CHECK(go(&a, 2, 0x88000010) == 0);
    static const char *const expect[] = {
        "PAYLOAD STATE CURRENTEL=0X8", "PAYLOAD STATE MIDR_EL1=0X512F0011", "PAYLOAD STATE MPIDR_EL1=0X80000000",
        "PAYLOAD STATE ID_AA64MMFR0_EL1=0X2100032310201126", "PAYLOAD STATE ID_AA64MMFR1_EL1=0X110112010312122",
        "PAYLOAD STATE ID_AA64MMFR2_EL1=0X1201011112101011", "PAYLOAD STATE ID_AA64MMFR3_EL1=0X1000000011001111",
        "PAYLOAD STATE ID_AA64MMFR4_EL1=0X0", "PAYLOAD STATE ID_AA64PFR0_EL1=0X1301001121110222",
        "PAYLOAD STATE ID_AA64PFR1_EL1=0X10101012000121", "PAYLOAD STATE HCR_EL2=0X88000010",
        "PAYLOAD STATE SCTLR_EL2=0X100030C5183D", "PAYLOAD STATE TCR_EL2=0X80843514", "PAYLOAD STATE TTBR0_EL2=0XA7F2E000",
        "PAYLOAD STATE MAIR_EL2=0XFFBB4400", "PAYLOAD STATE VBAR_EL2=0XCE399800", "PAYLOAD STATE CPTR_EL2=0X22FF",
        "PAYLOAD STATE CNTHCTL_EL2=0X3", "PAYLOAD STATE CNTFRQ_EL0=0X3B9ACA00", "PAYLOAD STATE DAIF=0X3C0",
        "PAYLOAD STATE SPSEL=0X1",
    };
    CHECK(line_count == sizeof expect / sizeof expect[0]);
    for (unsigned i = 0; i < line_count; i++) {
        if (strcmp(lines[i], expect[i])) fprintf(stderr, "line %u: %s != %s\n", i, lines[i], expect[i]);
        CHECK(!strcmp(lines[i], expect[i]));
    }
    CHECK(!was_read("S3_4_C2_C0_1"));                            /* TTBR1_EL2 is not part of the regime with E2H clear */
    CHECK(read_count == sizeof documented / sizeof documented[0] - 1);

    /* E2H set (bit 34): TTBR1_EL2 is read and printed, after TTBR0_EL2. */
    CHECK(go(&a, 2, UINT64_C(1) << 34 | 0x88000010) == 0);
    CHECK(line_count == 22 && has_line("PAYLOAD STATE TTBR1_EL2=0X12345000") && has_line("PAYLOAD STATE HCR_EL2=0X488000010"));
    CHECK(!strcmp(lines[13], "PAYLOAD STATE TTBR0_EL2=0XA7F2E000") && !strcmp(lines[14], "PAYLOAD STATE TTBR1_EL2=0X12345000"));
    CHECK(read_count == sizeof documented / sizeof documented[0]);
    /* Every bit of HCR_EL2 but 34 set: no TTBR1; only 34 set: TTBR1. */
    CHECK(go(&a, 2, ~(UINT64_C(1) << 34)) == 0 && !was_read("S3_4_C2_C0_1") && line_count == 21);
    CHECK(go(&a, 2, UINT64_C(1) << 34) == 0 && was_read("S3_4_C2_C0_1") && line_count == 22);

    /* The set of registers read is exactly the documented one, each once, and every line is in the font. */
    CHECK(read_count == 22);
    for (unsigned i = 0; i < sizeof documented / sizeof documented[0]; i++) {
        unsigned n = 0;
        for (unsigned k = 0; k < read_count; k++) n += !strcmp(reads[k], documented[i]);
        CHECK(n == 1);
    }
    for (unsigned i = 0; i < line_count; i++) {
        CHECK(strlen(lines[i]) <= Q1N1_PAYLOAD_LINE_MAX && !strncmp(lines[i], "PAYLOAD STATE ", 14));
        const char *eq = strchr(lines[i], '=');
        CHECK(eq && !strncmp(eq + 1, "0X", 2));
        for (const char *p = lines[i]; *p; p++) CHECK((*p >= 'A' && *p <= 'Z') || (*p >= '0' && *p <= '9') || strchr(" _=", *p));
    }
    /* Lines are well under the payload's budget, with room for the runner's own. */
    CHECK(line_count <= Q1N1_PAYLOAD_LINES_MAX / 2 + 2);
    return 0;
}

static int suite_not_el2(void)
{
    struct q1n1_payload_args a = args();
    for (uint64_t el = 0; el <= 3; el++) {
        if (el == 2) continue;
        CHECK(go(&a, el, UINT64_C(1) << 34) == 0);
        for (unsigned i = 0; i < sizeof el2_only / sizeof el2_only[0]; i++) CHECK(!was_read(el2_only[i]));
        CHECK(line_count == 14 && has_line("PAYLOAD STATE EL2REGS=SKIPPED_NOT_AT_EL2"));
        CHECK(has_line(el == 0 ? "PAYLOAD STATE CURRENTEL=0X0" : el == 1 ? "PAYLOAD STATE CURRENTEL=0X4" : "PAYLOAD STATE CURRENTEL=0XC"));
        CHECK(has_line("PAYLOAD STATE SPSEL=0X1") && has_line("PAYLOAD STATE DAIF=0X3C0"));
        CHECK(read_count == 13);
        for (unsigned i = 0; i < line_count; i++) CHECK(strncmp(lines[i], "PAYLOAD STATE HCR_EL2", 21) != 0);
    }
    return 0;
}

static int suite_args(void)
{
    struct q1n1_payload_args a = args();
    CHECK(go(NULL, 2, 0) == Q1N1_PAYLOAD_RET_BAD_ARGS && read_count == 0 && line_count == 0);
    a = args(); a.magic ^= 1;
    CHECK(go(&a, 2, 0) == Q1N1_PAYLOAD_RET_BAD_ARGS && read_count == 0 && line_count == 0);
    a = args(); a.version = 2;
    CHECK(go(&a, 2, 0) == Q1N1_PAYLOAD_RET_BAD_ARGS && read_count == 0 && line_count == 0);
    a = args(); a.version = 0;
    CHECK(go(&a, 2, 0) == Q1N1_PAYLOAD_RET_BAD_ARGS && read_count == 0);
    a = args(); a.size = sizeof a - 1;
    CHECK(go(&a, 2, 0) == Q1N1_PAYLOAD_RET_BAD_ARGS && read_count == 0 && line_count == 0);
    a = args(); a.ops.puts = NULL;
    CHECK(go(&a, 2, 0) == Q1N1_PAYLOAD_RET_BAD_ARGS && read_count == 0);
    a = args(); a.ops.hex = NULL;
    CHECK(go(&a, 2, 0) == Q1N1_PAYLOAD_RET_BAD_ARGS && read_count == 0);
    /* A newer runner hands a bigger block: accepted, the payload reads only what version 1 has. */
    a = args(); a.size = sizeof a + 64;
    CHECK(go(&a, 2, 0) == 0 && line_count == 21);
    /* load32 and counter are not needed and not used (a use would exit with a tripwire). */
    a = args(); a.ops.load32 = NULL; a.ops.counter = NULL;
    CHECK(go(&a, 2, 0) == 0 && line_count == 21);
    return 0;
}

int main(int argc, char **argv)
{
    static const struct { const char *name; int (*run)(void); } suites[] = {
        {"el2", suite_el2}, {"not-el2", suite_not_el2}, {"args", suite_args},
    };
    unsigned ran = 0;
    for (unsigned i = 0; i < sizeof suites / sizeof suites[0]; i++) {
        if (argc > 1 && strcmp(argv[1], "all") && strcmp(argv[1], suites[i].name)) continue;
        if (suites[i].run()) { fprintf(stderr, "FAIL: suite %s\n", suites[i].name); return 1; }
        ran++;
    }
    printf("PASS: %u payload state suites, %u checks\n", ran, checks);
    return 0;
}
