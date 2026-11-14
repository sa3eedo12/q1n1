/* SPDX-License-Identifier: MIT */
/* Host test for the payload "psci" (payloads/psci.c), built natively with Q1N1_PAYLOAD_HOST_TEST so that its two
 * system register reads and its one SMC come from scripts instead of the CPU. Driven by
 * tools/test-q1n1-sp11-payload.py and tools/test-q1n1-sp11-payload-chain.py under ASan and UBSan.
 *
 * What it pins, each against the same independent copy of the tables the payload is documented to hold:
 *   ids       only the five whitelisted function ids are ever called; PSCI_FEATURES is only ever given one of the ten
 *             ids of its table and AFFINITY_INFO one of the twelve MPIDRs with lowest level 0; no argument register
 *             is set that the call does not use; CPU_ON, CPU_OFF, CPU_SUSPEND, SYSTEM_OFF, SYSTEM_RESET,
 *             SYSTEM_RESET2, SYSTEM_SUSPEND and MIGRATE appear only as the argument of PSCI_FEATURES; every call
 *             comes from one call site (the return address of the scripted SMC is always the same)
 *   el        no SMC at all and one line when CurrentEL is not 2
 *   next      a NEXT line before the first call of each group, each group's results as soon as it is complete, and
 *             the order of the groups
 *   decode    the text of every documented return code, for the 32-bit results of SMC32 calls and the 64-bit one of
 *             AFFINITY_INFO, and no decode for anything that is not certain
 *   garbage   all ones, zero, a huge positive and thousands of random answers never print a character outside the
 *             page font, a line over 100 characters, more than 40 lines, or lose an entry
 *   qemu      the exact lines for the answers QEMU 11.1.3's PSCI gave at EL2 (OBSERVED once, under the pinned test
 *             setup; the QEMU test compares the same lines)
 *   args      bad arguments print and call nothing
 *
 * The test cannot show what the binary does on a core: tools/test-q1n1-sp11-payload-build.py disassembles the real
 * binary. Nothing here runs at EL2 or on hardware. Evidence: EXPERIMENTAL (host model only). */
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

#define FEATURES 10u
#define CPUS 12u
/* The tables the payload is documented to hold: this is the second, independent copy. */
static const uint32_t feature_id[FEATURES] = {0xC4000001u, 0x84000002u, 0xC4000003u, 0xC4000004u, 0x84000006u,
                                              0x84000008u, 0x84000009u, 0x8400000Au, 0xC400000Eu, 0xC4000012u};
static const char *const feature_name[FEATURES] = {"CPU_SUSPEND", "CPU_OFF", "CPU_ON", "AFFINITY_INFO", "MIGRATE_INFO_TYPE",
                                                   "SYSTEM_OFF", "SYSTEM_RESET", "PSCI_FEATURES", "SYSTEM_SUSPEND",
                                                   "SYSTEM_RESET2"};
static const uint64_t mpidr[CPUS] = {0x0, 0x100, 0x200, 0x300, 0x10000, 0x10100, 0x10200, 0x10300,
                                     0x20000, 0x20100, 0x20200, 0x20300};
#define ID_PSCI_VERSION 0x84000000u
#define ID_MIGRATE_INFO_TYPE 0x84000006u
#define ID_PSCI_FEATURES 0x8400000Au
#define ID_AFFINITY_INFO 0xC4000004u
#define ID_SMCCC_VERSION 0x80000000u
/* Functions that change the machine: never a call, only ever the argument of PSCI_FEATURES. */
static const uint32_t forbidden[] = {0x84000001u, 0xC4000001u, 0x84000002u, 0x84000003u, 0xC4000003u, 0x84000005u,
                                     0xC4000005u, 0x84000008u, 0x84000009u, 0x8400000Eu, 0xC400000Eu, 0x84000012u,
                                     0xC4000012u, 0x8400000Bu, 0x8400000Fu, 0x84000013u, 0x84000015u};

/* ---- The scripts ---------------------------------------------------------------------------------------- */

struct scenario {
    uint64_t version, migrate, smccc, other;   /* `other` fills x1..x3 of every reply */
    uint64_t feature[FEATURES], affinity[CPUS];
};
static struct scenario sc;
static uint64_t scenario_el = 2, scenario_mpidr = 0x80000000;
static const char *reads[16];
static unsigned read_count;

uint64_t pl_host_sysreg(const char *name);
uint64_t pl_host_sysreg(const char *name)
{
    if (read_count < sizeof reads / sizeof reads[0]) reads[read_count++] = name;
    if (!strcmp(name, "CurrentEL")) return scenario_el << 2;
    if (!strcmp(name, "mpidr_el1")) return scenario_mpidr;
    fprintf(stderr, "FAIL: the payload read a register the test does not know: %s\n", name);
    exit(3);
}

enum { EV_LINE, EV_CALL };
struct event { int kind; char text[160]; uint64_t id, x1, x2, x3; const void *site; };
static struct event log_[512];
static unsigned log_n, calls, bad_calls, bad_lines, line_total;
static char first_bad[160];
static void record(struct event e)
{
    if (log_n >= sizeof log_ / sizeof log_[0]) { fprintf(stderr, "FAIL: event log full\n"); exit(2); }
    log_[log_n++] = e;
}

static int in_font(const char *text)
{
    for (; *text; text++)
        if (!((*text >= 'A' && *text <= 'Z') || (*text >= '0' && *text <= '9') || strchr(" :-./=?()_", *text))) return 0;
    return 1;
}
static void fake_puts(const char *line)
{
    struct event e = {.kind = EV_LINE};
    size_t n = strlen(line);
    snprintf(e.text, sizeof e.text, "%.159s", line);
    if (n > Q1N1_PAYLOAD_LINE_MAX || !in_font(line)) {
        bad_lines++;
        if (!first_bad[0]) snprintf(first_bad, sizeof first_bad, "%.159s", line);
    }
    line_total++;
    record(e);
}
static uint32_t fake_hex(char *dst, uint32_t cap, uint64_t value) { return (uint32_t)q1n1_payload_fmt_hex(dst, cap, value); }
static int32_t fake_load32(uint64_t addr, uint32_t *out) { (void)addr; (void)out; fprintf(stderr, "FAIL: psci used load32\n"); exit(3); }
static uint64_t fake_counter(void) { fprintf(stderr, "FAIL: psci used counter\n"); exit(3); }

/* The scripted SMC. The reply to each call comes from the scenario, chosen by the call's own function id and, for
 * the two that take an argument, by that argument; a call the test does not know is a call that is not allowed. */
void pl_host_smc(uint64_t regs[4]);
void pl_host_smc(uint64_t regs[4])
{
    struct event e = {.kind = EV_CALL, .id = regs[0], .x1 = regs[1], .x2 = regs[2], .x3 = regs[3],
                      .site = __builtin_return_address(0)};
    uint64_t reply = ~UINT64_C(0);
    calls++;
    if (regs[0] == ID_PSCI_VERSION) reply = sc.version;
    else if (regs[0] == ID_MIGRATE_INFO_TYPE) reply = sc.migrate;
    else if (regs[0] == ID_SMCCC_VERSION) reply = sc.smccc;
    else if (regs[0] == ID_PSCI_FEATURES) {
        unsigned known = 0;
        for (unsigned i = 0; i < FEATURES; i++) if (regs[1] == feature_id[i]) { reply = sc.feature[i]; known = 1; }
        bad_calls += !known;
    } else if (regs[0] == ID_AFFINITY_INFO) {
        unsigned known = 0;
        for (unsigned i = 0; i < CPUS; i++) if (regs[1] == mpidr[i]) { reply = sc.affinity[i]; known = 1; }
        bad_calls += !known;
    } else {
        bad_calls++;
    }
    snprintf(e.text, sizeof e.text, "%" PRIx64, regs[0]);
    record(e);
    regs[0] = reply;
    regs[1] = regs[2] = regs[3] = sc.other;
}

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
static uint64_t go(const struct q1n1_payload_args *a, uint64_t el)
{
    scenario_el = el;
    log_n = calls = bad_calls = bad_lines = line_total = read_count = 0;
    first_bad[0] = 0;
    return payload_entry(a);
}

static void fill_all(uint64_t value)
{
    sc.version = sc.migrate = sc.smccc = value;
    for (unsigned i = 0; i < FEATURES; i++) sc.feature[i] = value;
    for (unsigned i = 0; i < CPUS; i++) sc.affinity[i] = value;
}
/* What QEMU 11.1.3's PSCI answered at EL2 under the pinned test setup (virt, virtualization=on, one CPU). */
static void fill_qemu(void)
{
    memset(&sc, 0, sizeof sc);
    sc.version = 0x10001;
    sc.migrate = 2;
    for (unsigned i = 0; i < FEATURES; i++) sc.feature[i] = i == 8 || i == 9 ? ~UINT64_C(0) : 0;
    for (unsigned i = 0; i < CPUS; i++) sc.affinity[i] = i == 0 ? 0 : ~UINT64_C(1);
    sc.smccc = ~UINT64_C(0);
    sc.other = 0;
}

/* ---- Reading the output ---------------------------------------------------------------------------------- */

static unsigned lines_n(void) { unsigned n = 0; for (unsigned i = 0; i < log_n; i++) n += log_[i].kind == EV_LINE; return n; }
static int line_index(const char *text)
{
    for (unsigned i = 0; i < log_n; i++) if (log_[i].kind == EV_LINE && !strcmp(log_[i].text, text)) return (int)i;
    return -1;
}
/* The log index of the first line that starts with `prefix`, at or after `from`. */
static int line_from(const char *prefix, unsigned from)
{
    for (unsigned i = from; i < log_n; i++) if (log_[i].kind == EV_LINE && !strncmp(log_[i].text, prefix, strlen(prefix))) return (int)i;
    return -1;
}
/* Index of the first call with function id `id` (and, if `x1` is not ~0, that argument). */
static int call_index(uint32_t id, uint64_t x1, int after)
{
    for (unsigned i = after < 0 ? 0 : (unsigned)after + 1; i < log_n; i++)
        if (log_[i].kind == EV_CALL && log_[i].id == id && (x1 == ~UINT64_C(0) || log_[i].x1 == x1)) return (int)i;
    return -1;
}
/* The entry `key=...` of a group, copied out, or NULL. Entries are separated by spaces after "PAYLOAD PSCI <GROUP>". */
static const char *entry_of(const char *group, const char *key, char *out, size_t cap)
{
    char prefix[40];
    snprintf(prefix, sizeof prefix, "PAYLOAD PSCI %s ", group);
    size_t want = strlen(key);
    for (unsigned i = 0; i < log_n; i++) {
        if (log_[i].kind != EV_LINE || strncmp(log_[i].text, prefix, strlen(prefix))) continue;
        const char *p = log_[i].text + strlen(prefix);
        while (*p) {
            const char *end = strchr(p, ' ');
            size_t n = end ? (size_t)(end - p) : strlen(p);
            if (n > want && !strncmp(p, key, want) && p[want] == '=') { snprintf(out, cap, "%.*s", (int)n, p); return out; }
            p += n + (end ? 1 : 0);
        }
    }
    return NULL;
}
static unsigned entries_in(const char *group)
{
    char prefix[40];
    unsigned n = 0;
    snprintf(prefix, sizeof prefix, "PAYLOAD PSCI %s ", group);
    for (unsigned i = 0; i < log_n; i++) {
        if (log_[i].kind != EV_LINE || strncmp(log_[i].text, prefix, strlen(prefix))) continue;
        n++;
        for (const char *p = log_[i].text + strlen(prefix); *p; p++) n += *p == ' ';
    }
    return n;
}
static void key_of(unsigned cpu, char *out, size_t cap) { snprintf(out, cap, "0X%" PRIX64, mpidr[cpu]); }

/* ---- ids --------------------------------------------------------------------------------------------------- */

static int suite_ids(void)
{
    struct q1n1_payload_args a = args();
    fill_qemu();
    CHECK(go(&a, 2) == 0);
    CHECK(calls == 1 + 1 + FEATURES + CPUS + 1 && bad_calls == 0 && bad_lines == 0);
    unsigned seen_calls = 0;
    const void *site = NULL;
    unsigned features_seen = 0, cpus_seen = 0;
    for (unsigned i = 0; i < log_n; i++) {
        if (log_[i].kind != EV_CALL) continue;
        seen_calls++;
        uint64_t id = log_[i].id;
        /* One call site for every SMC. */
        if (!site) site = log_[i].site;
        CHECK(log_[i].site == site);
        CHECK(id == ID_PSCI_VERSION || id == ID_MIGRATE_INFO_TYPE || id == ID_PSCI_FEATURES || id == ID_AFFINITY_INFO ||
              id == ID_SMCCC_VERSION);
        for (unsigned k = 0; k < sizeof forbidden / sizeof forbidden[0]; k++) CHECK(id != forbidden[k]);
        if (id == ID_PSCI_FEATURES) {
            /* The argument is a function id of the table, in the table's order, once each: a query, not a call. */
            CHECK(features_seen < FEATURES && log_[i].x1 == feature_id[features_seen]);
            features_seen++;
            CHECK(log_[i].x2 == 0 && log_[i].x3 == 0);
        } else if (id == ID_AFFINITY_INFO) {
            CHECK(cpus_seen < CPUS && log_[i].x1 == mpidr[cpus_seen]);
            cpus_seen++;
            CHECK(log_[i].x2 == 0 && log_[i].x3 == 0);              /* lowest affinity level 0 */
        } else {
            CHECK(log_[i].x1 == 0 && log_[i].x2 == 0 && log_[i].x3 == 0);
        }
    }
    CHECK(seen_calls == calls && features_seen == FEATURES && cpus_seen == CPUS);
    /* The order of the groups: PSCI_VERSION and MIGRATE_INFO_TYPE, the ten queries, the twelve CPUs, SMCCC_VERSION last. */
    int v = call_index(ID_PSCI_VERSION, ~UINT64_C(0), -1), m = call_index(ID_MIGRATE_INFO_TYPE, ~UINT64_C(0), -1);
    int f0 = call_index(ID_PSCI_FEATURES, ~UINT64_C(0), -1), a0 = call_index(ID_AFFINITY_INFO, ~UINT64_C(0), -1);
    int s = call_index(ID_SMCCC_VERSION, ~UINT64_C(0), -1);
    CHECK(v == 1 + line_from("PAYLOAD PSCI NEXT VERSION", 0) && m > v && f0 > m && a0 > f0 && s > a0);
    CHECK(call_index(ID_SMCCC_VERSION, ~UINT64_C(0), s) < 0 && s > call_index(ID_AFFINITY_INFO, mpidr[CPUS - 1], -1));
    /* The ids that would change the machine do show up, as the argument of PSCI_FEATURES, and only there. */
    for (unsigned k = 0; k < FEATURES; k++) {
        int at = call_index(ID_PSCI_FEATURES, feature_id[k], -1);
        CHECK(at >= 0 && log_[at].id == ID_PSCI_FEATURES);
    }
    /* The payload reads CurrentEL and MPIDR_EL1 and nothing else. */
    CHECK(read_count == 2 && !strcmp(reads[0], "CurrentEL") && !strcmp(reads[1], "mpidr_el1"));
    return 0;
}

/* ---- el ----------------------------------------------------------------------------------------------------- */

static int suite_el(void)
{
    struct q1n1_payload_args a = args();
    fill_qemu();
    for (uint64_t el = 0; el <= 3; el++) {
        if (el == 2) continue;
        CHECK(go(&a, el) == 0);
        CHECK(calls == 0 && bad_calls == 0);                          /* no function id at all */
        CHECK(lines_n() == 1 && line_index("PAYLOAD PSCI SKIPPED_NOT_AT_EL2") == 0);
        CHECK(read_count == 1 && !strcmp(reads[0], "CurrentEL"));     /* not even MPIDR_EL1 */
    }
    CHECK(go(&a, 2) == 0 && calls == 25 && line_index("PAYLOAD PSCI SKIPPED_NOT_AT_EL2") < 0);
    return 0;
}

/* ---- next --------------------------------------------------------------------------------------------------- */

static int suite_next(void)
{
    struct q1n1_payload_args a = args();
    fill_qemu();
    CHECK(go(&a, 2) == 0);
    int mpidr_line = line_index("PAYLOAD PSCI MPIDR_EL1=0X80000000");
    int next_v = line_index("PAYLOAD PSCI NEXT VERSION"), next_f = line_index("PAYLOAD PSCI NEXT FEATURES");
    int next_a = line_index("PAYLOAD PSCI NEXT AFFINITY"), next_s = line_index("PAYLOAD PSCI NEXT SMCCC");
    CHECK(mpidr_line == 0 && next_v > mpidr_line && next_f > next_v && next_a > next_f && next_s > next_a);
    /* Exactly four NEXT lines, one per group. */
    unsigned nexts = 0;
    for (unsigned i = 0; i < log_n; i++) nexts += log_[i].kind == EV_LINE && !strncmp(log_[i].text, "PAYLOAD PSCI NEXT ", 18);
    CHECK(nexts == 4);
    /* The NEXT line is before the first call of its group... */
    int first_v = call_index(ID_PSCI_VERSION, ~UINT64_C(0), -1), first_f = call_index(ID_PSCI_FEATURES, ~UINT64_C(0), -1);
    int first_a = call_index(ID_AFFINITY_INFO, ~UINT64_C(0), -1), first_s = call_index(ID_SMCCC_VERSION, ~UINT64_C(0), -1);
    CHECK(next_v < first_v && next_f < first_f && next_a < first_a && next_s < first_s);
    /* ...and no call at all is made before the first NEXT line. */
    unsigned first_any = 0;
    while (first_any < log_n && log_[first_any].kind != EV_CALL) first_any++;
    CHECK(first_any < log_n && next_v < (int)first_any && (int)first_any == first_v);
    int last_m = call_index(ID_MIGRATE_INFO_TYPE, ~UINT64_C(0), -1), last_f = call_index(ID_PSCI_FEATURES, feature_id[FEATURES - 1], -1);
    int last_a = call_index(ID_AFFINITY_INFO, mpidr[CPUS - 1], -1);
    /* Each group's results are printed as soon as it is complete: after its last call and before the next group's NEXT. */
    int res_v = line_from("PAYLOAD PSCI VERSION ", 0), res_f = line_from("PAYLOAD PSCI FEATURES ", 0);
    int res_a = line_from("PAYLOAD PSCI AFFINITY ", 0), res_s = line_from("PAYLOAD PSCI SMCCC ", 0);
    CHECK(res_v > last_m && res_v < next_f);
    CHECK(res_f > last_f && res_f < next_a);
    CHECK(res_a > last_a && res_a < next_s);
    CHECK(res_s > first_s);
    /* The last line of the payload is the SMCCC result: nothing follows it. */
    CHECK(log_[log_n - 1].kind == EV_LINE && !strncmp(log_[log_n - 1].text, "PAYLOAD PSCI SMCCC ", 19));
    /* No result line precedes the calls it reports: no group is printed before its own calls ended. */
    CHECK(line_from("PAYLOAD PSCI VERSION ", 0) > first_v && line_from("PAYLOAD PSCI FEATURES ", 0) > first_f);
    /* Every line of the payload is a PAYLOAD PSCI line. */
    for (unsigned i = 0; i < log_n; i++) if (log_[i].kind == EV_LINE) CHECK(!strncmp(log_[i].text, "PAYLOAD PSCI ", 13));
    return 0;
}

/* ---- decode ------------------------------------------------------------------------------------------------- */

struct decode_case { uint64_t value; const char *want; };

/* Sets the reply of one call, runs the payload, returns the entry it printed for it. */
static const char *run_entry(const char *group, const char *key, char *out, size_t cap)
{
    struct q1n1_payload_args a = args();
    if (go(&a, 2) != 0) return NULL;
    return entry_of(group, key, out, cap);
}

static int check_cases(const char *group, const char *key, const struct decode_case *cases, unsigned n, void (*set)(uint64_t, unsigned),
                       unsigned index)
{
    for (unsigned i = 0; i < n; i++) {
        char entry[100], want[100];
        fill_qemu();
        set(cases[i].value, index);
        const char *got = run_entry(group, key, entry, sizeof entry);
        snprintf(want, sizeof want, "%s=%s", key, cases[i].want);
        if (!got || strcmp(got, want)) fprintf(stderr, "%s %s: got %s, want %s\n", group, key, got ? got : "(none)", want);
        CHECK(got && !strcmp(got, want));
        CHECK(bad_lines == 0 && bad_calls == 0);
    }
    return 0;
}
static void set_version(uint64_t v, unsigned i) { (void)i; sc.version = v; }
static void set_migrate(uint64_t v, unsigned i) { (void)i; sc.migrate = v; }
static void set_smccc(uint64_t v, unsigned i) { (void)i; sc.smccc = v; }
static void set_feature(uint64_t v, unsigned i) { sc.feature[i] = v; }
static void set_affinity(uint64_t v, unsigned i) { sc.affinity[i] = v; }

static int suite_decode(void)
{
    /* PSCI_VERSION and SMCCC_VERSION: SMC32, so the answer is w0 and the upper half of x0 is not looked at. */
    static const struct decode_case version[] = {
        {0x10001, "0X10001:V1.1"}, {0x10000, "0X10000:V1.0"}, {0x2, "0X2:V0.2"}, {0x10003, "0X10003:V1.3"},
        {0x0, "0X0:V0.0"}, {0x7fffffff, "0X7FFFFFFF:V32767.65535"}, {0xdead00010001, "0XDEAD00010001:V1.1"},
        {0xffffffff, "0XFFFFFFFF:NOT_SUPPORTED(-1)"}, {~UINT64_C(0), "0XFFFFFFFFFFFFFFFF:NOT_SUPPORTED(-1)"},
        {0xfffffffe, "0XFFFFFFFE:INVALID_PARAMETERS(-2)"}, {0xfffffffd, "0XFFFFFFFD:DENIED(-3)"},
        {0xfffffffc, "0XFFFFFFFC:ALREADY_ON(-4)"}, {0xfffffffb, "0XFFFFFFFB:ON_PENDING(-5)"},
        {0xfffffffa, "0XFFFFFFFA:INTERNAL_FAILURE(-6)"}, {0xfffffff9, "0XFFFFFFF9:NOT_PRESENT(-7)"},
        {0xfffffff8, "0XFFFFFFF8:DISABLED(-8)"}, {0xfffffff7, "0XFFFFFFF7:INVALID_ADDRESS(-9)"},
        {0xfffffff6, "0XFFFFFFF6"}, {0x80000000, "0X80000000"}, {0x80010001, "0X80010001"},
        {~UINT64_C(1), "0XFFFFFFFFFFFFFFFE:INVALID_PARAMETERS(-2)"}, {0x1ffffffff, "0X1FFFFFFFF:NOT_SUPPORTED(-1)"},
    };
    unsigned n = sizeof version / sizeof version[0];
    CHECK(!check_cases("VERSION", "PSCI_VERSION", version, n, set_version, 0));
    CHECK(!check_cases("SMCCC", "SMCCC_VERSION", version, n, set_smccc, 0));

    /* MIGRATE_INFO_TYPE: 0, 1 and 2 are the three kinds of Trusted OS; the rest is an error or not certain. */
    static const struct decode_case migrate[] = {
        {0, "0X0:TOS_UP_MIGRATE"}, {1, "0X1:TOS_UP_NO_MIGRATE"}, {2, "0X2:TOS_MP"}, {3, "0X3"}, {0x100, "0X100"},
        {0xffffffff, "0XFFFFFFFF:NOT_SUPPORTED(-1)"}, {~UINT64_C(0), "0XFFFFFFFFFFFFFFFF:NOT_SUPPORTED(-1)"},
        {0xfffffffd, "0XFFFFFFFD:DENIED(-3)"}, {0x100000002, "0X100000002:TOS_MP"},
        {0x7fffffffffffffff, "0X7FFFFFFFFFFFFFFF:NOT_SUPPORTED(-1)"},
    };
    CHECK(!check_cases("VERSION", "MIGRATE_INFO_TYPE", migrate, sizeof migrate / sizeof migrate[0], set_migrate, 0));

    /* PSCI_FEATURES, for every function of the table: flags are shown raw, errors by name. */
    static const struct decode_case feature[] = {
        {0, "0X0"}, {1, "0X1"}, {2, "0X2"}, {3, "0X3"}, {0x7fffffff, "0X7FFFFFFF"}, {0x80000000, "0X80000000"},
        {0xffffffff, "0XFFFFFFFF:NOT_SUPPORTED(-1)"}, {~UINT64_C(0), "0XFFFFFFFFFFFFFFFF:NOT_SUPPORTED(-1)"},
        {0xfffffffe, "0XFFFFFFFE:INVALID_PARAMETERS(-2)"}, {0xfffffffd, "0XFFFFFFFD:DENIED(-3)"},
        {0xfffffffc, "0XFFFFFFFC:ALREADY_ON(-4)"}, {0xfffffffb, "0XFFFFFFFB:ON_PENDING(-5)"},
        {0xfffffffa, "0XFFFFFFFA:INTERNAL_FAILURE(-6)"}, {0xfffffff9, "0XFFFFFFF9:NOT_PRESENT(-7)"},
        {0xfffffff8, "0XFFFFFFF8:DISABLED(-8)"}, {0xfffffff7, "0XFFFFFFF7:INVALID_ADDRESS(-9)"}, {0xfffffff6, "0XFFFFFFF6"},
        {~UINT64_C(8), "0XFFFFFFFFFFFFFFF7:INVALID_ADDRESS(-9)"}, {0x1fffffffe, "0X1FFFFFFFE:INVALID_PARAMETERS(-2)"},
    };
    for (unsigned i = 0; i < FEATURES; i++)
        CHECK(!check_cases("FEATURES", feature_name[i], feature, sizeof feature / sizeof feature[0], set_feature, i));

    /* AFFINITY_INFO, for every MPIDR: SMC64, so the answer is the whole of x0. 0 ON, 1 OFF, 2 ON_PENDING; the nine errors
     * as 64-bit values; a 32-bit error code without its sign extension is not one, and is shown raw. */
    static const struct decode_case affinity[] = {
        {0, "0X0:ON"}, {1, "0X1:OFF"}, {2, "0X2:ON_PENDING"}, {3, "0X3"}, {0x100000000, "0X100000000"},
        {~UINT64_C(0), "0XFFFFFFFFFFFFFFFF:NOT_SUPPORTED(-1)"}, {~UINT64_C(1), "0XFFFFFFFFFFFFFFFE:INVALID_PARAMETERS(-2)"},
        {~UINT64_C(2), "0XFFFFFFFFFFFFFFFD:DENIED(-3)"}, {~UINT64_C(3), "0XFFFFFFFFFFFFFFFC:ALREADY_ON(-4)"},
        {~UINT64_C(4), "0XFFFFFFFFFFFFFFFB:ON_PENDING(-5)"}, {~UINT64_C(5), "0XFFFFFFFFFFFFFFFA:INTERNAL_FAILURE(-6)"},
        {~UINT64_C(6), "0XFFFFFFFFFFFFFFF9:NOT_PRESENT(-7)"}, {~UINT64_C(7), "0XFFFFFFFFFFFFFFF8:DISABLED(-8)"},
        {~UINT64_C(8), "0XFFFFFFFFFFFFFFF7:INVALID_ADDRESS(-9)"}, {~UINT64_C(9), "0XFFFFFFFFFFFFFFF6"},
        {0xffffffff, "0XFFFFFFFF"}, {0xfffffffe, "0XFFFFFFFE"}, {0xffffffff00000001, "0XFFFFFFFF00000001"},
        {0x7fffffffffffffff, "0X7FFFFFFFFFFFFFFF"}, {0x8000000000000000, "0X8000000000000000"},
    };
    for (unsigned i = 0; i < CPUS; i++) {
        char key[24];
        key_of(i, key, sizeof key);
        CHECK(!check_cases("AFFINITY", key, affinity, sizeof affinity / sizeof affinity[0], set_affinity, i));
    }
    return 0;
}

/* ---- garbage ------------------------------------------------------------------------------------------------- */

static uint64_t rng = 0x9e3779b97f4a7c15ull;
static uint64_t next_random(void)
{
    rng ^= rng << 13; rng ^= rng >> 7; rng ^= rng << 17;
    return rng;
}

/* The raw value an entry shows, parsed from the hex after the first '=' and before any ':'. */
static int entry_raw(const char *entry, uint64_t *value)
{
    const char *p = strchr(entry, '=');
    if (!p || p[1] != '0' || p[2] != 'X') return 0;
    char *end;
    *value = strtoull(p + 3, &end, 16);
    return *end == 0 || *end == ':';
}

static int run_garbage(void)
{
    struct q1n1_payload_args a = args();
    CHECK(go(&a, 2) == 0);
    CHECK(bad_lines == 0 && bad_calls == 0 && calls == 25);
    CHECK(lines_n() >= 9 && lines_n() <= 30);                         /* 30 is the most there can be, 40 the ABI's */
    CHECK(entries_in("VERSION") == 2 && entries_in("FEATURES") == FEATURES && entries_in("AFFINITY") == CPUS &&
          entries_in("SMCCC") == 1);
    char entry[100];
    /* No entry is lost or cut: each shows the very value the SMC returned, and only a decode from the allowed words. */
    uint64_t raw;
    CHECK(entry_of("VERSION", "PSCI_VERSION", entry, sizeof entry) && entry_raw(entry, &raw) && raw == sc.version);
    CHECK(entry_of("VERSION", "MIGRATE_INFO_TYPE", entry, sizeof entry) && entry_raw(entry, &raw) && raw == sc.migrate);
    CHECK(entry_of("SMCCC", "SMCCC_VERSION", entry, sizeof entry) && entry_raw(entry, &raw) && raw == sc.smccc);
    for (unsigned i = 0; i < FEATURES; i++)
        CHECK(entry_of("FEATURES", feature_name[i], entry, sizeof entry) && entry_raw(entry, &raw) && raw == sc.feature[i]);
    for (unsigned i = 0; i < CPUS; i++) {
        char key[24];
        key_of(i, key, sizeof key);
        CHECK(entry_of("AFFINITY", key, entry, sizeof entry) && entry_raw(entry, &raw) && raw == sc.affinity[i]);
    }
    return 0;
}

static int suite_garbage(void)
{
    static const uint64_t fixed[] = {~UINT64_C(0), 0, 0x7fffffffffffffffull, 0x8000000000000000ull, 0xffffffff00000001ull,
                                     0x00000000ffffffffull, 1, 2, 0xfffffffeull, 0x4e4f545f49535345ull};
    for (unsigned i = 0; i < sizeof fixed / sizeof fixed[0]; i++) {
        fill_qemu();
        fill_all(fixed[i]);
        sc.other = fixed[i];
        CHECK(!run_garbage());
    }
    /* The most lines the payload can print: every answer an error name, which is the widest an entry gets. */
    fill_all(~UINT64_C(1));
    sc.version = sc.migrate = sc.smccc = 0xfffffffe;
    struct q1n1_payload_args a = args();
    CHECK(go(&a, 2) == 0 && lines_n() <= 30 && lines_n() > 20);
    /* Random answers per call: the same properties. */
    for (unsigned round = 0; round < 3000; round++) {
        fill_qemu();
        sc.version = next_random(); sc.migrate = next_random(); sc.smccc = next_random();
        for (unsigned i = 0; i < FEATURES; i++) sc.feature[i] = next_random() >> (next_random() & 63);
        for (unsigned i = 0; i < CPUS; i++) sc.affinity[i] = next_random() >> (next_random() & 63);
        sc.other = next_random();
        if (round % 3 == 0) for (unsigned i = 0; i < CPUS; i++) sc.affinity[i] = ~(next_random() % 12);
        if (round % 5 == 0) sc.version = (uint32_t)(0u - 1u - (unsigned)(next_random() % 10));
        CHECK(!run_garbage());
    }
    return 0;
}

/* ---- qemu ---------------------------------------------------------------------------------------------------- */

/* The lines of the QEMU run (docs/SP11-PAYLOAD.md; the QEMU test compares the same text). */
static const char *const qemu_lines[] = {
    "PAYLOAD PSCI MPIDR_EL1=0X80000000",
    "PAYLOAD PSCI NEXT VERSION",
    "PAYLOAD PSCI VERSION PSCI_VERSION=0X10001:V1.1 MIGRATE_INFO_TYPE=0X2:TOS_MP",
    "PAYLOAD PSCI NEXT FEATURES",
    "PAYLOAD PSCI FEATURES CPU_SUSPEND=0X0 CPU_OFF=0X0 CPU_ON=0X0 AFFINITY_INFO=0X0 MIGRATE_INFO_TYPE=0X0",
    "PAYLOAD PSCI FEATURES SYSTEM_OFF=0X0 SYSTEM_RESET=0X0 PSCI_FEATURES=0X0",
    "PAYLOAD PSCI FEATURES SYSTEM_SUSPEND=0XFFFFFFFFFFFFFFFF:NOT_SUPPORTED(-1)",
    "PAYLOAD PSCI FEATURES SYSTEM_RESET2=0XFFFFFFFFFFFFFFFF:NOT_SUPPORTED(-1)",
    "PAYLOAD PSCI NEXT AFFINITY",
    "PAYLOAD PSCI AFFINITY 0X0=0X0:ON 0X100=0XFFFFFFFFFFFFFFFE:INVALID_PARAMETERS(-2)",
    "PAYLOAD PSCI AFFINITY 0X200=0XFFFFFFFFFFFFFFFE:INVALID_PARAMETERS(-2)",
    "PAYLOAD PSCI AFFINITY 0X300=0XFFFFFFFFFFFFFFFE:INVALID_PARAMETERS(-2)",
    "PAYLOAD PSCI AFFINITY 0X10000=0XFFFFFFFFFFFFFFFE:INVALID_PARAMETERS(-2)",
    "PAYLOAD PSCI AFFINITY 0X10100=0XFFFFFFFFFFFFFFFE:INVALID_PARAMETERS(-2)",
    "PAYLOAD PSCI AFFINITY 0X10200=0XFFFFFFFFFFFFFFFE:INVALID_PARAMETERS(-2)",
    "PAYLOAD PSCI AFFINITY 0X10300=0XFFFFFFFFFFFFFFFE:INVALID_PARAMETERS(-2)",
    "PAYLOAD PSCI AFFINITY 0X20000=0XFFFFFFFFFFFFFFFE:INVALID_PARAMETERS(-2)",
    "PAYLOAD PSCI AFFINITY 0X20100=0XFFFFFFFFFFFFFFFE:INVALID_PARAMETERS(-2)",
    "PAYLOAD PSCI AFFINITY 0X20200=0XFFFFFFFFFFFFFFFE:INVALID_PARAMETERS(-2)",
    "PAYLOAD PSCI AFFINITY 0X20300=0XFFFFFFFFFFFFFFFE:INVALID_PARAMETERS(-2)",
    "PAYLOAD PSCI NEXT SMCCC",
    "PAYLOAD PSCI SMCCC SMCCC_VERSION=0XFFFFFFFFFFFFFFFF:NOT_SUPPORTED(-1)",
};

/* A firmware that answers as a PSCI 1.1 implementation with the boot CPU on and the others off might: invented
 * values, to show the compact form that a real answer takes (INFERRED, nothing measured). */
static const char *const plausible_lines[] = {
    "PAYLOAD PSCI MPIDR_EL1=0X80000000",
    "PAYLOAD PSCI NEXT VERSION",
    "PAYLOAD PSCI VERSION PSCI_VERSION=0X10001:V1.1 MIGRATE_INFO_TYPE=0X2:TOS_MP",
    "PAYLOAD PSCI NEXT FEATURES",
    "PAYLOAD PSCI FEATURES CPU_SUSPEND=0X2 CPU_OFF=0X0 CPU_ON=0X0 AFFINITY_INFO=0X0 MIGRATE_INFO_TYPE=0X0",
    "PAYLOAD PSCI FEATURES SYSTEM_OFF=0X0 SYSTEM_RESET=0X0 PSCI_FEATURES=0X0 SYSTEM_SUSPEND=0X0",
    "PAYLOAD PSCI FEATURES SYSTEM_RESET2=0X0",
    "PAYLOAD PSCI NEXT AFFINITY",
    "PAYLOAD PSCI AFFINITY 0X0=0X0:ON 0X100=0X1:OFF 0X200=0X1:OFF 0X300=0X1:OFF 0X10000=0X1:OFF",
    "PAYLOAD PSCI AFFINITY 0X10100=0X1:OFF 0X10200=0X1:OFF 0X10300=0X1:OFF 0X20000=0X1:OFF",
    "PAYLOAD PSCI AFFINITY 0X20100=0X1:OFF 0X20200=0X1:OFF 0X20300=0X1:OFF",
    "PAYLOAD PSCI NEXT SMCCC",
    "PAYLOAD PSCI SMCCC SMCCC_VERSION=0X10001:V1.1",
};

static int lines_are(const char *const want[], unsigned n)
{
    unsigned k = 0;
    for (unsigned i = 0; i < log_n; i++) {
        if (log_[i].kind != EV_LINE) continue;
        if (k >= n || strcmp(log_[i].text, want[k])) {
            fprintf(stderr, "line %u: '%s' != '%s'\n", k, log_[i].text, k < n ? want[k] : "(nothing)");
            return 0;
        }
        k++;
    }
    if (k != n) fprintf(stderr, "%u lines, wanted %u\n", k, n);
    return k == n;
}

static int suite_qemu(void)
{
    struct q1n1_payload_args a = args();
    fill_qemu();
    CHECK(go(&a, 2) == 0);
    CHECK(lines_are(qemu_lines, sizeof qemu_lines / sizeof qemu_lines[0]));
    CHECK(lines_n() == 22 && bad_lines == 0 && calls == 25);
    /* The same payload against answers a PSCI 1.1 firmware might give: entries pack five or six to a line. */
    memset(&sc, 0, sizeof sc);
    sc.version = 0x10001; sc.migrate = 2; sc.smccc = 0x10001;
    sc.feature[0] = 2;
    for (unsigned i = 0; i < CPUS; i++) sc.affinity[i] = i == 0 ? 0 : 1;
    CHECK(go(&a, 2) == 0);
    CHECK(lines_are(plausible_lines, sizeof plausible_lines / sizeof plausible_lines[0]));
    return 0;
}

/* ---- args ---------------------------------------------------------------------------------------------------- */

static int suite_args(void)
{
    struct q1n1_payload_args a;
    fill_qemu();
    CHECK(go(NULL, 2) == Q1N1_PAYLOAD_RET_BAD_ARGS && read_count == 0 && lines_n() == 0 && calls == 0);
    a = args(); a.magic ^= 1;
    CHECK(go(&a, 2) == Q1N1_PAYLOAD_RET_BAD_ARGS && read_count == 0 && lines_n() == 0 && calls == 0);
    a = args(); a.version = 2;
    CHECK(go(&a, 2) == Q1N1_PAYLOAD_RET_BAD_ARGS && calls == 0);
    a = args(); a.size = sizeof a - 1;
    CHECK(go(&a, 2) == Q1N1_PAYLOAD_RET_BAD_ARGS && calls == 0);
    a = args(); a.ops.puts = NULL;
    CHECK(go(&a, 2) == Q1N1_PAYLOAD_RET_BAD_ARGS && calls == 0);
    a = args(); a.ops.hex = NULL;
    CHECK(go(&a, 2) == Q1N1_PAYLOAD_RET_BAD_ARGS && calls == 0);
    /* A newer runner hands a bigger block: accepted. load32 and counter are not needed (a use would exit). */
    a = args(); a.size = sizeof a + 64; a.ops.load32 = NULL; a.ops.counter = NULL;
    CHECK(go(&a, 2) == 0 && calls == 25 && lines_n() == 22);
    return 0;
}

/* The number docs/SP11-PAYLOAD.md plans a chain's page with, measured rather than copied: the most lines this payload
 * prints over every EL, the widest answers there are (every answer one of the nine error names, as the 32-bit result of
 * an SMC32 call and as the 64-bit one) and thousands of random ones. Run as `lines-report`;
 * tools/test-q1n1-sp11-payload-chain.py compares the planning table of the document with its output. */
static int report_lines(void)
{
    struct q1n1_payload_args a = args();
    unsigned most = 0;
    for (uint64_t el = 0; el <= 3; el++) {
        fill_all(~UINT64_C(1));
        go(&a, el);
        if (lines_n() > most) most = lines_n();
    }
    for (unsigned code = 1; code <= 9; code++) {
        fill_all(-(uint64_t)code);
        go(&a, 2);
        if (lines_n() > most) most = lines_n();
        fill_all((uint32_t)-(int32_t)code);
        go(&a, 2);
        if (lines_n() > most) most = lines_n();
    }
    for (unsigned round = 0; round < 3000; round++) {
        sc.version = next_random(); sc.migrate = next_random(); sc.smccc = next_random();
        for (unsigned i = 0; i < FEATURES; i++) sc.feature[i] = next_random() >> (next_random() & 63);
        for (unsigned i = 0; i < CPUS; i++) sc.affinity[i] = next_random() >> (next_random() & 63);
        sc.other = next_random();
        go(&a, 2);
        if (lines_n() > most) most = lines_n();
    }
    printf("LINES_MAX=%u\n", most);
    return 0;
}

int main(int argc, char **argv)
{
    static const struct { const char *name; int (*run)(void); } suites[] = {
        {"ids", suite_ids}, {"el", suite_el}, {"next", suite_next}, {"decode", suite_decode}, {"garbage", suite_garbage},
        {"qemu", suite_qemu}, {"args", suite_args},
    };
    if (argc > 1 && !strcmp(argv[1], "lines-report")) return report_lines();
    unsigned ran = 0;
    for (unsigned i = 0; i < sizeof suites / sizeof suites[0]; i++) {
        if (argc > 1 && strcmp(argv[1], "all") && strcmp(argv[1], suites[i].name)) continue;
        if (suites[i].run()) { fprintf(stderr, "FAIL: suite %s\n", suites[i].name); return 1; }
        ran++;
    }
    printf("PASS: %u payload psci suites, %u checks\n", ran, checks);
    return 0;
}
