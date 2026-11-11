/* SPDX-License-Identifier: MIT */
/* Validator harness for the Surface Pro 11 USB table (platform/uefi/sp11-usb-ports.c). Built with
 * -DSNAP_PLATFORM_SP11=1 by tools/test-q1n1-sp11-usb-ports.py and by Snapintosh's tools/test-sp11-usb-ports.py.
 *
 *   emitted      validate the table a generated C file (sp11_usb_ports.py emit-c) links in; print its fields
 *   batch        one table per stdin line, thirteen hex numbers: magic version count, then base window qscratch gsnpsid
 *                flags for each of the two entries; print the verdict name per line
 *   controller   one candidate per stdin line: expect_gsnpsid gsnpsid cap_dword hcsparams1 (hex); print the verdict
 *   self         hand-written valid and faulty tables with the verdicts they must get; exits non-zero on a mismatch
 *
 * The linked-in table getter is supplied by the generated file (emitted) or by the harness itself (self). */
#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include "sp11-usb-ports.h"

#ifdef SP11_HARNESS_OWN_TABLE
static const struct q1n1_sp11_usb_table fixture = {
    .magic = Q1N1_SP11_USB_MAGIC, .version = Q1N1_SP11_USB_VERSION, .count = 2,
    .port = {{.dwc3_base = UINT64_C(0x0c000000), .window_size = 0xfd000u, .qscratch_offset = 0xf8800u,
              .flags = Q1N1_SP11_USB_PORT_HOST_ONLY},
             {.dwc3_base = UINT64_C(0x0c200000), .window_size = 0xfd000u, .qscratch_offset = 0xf8800u,
              .flags = Q1N1_SP11_USB_PORT_HOST_ONLY}}};
const struct q1n1_sp11_usb_table *q1n1_sp11_usb_table_get(void) { return &fixture; }
#endif

static const char *controller_name(int code)
{
    static const char *const names[] = {"OK", "FAMILY", "CAPLENGTH", "HCIVERSION", "MAXPORTS"};
    return code >= 0 && code <= Q1N1_SP11_USB_ID_MAXPORTS ? names[code] : "UNKNOWN";
}

static int emitted(void)
{
    const struct q1n1_sp11_usb_table *t = q1n1_sp11_usb_table_get();
    int verdict = q1n1_sp11_usb_table_validate(t);
    printf("%s\n", q1n1_sp11_usb_error_name(verdict));
    if (!t) return 1;
    printf("count %" PRIu32 "\n", t->count);
    for (uint32_t i = 0; i < Q1N1_SP11_USB_MAX_PORTS; i++)
        printf("port %" PRIu32 " base 0x%" PRIx64 " window 0x%" PRIx32 " qscratch 0x%" PRIx32 " gsnpsid 0x%" PRIx32
               " flags 0x%" PRIx32 "\n",
               i, t->port[i].dwc3_base, t->port[i].window_size, t->port[i].qscratch_offset, t->port[i].expect_gsnpsid,
               t->port[i].flags);
    return verdict != Q1N1_SP11_USB_OK;
}

static int batch(void)
{
    char line[512];
    while (fgets(line, sizeof(line), stdin)) {
        uint64_t v[13];
        if (sscanf(line, "%" SCNx64 " %" SCNx64 " %" SCNx64 " %" SCNx64 " %" SCNx64 " %" SCNx64 " %" SCNx64 " %" SCNx64
                         " %" SCNx64 " %" SCNx64 " %" SCNx64 " %" SCNx64 " %" SCNx64,
                   &v[0], &v[1], &v[2], &v[3], &v[4], &v[5], &v[6], &v[7], &v[8], &v[9], &v[10], &v[11], &v[12]) != 13) {
            printf("BAD-INPUT\n");
            continue;
        }
        struct q1n1_sp11_usb_table t;
        memset(&t, 0, sizeof(t));
        t.magic = v[0]; t.version = (uint32_t)v[1]; t.count = (uint32_t)v[2];
        for (unsigned i = 0; i < 2; i++) {
            t.port[i].dwc3_base = v[3 + 5 * i];
            t.port[i].window_size = (uint32_t)v[4 + 5 * i];
            t.port[i].qscratch_offset = (uint32_t)v[5 + 5 * i];
            t.port[i].expect_gsnpsid = (uint32_t)v[6 + 5 * i];
            t.port[i].flags = (uint32_t)v[7 + 5 * i];
        }
        printf("%s\n", q1n1_sp11_usb_error_name(q1n1_sp11_usb_table_validate(&t)));
    }
    return 0;
}

static int controller(void)
{
    char line[256];
    while (fgets(line, sizeof(line), stdin)) {
        uint32_t expect, id, cap, hcs1;
        struct q1n1_sp11_usb_port p;
        memset(&p, 0, sizeof(p));
        if (sscanf(line, "%" SCNx32 " %" SCNx32 " %" SCNx32 " %" SCNx32, &expect, &id, &cap, &hcs1) != 4) {
            printf("BAD-INPUT\n");
            continue;
        }
        p.expect_gsnpsid = expect;
        printf("%s\n", controller_name(q1n1_sp11_usb_controller_ok(&p, id, cap, hcs1)));
    }
    return 0;
}

#ifdef SP11_HARNESS_OWN_TABLE
static unsigned checks;
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #x); return 1; } checks++; } while (0)

static struct q1n1_sp11_usb_table good(void)
{
    struct q1n1_sp11_usb_table t = fixture;
    return t;
}

static int self(void)
{
    struct q1n1_sp11_usb_table t;
    CHECK(q1n1_sp11_usb_table_validate(0) == Q1N1_SP11_USB_ERR_NULL);
    t = good(); CHECK(q1n1_sp11_usb_table_validate(&t) == Q1N1_SP11_USB_OK);
    t = good(); t.magic ^= 1; CHECK(q1n1_sp11_usb_table_validate(&t) == Q1N1_SP11_USB_ERR_MAGIC);
    t = good(); t.version = 2; CHECK(q1n1_sp11_usb_table_validate(&t) == Q1N1_SP11_USB_ERR_VERSION);
    t = good(); t.count = 0; CHECK(q1n1_sp11_usb_table_validate(&t) == Q1N1_SP11_USB_ERR_COUNT);
    t = good(); t.count = 3; CHECK(q1n1_sp11_usb_table_validate(&t) == Q1N1_SP11_USB_ERR_COUNT);
    t = good(); t.count = 1; CHECK(q1n1_sp11_usb_table_validate(&t) == Q1N1_SP11_USB_ERR_RESERVED);
    t = good(); t.count = 1; memset(&t.port[1], 0, sizeof(t.port[1])); CHECK(q1n1_sp11_usb_table_validate(&t) == Q1N1_SP11_USB_OK);
    t = good(); t.port[0].flags |= 4; CHECK(q1n1_sp11_usb_table_validate(&t) == Q1N1_SP11_USB_ERR_FLAGS);
    t = good(); t.port[0].dwc3_base = 0; CHECK(q1n1_sp11_usb_table_validate(&t) == Q1N1_SP11_USB_ERR_BASE);
    t = good(); t.port[1].dwc3_base += 0x10; CHECK(q1n1_sp11_usb_table_validate(&t) == Q1N1_SP11_USB_ERR_BASE);
    t = good(); t.port[0].window_size = 0; CHECK(q1n1_sp11_usb_table_validate(&t) == Q1N1_SP11_USB_ERR_WINDOW);
    t = good(); t.port[0].window_size = 0xfd100; CHECK(q1n1_sp11_usb_table_validate(&t) == Q1N1_SP11_USB_ERR_WINDOW);
    t = good(); t.port[0].window_size = 0x201000; CHECK(q1n1_sp11_usb_table_validate(&t) == Q1N1_SP11_USB_ERR_WINDOW);
    t = good(); t.port[0].dwc3_base = UINT64_C(1) << 36; CHECK(q1n1_sp11_usb_table_validate(&t) == Q1N1_SP11_USB_ERR_LIMIT);
    t = good(); t.port[0].dwc3_base = (UINT64_C(1) << 36) - 0x1000; t.port[0].window_size = 0x1000;
    t.port[0].qscratch_offset = 0xf8800; CHECK(q1n1_sp11_usb_table_validate(&t) == Q1N1_SP11_USB_ERR_LIMIT);
    t = good(); t.port[0].qscratch_offset = 0xf8802; CHECK(q1n1_sp11_usb_table_validate(&t) == Q1N1_SP11_USB_ERR_QSCRATCH);
    t = good(); t.port[0].qscratch_offset = 0x1000; CHECK(q1n1_sp11_usb_table_validate(&t) == Q1N1_SP11_USB_ERR_QSCRATCH);
    t = good(); t.port[0].qscratch_offset = 0xfd000; CHECK(q1n1_sp11_usb_table_validate(&t) == Q1N1_SP11_USB_ERR_QSCRATCH);
    t = good(); t.port[0].window_size = 0x1000; t.port[0].qscratch_offset = 0;
    CHECK(q1n1_sp11_usb_table_validate(&t) == Q1N1_SP11_USB_ERR_QSCRATCH);
    t = good(); t.port[0].expect_gsnpsid = 0x12340000; CHECK(q1n1_sp11_usb_table_validate(&t) == Q1N1_SP11_USB_ERR_IDENTITY);
    t = good(); t.port[0].expect_gsnpsid = 0x33313130; CHECK(q1n1_sp11_usb_table_validate(&t) == Q1N1_SP11_USB_OK);
    t = good(); t.port[0].dwc3_base = UINT64_C(0x0a600000); CHECK(q1n1_sp11_usb_table_validate(&t) == Q1N1_SP11_USB_ERR_A16_BASE);
    t = good(); t.port[1].dwc3_base = UINT64_C(0x0a800000); CHECK(q1n1_sp11_usb_table_validate(&t) == Q1N1_SP11_USB_ERR_A16_BASE);
    t = good(); t.port[0].dwc3_base = UINT64_C(0x0a600000); t.port[0].flags |= Q1N1_SP11_USB_PORT_A16_BASE_LISTED;
    CHECK(q1n1_sp11_usb_table_validate(&t) == Q1N1_SP11_USB_OK);
    t = good(); t.port[1].dwc3_base = t.port[0].dwc3_base + 0x80000; CHECK(q1n1_sp11_usb_table_validate(&t) == Q1N1_SP11_USB_ERR_OVERLAP);
    t = good(); t.port[1] = t.port[0]; CHECK(q1n1_sp11_usb_table_validate(&t) == Q1N1_SP11_USB_ERR_OVERLAP);
    CHECK(!strcmp(q1n1_sp11_usb_error_name(Q1N1_SP11_USB_ERR_COUNT_ALL), "UNKNOWN"));
    CHECK(!strcmp(q1n1_sp11_usb_error_name(-1), "UNKNOWN"));

    const struct q1n1_sp11_usb_table *g = &fixture;
    CHECK(q1n1_sp11_usb_port_for_base(g, 0x0c200000) == &g->port[1]);
    CHECK(q1n1_sp11_usb_port_for_base(g, 0x0a600000) == 0);
    CHECK(q1n1_sp11_usb_port_for_base(0, 0x0c200000) == 0);
    const struct q1n1_sp11_usb_port *p = &g->port[0];
    CHECK(q1n1_sp11_usb_controller_ok(p, 0x5533330a, 0x01100020, 0x02000040) == Q1N1_SP11_USB_ID_OK);
    CHECK(q1n1_sp11_usb_controller_ok(p, 0x33313130, 0x01200030, 0x02000040) == Q1N1_SP11_USB_ID_OK);
    CHECK(q1n1_sp11_usb_controller_ok(p, 0x12345678, 0x01100020, 0x02000040) == Q1N1_SP11_USB_ID_FAMILY);
    CHECK(q1n1_sp11_usb_controller_ok(p, 0, 0x01100020, 0x02000040) == Q1N1_SP11_USB_ID_FAMILY);
    CHECK(q1n1_sp11_usb_controller_ok(p, 0xffffffff, 0xffffffff, 0xffffffff) == Q1N1_SP11_USB_ID_FAMILY);
    CHECK(q1n1_sp11_usb_controller_ok(p, 0x5533330a, 0x0110001c, 0x02000040) == Q1N1_SP11_USB_ID_CAPLENGTH);
    CHECK(q1n1_sp11_usb_controller_ok(p, 0x5533330a, 0x01100022, 0x02000040) == Q1N1_SP11_USB_ID_CAPLENGTH);
    CHECK(q1n1_sp11_usb_controller_ok(p, 0x5533330a, 0x00ff0020, 0x02000040) == Q1N1_SP11_USB_ID_HCIVERSION);
    CHECK(q1n1_sp11_usb_controller_ok(p, 0x5533330a, 0x02000020, 0x02000040) == Q1N1_SP11_USB_ID_HCIVERSION);
    CHECK(q1n1_sp11_usb_controller_ok(p, 0x5533330a, 0x01100020, 0x00000040) == Q1N1_SP11_USB_ID_MAXPORTS);
    CHECK(q1n1_sp11_usb_controller_ok(p, 0x5533330a, 0x01100020, 0x11000040) == Q1N1_SP11_USB_ID_MAXPORTS);
    CHECK(q1n1_sp11_usb_controller_ok(0, 0x5533330a, 0x01100020, 0x02000040) == Q1N1_SP11_USB_ID_FAMILY);
    struct q1n1_sp11_usb_port exact = {.expect_gsnpsid = 0x33313130};
    CHECK(q1n1_sp11_usb_controller_ok(&exact, 0x33313130, 0x01100020, 0x02000040) == Q1N1_SP11_USB_ID_OK);
    CHECK(q1n1_sp11_usb_controller_ok(&exact, 0x33313131, 0x01100020, 0x02000040) == Q1N1_SP11_USB_ID_FAMILY);
    CHECK(q1n1_sp11_usb_controller_ok(&exact, 0x5533330a, 0x01100020, 0x02000040) == Q1N1_SP11_USB_ID_FAMILY);
    printf("PASS %u SP11 table and controller checks\n", checks);
    return 0;
}
#endif

int main(int argc, char **argv)
{
    if (argc == 2 && !strcmp(argv[1], "emitted")) return emitted();
    if (argc == 2 && !strcmp(argv[1], "batch")) return batch();
    if (argc == 2 && !strcmp(argv[1], "controller")) return controller();
#ifdef SP11_HARNESS_OWN_TABLE
    if (argc == 2 && !strcmp(argv[1], "self")) return self();
#endif
    fprintf(stderr, "usage: test-q1n1-sp11-table emitted|batch|controller|self\n");
    return 2;
}
