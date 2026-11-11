/* SPDX-License-Identifier: MIT */
/* TEST FIXTURE ONLY. Not a Surface Pro 11 fact and not generated from any descriptor: the bases are invented, chosen
 * so that they are nobody's hardware. tools/test-q1n1-sp11-usb-ports.py uses it to prove that the SP11=1 build wiring
 * (platform/uefi/Makefile) compiles and links. A real build passes the file written by Snapintosh's
 * tools/sp11_usb_ports.py emit-c instead. */
#include "sp11-usb-ports.h"

static const struct q1n1_sp11_usb_table table = {
    .magic = Q1N1_SP11_USB_MAGIC, .version = Q1N1_SP11_USB_VERSION, .count = 2,
    .port = {{.dwc3_base = UINT64_C(0x0c000000), .window_size = 0xfd000u, .qscratch_offset = 0xf8800u,
              .flags = Q1N1_SP11_USB_PORT_HOST_ONLY},
             {.dwc3_base = UINT64_C(0x0c200000), .window_size = 0xfd000u, .qscratch_offset = 0xf8800u,
              .flags = Q1N1_SP11_USB_PORT_HOST_ONLY}}};

const struct q1n1_sp11_usb_table *q1n1_sp11_usb_table_get(void) { return &table; }
