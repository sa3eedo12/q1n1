/* SPDX-License-Identifier: MIT */
/* Test fixture of tools/test-q1n1-sp11-payload-qemu-xhci.py, never installed on a stick and never shipped. Under QEMU's EDK2 the firmware's xHCI
 * driver gives the controller's PCI attributes back at ExitBootServices (memory decode off), so that a read of its BAR returns all ones. This
 * fixture reads the command register and the BAR of 00:01.0 through the ECAM (the virt machine's high window at 0x4010000000, which EDK2 uses
 * when the machine has high memory), turns on memory space and bus master (the only stores of the file: the xhci payload has none to a PCI
 * device), reads the register back, and reads the first word of the BAR. It stores nothing unless the vendor and device are the qemu-xhci's.
 * The xhci payload then runs as the second payload of the same stick. */
#include "payload-util.h"

#define ECAM_00_01_0 UINT64_C(0x4010008000)
#define PREFIX "PAYLOAD XHCIQ "
#define QEMU_XHCI_ID 0x000D1B36u

static uint32_t read_word(const struct q1n1_payload_args *a, uint64_t address)
{
    uint32_t word = 0xDEAD0000u;
    if (a->ops.load32(address, &word)) return 0xDEADBEEFu;
    return word;
}

uint64_t payload_entry(const struct q1n1_payload_args *a);
uint64_t payload_entry(const struct q1n1_payload_args *a)
{
    uint64_t bar0;
    uint32_t command, id;
    if (!pl_args_ok(a)) return Q1N1_PAYLOAD_RET_BAD_ARGS;
    id = read_word(a, ECAM_00_01_0);
    pl_keyed_hex(a, PREFIX, "ID", id);
    if (id != QEMU_XHCI_ID) return 2;
    command = read_word(a, ECAM_00_01_0 + 4);
    bar0 = (uint64_t)(read_word(a, ECAM_00_01_0 + 0x10) & ~0xfu) | (uint64_t)read_word(a, ECAM_00_01_0 + 0x14) << 32;
    pl_keyed_hex(a, PREFIX, "CMD_BEFORE", command & 0xffffu);
    pl_keyed_hex(a, PREFIX, "BAR0", bar0);
    pl_keyed_hex(a, PREFIX, "CAP0_BEFORE", bar0 ? read_word(a, bar0) : 0);
    *(volatile uint32_t *)(uintptr_t)(ECAM_00_01_0 + 4) = (command & 0xffffu) | 6u;
    pl_keyed_hex(a, PREFIX, "CMD_AFTER", read_word(a, ECAM_00_01_0 + 4) & 0xffffu);
    pl_keyed_hex(a, PREFIX, "CAP0_AFTER", bar0 ? read_word(a, bar0) : 0);
    return 0;
}
