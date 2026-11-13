/* SPDX-License-Identifier: MIT */
/* The UEFI protocol layouts the survey's P2 queries use, and nothing else (efi.h has none of them).
 * Every field the code reads is either named here with its offset pinned by _Static_assert against the
 * UEFI 2.x specification's own layout, or is a byte offset into a descriptor whose layout is the USB
 * specification's. Function pointers the survey never calls stay `void *`: the table has to keep its
 * shape, not its types.
 *
 * Only compiled into the survey build (Q1N1_SP11_STK_SURVEY); the default build does not see it. */
#pragma once
#include "efi.h"
#include "sp11-stk-survey.h"

#if Q1N1_SP11_STK_SURVEY

#define STK_GUID_DEVICE_PATH {0x09576e91, 0x6d3f, 0x11d2, {0x8e, 0x39, 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b}}
#define STK_GUID_BLOCK_IO {0x964e5b21, 0x6459, 0x11d2, {0x8e, 0x39, 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b}}
#define STK_GUID_USB_IO {0x2b2f68d6, 0x0cd2, 0x44cf, {0x8e, 0x8b, 0xbb, 0xa2, 0x0b, 0x1b, 0x5b, 0x75}}
#define STK_GUID_USB2_HC {0x3e745226, 0x9818, 0x45b6, {0xa2, 0xac, 0xd7, 0xcd, 0x0e, 0x8b, 0xa2, 0xbc}}
#define STK_GUID_PCI_IO {0x4cf5b200, 0x68b8, 0x4ca5, {0x9e, 0xec, 0xb2, 0x3e, 0x3f, 0x50, 0x02, 0x9a}}
#define STK_GUID_LOADED_IMAGE {0x5b1b31a1, 0x9562, 0x11d2, {0x8e, 0x3f, 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b}}

/* EFI_BLOCK_IO_PROTOCOL (UEFI 2.x 13.7) and its media. */
struct stk_efi_block_io_media {
    uint32_t media_id;
    uint8_t removable, present, logical_partition, read_only, write_caching;
    uint32_t block_size, io_align;
    uint64_t last_block;
};
struct stk_efi_block_io {
    uint64_t revision;
    const struct stk_efi_block_io_media *media;
    void *reset, *read_blocks, *write_blocks, *flush_blocks;
};
_Static_assert(offsetof(struct stk_efi_block_io, media) == 8, "UEFI BlockIo.Media");
_Static_assert(offsetof(struct stk_efi_block_io_media, removable) == 4, "UEFI BlockIoMedia.RemovableMedia");
_Static_assert(offsetof(struct stk_efi_block_io_media, logical_partition) == 6, "UEFI BlockIoMedia.LogicalPartition");
_Static_assert(offsetof(struct stk_efi_block_io_media, read_only) == 7, "UEFI BlockIoMedia.ReadOnly");
_Static_assert(offsetof(struct stk_efi_block_io_media, block_size) == 12, "UEFI BlockIoMedia.BlockSize");
_Static_assert(offsetof(struct stk_efi_block_io_media, last_block) == 24, "UEFI BlockIoMedia.LastBlock");

/* EFI_USB_IO_PROTOCOL (UEFI 2.x 17.2): thirteen members after the three transfer groups. The device,
 * interface and endpoint descriptors come back as the USB specification lays them out, in caches the
 * USB bus driver filled when it enumerated the device: no transfer is made to answer these calls. */
struct stk_efi_usb_io;
struct stk_efi_usb_io {
    void *control_transfer, *bulk_transfer, *async_interrupt_transfer, *sync_interrupt_transfer;
    void *isochronous_transfer, *async_isochronous_transfer;
    efi_status (*get_device_descriptor)(struct stk_efi_usb_io *, uint8_t *descriptor);
    void *get_config_descriptor;
    efi_status (*get_interface_descriptor)(struct stk_efi_usb_io *, uint8_t *descriptor);
    efi_status (*get_endpoint_descriptor)(struct stk_efi_usb_io *, uint8_t index, uint8_t *descriptor);
    void *get_string_descriptor, *get_supported_languages, *port_reset;
};
_Static_assert(offsetof(struct stk_efi_usb_io, get_device_descriptor) == 48, "UEFI UsbIo.UsbGetDeviceDescriptor");
_Static_assert(offsetof(struct stk_efi_usb_io, get_interface_descriptor) == 64, "UEFI UsbIo.UsbGetInterfaceDescriptor");
_Static_assert(offsetof(struct stk_efi_usb_io, get_endpoint_descriptor) == 72, "UEFI UsbIo.UsbGetEndpointDescriptor");
_Static_assert(offsetof(struct stk_efi_usb_io, port_reset) == 96, "UEFI UsbIo.UsbPortReset");

/* USB descriptor sizes and the offsets of the fields read. The device descriptor also holds the
 * vendor and product ids and the string indexes of the serial number: only bcdUSB is taken from it. */
#define STK_USB_DEVICE_DESC_BYTES 18u
#define STK_USB_BCD_USB 2u
#define STK_USB_INTERFACE_DESC_BYTES 9u
#define STK_USB_IF_NUM_ENDPOINTS 4u
#define STK_USB_IF_CLASS 5u
#define STK_USB_IF_SUBCLASS 6u
#define STK_USB_IF_PROTOCOL 7u
#define STK_USB_ENDPOINT_DESC_BYTES 7u
#define STK_USB_EP_ADDRESS 2u
#define STK_USB_EP_ATTRIBUTES 3u
#define STK_USB_EP_MAX_PACKET 4u
#define STK_USB_EP_BULK 2u
#define STK_USB_EP_DIR_IN 0x80u
#define STK_USB_EP_INDEX_MAX 16u

/* EFI_PCI_IO_PROTOCOL (UEFI 2.x 14.4). Widths: 0 is Uint8, 2 is Uint32. */
#define STK_PCI_WIDTH_UINT8 0u
#define STK_PCI_WIDTH_UINT32 2u
struct stk_efi_pci_io;
struct stk_efi_pci_io {
    void *poll_mem, *poll_io;
    struct {
        efi_status (*read)(struct stk_efi_pci_io *, uint32_t width, uint8_t bar, uint64_t offset, uint64_t count,
                           void *buffer);
        void *write;
    } mem;
    struct { void *read, *write; } io;
    struct {
        efi_status (*read)(struct stk_efi_pci_io *, uint32_t width, uint32_t offset, uint64_t count, void *buffer);
        void *write;
    } pci;
    void *copy_mem, *map, *unmap, *allocate_buffer, *free_buffer, *flush;
    efi_status (*get_location)(struct stk_efi_pci_io *, uint64_t *segment, uint64_t *bus, uint64_t *device,
                               uint64_t *function);
    void *attributes;
    efi_status (*get_bar_attributes)(struct stk_efi_pci_io *, uint8_t bar, uint64_t *supports, void **resources);
    void *set_bar_attributes;
    uint64_t rom_size;
    void *rom_image;
};
_Static_assert(offsetof(struct stk_efi_pci_io, mem) == 16, "UEFI PciIo.Mem");
_Static_assert(offsetof(struct stk_efi_pci_io, pci) == 48, "UEFI PciIo.Pci");
_Static_assert(offsetof(struct stk_efi_pci_io, get_location) == 112, "UEFI PciIo.GetLocation");
_Static_assert(offsetof(struct stk_efi_pci_io, get_bar_attributes) == 128, "UEFI PciIo.GetBarAttributes");
_Static_assert(offsetof(struct stk_efi_pci_io, rom_image) == 152, "UEFI PciIo.RomImage");

/* PCI configuration space: class code bytes (programming interface, sub class, base class) from 0x09
 * and the first two base address registers from 0x10 (PCI Local Bus Specification). */
#define STK_PCI_CLASSCODE 0x09u
#define STK_PCI_BAR0 0x10u

/* The ACPI QWORD address space descriptor GetBarAttributes returns: tag 0x8a, then a resource type
 * byte, two flag bytes and five 64-bit fields. Only the minimum address is read. */
#define STK_ACPI_QWORD_TAG 0x8au
#define STK_ACPI_QWORD_MIN 14u
#define STK_ACPI_QWORD_BYTES 46u

/* BootServices.LocateDevicePath is `void *` in efi.h (nothing else calls it): its type, UEFI 2.x 7.3. */
typedef efi_status (*stk_efi_locate_device_path_fn)(efi_guid *protocol, const uint8_t **path, efi_handle *device);
_Static_assert(offsetof(struct efi_boot_services, locate_device_path) == 184, "UEFI LocateDevicePath ABI");

/* The P2 query set. Collects the facts, prints the Appendix A P2 lines through `console` (one line per
 * call, no terminator) as it goes, and keeps them in `out` for the EL2 page. Every protocol call is
 * made here, before the last GetMemoryMap that precedes ExitBootServices: it must not run after it,
 * and it allocates only inside firmware calls that are made before that map is taken (the one pool
 * buffer GetBarAttributes may return is freed again before this function returns). Loads only. */
void stk_p2_collect(struct efi_system_table *st, efi_handle image_handle, const char *stamp, struct stk_p2 *out,
                    void (*console)(void *ctx, const char *line), void *console_ctx);

#endif /* Q1N1_SP11_STK_SURVEY */
