/* SPDX-License-Identifier: MIT */
/* Shared, byte-identical copy kept in two repositories: the Snapintosh SP11 fork of slbounce
 * (here, src/sp11-ebs-ranges.h) and the Snapintosh SP11 fork of q1n1 (platform/uefi/sp11-ebs-ranges.h).
 * Keep both copies textually identical; bump SP11_EBS_RANGES_VERSION on any layout change and update
 * both at once. This is the same convention the Snapintosh repository already uses for the NV2
 * functional-test record (tools/nv2_record.py / compat/nv2-gate.h there): one versioned, checksummed,
 * fixed wire layout understood independently by code in two places that share no build system, rather
 * than a struct declared once and included by both (there is no such shared build here either).
 *
 * q1n1, built with SNAP_PLATFORM_SP11=1, writes one of these tables into a volatile UEFI variable
 * (EFI_VARIABLE_BOOTSERVICE_ACCESS, exactly as platform/uefi/usb-ebs.h already does for its own
 * prep/takeover hand-off) before calling BS->ExitBootServices(), listing the physical ranges it has
 * itself written since boot -- the same seven ranges its own gpu_setup() already excludes from a GPU
 * DMA claim for an unrelated reason (q1n1 platform/uefi/main.c, the pinned commit this design reads:
 * its own loaded image, heap, DMA arena, stage slots, the memory-map buffer, the preload table and
 * the framebuffer). docs/SP11-Q1N1-BOOT-STUDY.md section 4.2's own prose names the seventh entry "the
 * GPU arena"; the array gpu_setup() actually builds is the framebuffer (fb_base/fb_size), not
 * gpu_arena_base/gpu_arena_size -- this header follows the array q1n1 actually builds, not the
 * study's prose. See this patch's REPORT.md for the full note.
 *
 * The Snapintosh SP11 fork of slbounce (src/bounce_main.c, SLBOUNCE_SCOPED_SWEEP) reads the same
 * variable, by the same name and GUID, from inside its own BS->ExitBootServices hook -- boot services
 * are still available there, before the hook calls the real ExitBootServices (docs/SP11-Q1N1-BOOT-
 * STUDY.md section 5.1) -- and refuses outright (returns an error from the hook) rather than widen or
 * guess at an absent or malformed table. q1n1's own leave_firmware() already treats a failing
 * ExitBootServices as fail-closed (G02/the existing "EXITBOOTSERVICES FAILED" halt page, no reset),
 * so a refusal here reaches an already-correct, already-reviewed failure path with no new q1n1-side
 * handling required for this specific case.
 *
 * Deliberately pure <stdint.h>: no EFI_GUID/efi_guid type is named here, because the two trees define
 * that type independently (gnu-efi's EFI_GUID in slbounce, q1n1's own efi_guid in platform/uefi/efi.h)
 * with the identical field layout (UINT32/uint32_t; UINT16/uint16_t; UINT16/uint16_t; UINT8[8]/
 * uint8_t[8]) but different names, so each tree wraps SP11_EBS_RANGES_GUID_INIT in its own local
 * literal of its own type instead of this header assuming either one. The validation function below
 * is `static inline` and self-contained (no allocation, no I/O) precisely so the *behaviour*, not only
 * the layout, is shared by copying this one file -- stronger than two independently written
 * validators that merely agree on layout. */
#ifndef SP11_EBS_RANGES_H
#define SP11_EBS_RANGES_H

#include <stddef.h>
#include <stdint.h>

/* "SP11EBS1" read byte 0 (lowest) to byte 7 (highest) of the little-endian value, the same
 * byte-ordering convention as q1n1's own USB_EBS_MAGIC ("1N1EBS01", usb-ebs.h) and bootinfo magic
 * ("Q1N1INFO", q1n1-bootinfo.h). */
#define SP11_EBS_RANGES_MAGIC UINT64_C(0x3153424531315053)
#define SP11_EBS_RANGES_VERSION 1u
/* >= the 7 ranges q1n1's gpu_setup() already enumerates (F14), with one spare slot for a future
 * addition without a version bump; unused slots at and after `count` must be all zero. */
#define SP11_EBS_MAX_RANGES 8u

/* A fixed, arbitrary local identifier -- not an authority-issued UUID, matching usb_ebs_guid's own
 * convention in platform/uefi/usb-ebs.h. */
#define SP11_EBS_RANGES_GUID_INIT \
    { 0x1a3c9e02, 0x7b6f, 0x4d81, { 0x9c, 0x2e, 0x53, 0x50, 0x31, 0x31, 0x45, 0x52 } }
/* u"Q1N1Sp11EbsRanges" spelled out as a plain uint16_t array, so neither tree's own CHAR16/char16
 * type needs to be named here either; each tree casts or copies this into its own string type. */
#define SP11_EBS_RANGES_VARIABLE_NAME_U16 \
    { 'Q','1','N','1','S','p','1','1','E','b','s','R','a','n','g','e','s',0 }

struct sp11_ebs_range {
    uint64_t base;
    uint64_t size;
};

struct sp11_ebs_ranges_table {
    uint64_t magic;
    uint32_t version;
    uint32_t count;      /* ranges in use, 1..SP11_EBS_MAX_RANGES; slots at/after count must be zero */
    uint32_t chunk_cap;  /* every flush operation the scoped sweep issues is capped to this many bytes; must be > 0 */
    uint32_t reserved;   /* must be 0 */
    struct sp11_ebs_range range[SP11_EBS_MAX_RANGES];
    uint64_t checksum;   /* FNV-1a of every preceding byte (sp11_ebs_ranges_fnv) */
};
_Static_assert(sizeof(struct sp11_ebs_range) == 16, "sp11_ebs_range layout is shared across repositories");
_Static_assert(sizeof(struct sp11_ebs_ranges_table) == 160,
               "sp11_ebs_ranges_table layout is shared across repositories");

/* FNV-1a, the same algorithm and constants as q1n1's own usb_ebs_fnv (usb-ebs.h), reproduced here
 * (not called there) so this header has no dependency on q1n1's tree from the slbounce side. */
static inline uint64_t sp11_ebs_ranges_fnv(const uint8_t *p, uint64_t n)
{
    uint64_t h = UINT64_C(0xcbf29ce484222325);
    while (n--) h = (h ^ *p++) * UINT64_C(0x100000001b3);
    return h;
}

/* Structural validation only: magic, version, a count in range, every reserved slot and field
 * zero, a positive chunk cap, and the checksum. Does not know about EFI_MEMORY_DESCRIPTOR or a
 * memory map -- that containment/type/attribute check is slbounce-side only (sp11_scoped_sweep.h),
 * since only slbounce's hook ever sees the live memory map this table is checked against. */
static inline int sp11_ebs_ranges_valid(const struct sp11_ebs_ranges_table *t)
{
    if (!t) return 0;
    if (t->magic != SP11_EBS_RANGES_MAGIC) return 0;
    if (t->version != SP11_EBS_RANGES_VERSION) return 0;
    if (t->count < 1 || t->count > SP11_EBS_MAX_RANGES) return 0;
    if (t->chunk_cap == 0) return 0;
    if (t->reserved != 0) return 0;
    for (uint32_t i = t->count; i < SP11_EBS_MAX_RANGES; i++)
        if (t->range[i].base || t->range[i].size) return 0;
    for (uint32_t i = 0; i < t->count; i++)
        if (t->range[i].size == 0) return 0;
    uint64_t want = sp11_ebs_ranges_fnv((const uint8_t *)t, offsetof(struct sp11_ebs_ranges_table, checksum));
    return t->checksum == want;
}

#endif /* SP11_EBS_RANGES_H */
