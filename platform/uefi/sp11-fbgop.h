/* SPDX-License-Identifier: MIT */
/* Surface Pro 11 GOP two-tier selection (SNAP_PLATFORM_SP11), ported from the pure selection logic
 * proven on this unit under the UEFI Shell by Snapintosh's passive probe (probes/uefi/fbtext.c
 * probe_gop_select/probe_gop_check, probes/uefi/probe_main.c gather_gop, in the Snapintosh
 * repository): docs/SP11-Q1N1-BOOT-STUDY.md section 8 names this the fix to port. q1n1 cannot
 * build-depend on that repository (a different project, a different build), so this is an
 * independent reimplementation of the same algorithm and status/rule names, not a shared file;
 * fbcon.c's own header comment already documents this project's precedent for keeping a provably
 * tested module independently maintained rather than reusing another tree's source file directly.
 *
 * Pure functions: no EFI type is named here (main.c's SP11-gated replacement for find_framebuffer
 * converts the real EFI_GRAPHICS_OUTPUT_PROTOCOL and EFI_MEMORY_DESCRIPTOR data into the shapes
 * below), so a host test can drive this file directly. Default build (SNAP_PLATFORM_SP11
 * undefined or 0): this file compiles to nothing and find_framebuffer is unchanged. */
#pragma once
#include <stdint.h>

#ifndef SNAP_PLATFORM_SP11
#define SNAP_PLATFORM_SP11 0
#endif

#if SNAP_PLATFORM_SP11

#define Q1N1_SP11_GOP_MAX_CANDIDATES 8u

/* Memory types a linear framebuffer may be described by (EFI_MEMORY_DESCRIPTOR.Type): reserved(0),
 * boot-services data(4, a display driver allocates its buffer there on some firmware), runtime
 * data(6) and the two MMIO types(11,12). Conventional, loader, code, ACPI and other types belong to
 * other users: a "framebuffer" inside them is the wrong address, and drawing into it would corrupt
 * whatever lives there. Identical to probes/uefi/fbtext.h's PROBE_FB_TYPES_MASK (Snapintosh
 * repository), by design: the same hazard, the same fix. */
#define Q1N1_SP11_GOP_TYPES_MASK ((1u << 0) | (1u << 4) | (1u << 6) | (1u << 11) | (1u << 12))

enum {
    Q1N1_SP11_GOP_OK = 0,
    Q1N1_SP11_GOP_ABSENT,       /* no handle offered a GOP with a usable mode */
    Q1N1_SP11_GOP_NOT_CONSOLE,  /* not the console's own GOP: never drawn into (rule 1 only) */
    Q1N1_SP11_GOP_BAD_MODE,     /* geometry, stride or pixel format this code does not trust */
    Q1N1_SP11_GOP_NOT_IN_MAP,   /* the framebuffer's byte range is not wholly inside an allowed type */
    Q1N1_SP11_GOP_AMBIGUOUS,    /* no console GOP, and more than one distinct framebuffer qualifies */
};
const char *q1n1_sp11_gop_status_name(int status);

enum { Q1N1_SP11_GOP_RULE_NONE = 0, Q1N1_SP11_GOP_RULE_CONSOLE = 1, Q1N1_SP11_GOP_RULE_SAME = 2 };
const char *q1n1_sp11_gop_rule_name(int rule);

/* pixel_format: 0 = RGBX (EFI PixelRedGreenBlueReserved8BitPerColor), 1 = BGRX
 * (PixelBlueGreenRedReserved8BitPerColor); anything else is refused (BAD_MODE). */
struct q1n1_sp11_gop_candidate {
    int is_console;    /* this handle equals the system table's own ConsoleOutHandle */
    uint64_t base, size_bytes;
    uint32_t width, height, pixels_per_scanline, pixel_format;
};

/* One EFI_MEMORY_DESCRIPTOR, reduced to what containment needs (q1n1's own get32/get64 convention,
 * main.c, already extracts exactly these three fields for sysinfo_memory). */
struct q1n1_sp11_gop_map_entry {
    uint32_t type;
    uint64_t base, pages;
};

struct q1n1_sp11_gop_result {
    int status;   /* Q1N1_SP11_GOP_OK when a framebuffer was chosen */
    int rule;     /* Q1N1_SP11_GOP_RULE_NONE unless status is OK */
    uint32_t index; /* the chosen candidate's index into the caller's own array; OK only */
    uint32_t examined; /* candidates looked at; rule 1 stops at the one it chooses */
};

/* Validates one candidate's geometry (nonzero, bounded, consistent stride, a known pixel_format,
 * no overflow forming its byte extent) and, only if that passes, that its whole byte range sits
 * inside the memory map in descriptors of Q1N1_SP11_GOP_TYPES_MASK and nothing else. Returns
 * Q1N1_SP11_GOP_OK, Q1N1_SP11_GOP_BAD_MODE or Q1N1_SP11_GOP_NOT_IN_MAP (never NOT_CONSOLE or
 * AMBIGUOUS: those are q1n1_sp11_gop_select's own policy, not a single candidate's property). */
int q1n1_sp11_gop_check(const struct q1n1_sp11_gop_map_entry *map, uint32_t map_count,
                        const struct q1n1_sp11_gop_candidate *c);

/* Rule 1 (CONSOLE): the first candidate that is both is_console and passes the check above; stops
 * immediately. Rule 2 (SAME), reached only if no candidate was ever is_console at all: every
 * candidate is checked as if it were the console; if every one that passes agrees on one identical
 * framebuffer (base, size, geometry, format), that one is chosen; if more than one genuinely
 * different framebuffer qualifies, AMBIGUOUS (no index is meaningful then, and the caller must not
 * draw into anything). With no valid memory map (map_count == 0) nothing can pass NOT_IN_MAP, so
 * nothing is ever chosen under either rule, by construction -- not a special case. */
void q1n1_sp11_gop_select(const struct q1n1_sp11_gop_map_entry *map, uint32_t map_count,
                         const struct q1n1_sp11_gop_candidate *cand, uint32_t count,
                         struct q1n1_sp11_gop_result *out);

#endif /* SNAP_PLATFORM_SP11 */
