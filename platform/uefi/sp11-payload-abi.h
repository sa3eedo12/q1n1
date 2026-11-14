/* SPDX-License-Identifier: MIT */
/* Surface Pro 11 stick payload runner: the ABI between q1n1 and a payload (docs/SP11-PAYLOAD.md).
 *
 * A payload is a flat, position-independent binary the runner loads from the boot stick before
 * ExitBootServices and calls at EL2 afterwards:
 *
 *     uint64_t payload_entry(const struct q1n1_payload_args *a);
 *
 * Entry is at offset 0 of the file, x0 = a, SP = the top of the payload stack described by a. It
 * returns in x0 and q1n1 prints the value. The payload follows AAPCS64 and calls into q1n1 only through
 * a->ops. A manifest may list several payloads: the runner calls them one after the other in one boot,
 * each with its own payload_base and payload_size and a fresh budget of ops, and nothing else in `a`
 * differs between them.
 *
 * This header is shared by the runner (a PE image), the payloads (bare-metal ELF) and the host tests,
 * so it is freestanding (stdint and stddef only) and has no gate: it only declares the contract.
 * Everything here is EXPERIMENTAL: built and tested on a host and on QEMU's EDK2, hardware NOT RUN.
 *
 * The ops table has no store. That is a property of the table, not a sandbox: a payload is machine
 * code at EL2 and can store wherever it likes. What keeps a store to a device register out of a payload
 * is that its bytes are reviewed and pinned by the SHA-256 in the manifest; a payload that needs one
 * needs a separate, explicitly authorized change (AGENTS.md hardware safety rules). */
#pragma once
#include <stddef.h>
#include <stdint.h>

/* "Q1N1PAY1" read byte 0 first, the convention of Q1N1PLD1 (preload.h) and Q1N1INFO. */
#define Q1N1_PAYLOAD_ABI_MAGIC UINT64_C(0x31594150314e3151)
#define Q1N1_PAYLOAD_ABI_VERSION 1u

/* The page font (main.c alphabet) has capitals, digits and : - . / = ? ( ) _ only. puts() truncates a
 * line to Q1N1_PAYLOAD_LINE_MAX characters, folds lower case up and turns every other character into
 * '_', so the panel and the UART carry the same text. */
#define Q1N1_PAYLOAD_LINE_MAX 100u
/* Lines puts() accepts in one call of the payload; later ones are counted and dropped. The runner's
 * own lines come on top: the whole region holds at most 60 (the survey's own budget). */
#define Q1N1_PAYLOAD_LINES_MAX 40u
/* Loads load32() performs in one call of the payload. */
#define Q1N1_PAYLOAD_LOADS_MAX 4096u
/* The payload's stack, allocated by the runner: 64 KiB, 16-byte aligned, SP at its top. q1n1's own ops
 * run on it too, and a fault pushes a 272-byte frame onto it, so a payload should keep at least 16 KiB
 * of it free (it may use the other 48 KiB). */
#define Q1N1_PAYLOAD_STACK_BYTES (64u * 1024u)

/* load32() results. */
enum {
    Q1N1_PAYLOAD_LOAD_OK = 0,
    Q1N1_PAYLOAD_LOAD_E_PARAM,      /* out is NULL */
    Q1N1_PAYLOAD_LOAD_E_ALIGN,      /* addr or out is not 4-byte aligned */
    Q1N1_PAYLOAD_LOAD_E_RANGE,      /* addr + 4 is beyond the 48-bit address space */
    Q1N1_PAYLOAD_LOAD_E_OUT,        /* out is not inside the payload's stack */
    Q1N1_PAYLOAD_LOAD_E_BUDGET,     /* Q1N1_PAYLOAD_LOADS_MAX loads were already made */
    Q1N1_PAYLOAD_LOAD_E_FAULT,      /* the guarded load aborted */
};

/* What payload_entry returns when it refuses its arguments. Any other value is the payload's own. */
#define Q1N1_PAYLOAD_RET_BAD_ARGS UINT64_C(1)

struct q1n1_payload_ops {
    /* One line, NUL terminated, drawn on the panel in the survey's region and mirrored to the UART. */
    void (*puts)(const char *line);
    /* "0X" and the fewest upper-case hex digits (value 0 is "0X0") into dst, which holds cap bytes
     * (the text is cut, never overrun). Returns the length without the terminator. */
    uint32_t (*hex)(char *dst, uint32_t cap, uint64_t value);
    /* Reads the 32-bit word at physical address addr (identity mapped by the firmware's tables) into
     * *out, which must be inside the payload's stack. Recoverable-fault guarded: an abort comes back
     * as Q1N1_PAYLOAD_LOAD_E_FAULT instead of taking the core. A load can still hang the bus (an
     * unclocked block), which no guard recovers: that is for the payload's reviewer to rule out. */
    int32_t (*load32)(uint64_t addr, uint32_t *out);
    /* CNTPCT_EL0, the raw physical counter. */
    uint64_t (*counter)(void);
};

struct q1n1_payload_args {
    uint64_t magic;             /* Q1N1_PAYLOAD_ABI_MAGIC */
    uint32_t version;           /* Q1N1_PAYLOAD_ABI_VERSION */
    uint32_t size;              /* sizeof(struct q1n1_payload_args) the runner filled in */
    uint64_t payload_base;      /* where the runner loaded this payload (page aligned) */
    uint64_t payload_size;      /* the file size in bytes */
    uint64_t fb_base;           /* the framebuffer the panel is drawn in (never declared to the sweep) */
    uint64_t fb_bytes;
    uint32_t fb_width, fb_height;
    uint32_t fb_stride;         /* pixels per scanline, 4 bytes per pixel */
    uint32_t fb_format;         /* 0 RGBX, 1 BGRX (EFI pixel formats) */
    uint64_t map_base;          /* the final UEFI memory map ExitBootServices was given */
    uint64_t map_size;          /* bytes */
    uint64_t map_stride;        /* descriptor size in bytes */
    uint64_t preload_table;     /* a struct q1n1_preload_cache (preload.h): this payload is the entry whose base is payload_base */
    uint64_t preload_size;
    uint64_t stack_base;        /* the payload stack, [stack_base, stack_base + stack_size) */
    uint64_t stack_size;
    struct q1n1_payload_ops ops;
    uint64_t reserved[5];       /* zero in version 1 */
};

_Static_assert(sizeof(void *) == 8, "the payload ABI is 64-bit");
_Static_assert(offsetof(struct q1n1_payload_args, magic) == 0, "payload ABI: magic");
_Static_assert(offsetof(struct q1n1_payload_args, version) == 8, "payload ABI: version");
_Static_assert(offsetof(struct q1n1_payload_args, size) == 12, "payload ABI: size");
_Static_assert(offsetof(struct q1n1_payload_args, payload_base) == 16, "payload ABI: payload_base");
_Static_assert(offsetof(struct q1n1_payload_args, payload_size) == 24, "payload ABI: payload_size");
_Static_assert(offsetof(struct q1n1_payload_args, fb_base) == 32, "payload ABI: fb_base");
_Static_assert(offsetof(struct q1n1_payload_args, fb_bytes) == 40, "payload ABI: fb_bytes");
_Static_assert(offsetof(struct q1n1_payload_args, fb_width) == 48, "payload ABI: fb_width");
_Static_assert(offsetof(struct q1n1_payload_args, fb_height) == 52, "payload ABI: fb_height");
_Static_assert(offsetof(struct q1n1_payload_args, fb_stride) == 56, "payload ABI: fb_stride");
_Static_assert(offsetof(struct q1n1_payload_args, fb_format) == 60, "payload ABI: fb_format");
_Static_assert(offsetof(struct q1n1_payload_args, map_base) == 64, "payload ABI: map_base");
_Static_assert(offsetof(struct q1n1_payload_args, map_size) == 72, "payload ABI: map_size");
_Static_assert(offsetof(struct q1n1_payload_args, map_stride) == 80, "payload ABI: map_stride");
_Static_assert(offsetof(struct q1n1_payload_args, preload_table) == 88, "payload ABI: preload_table");
_Static_assert(offsetof(struct q1n1_payload_args, preload_size) == 96, "payload ABI: preload_size");
_Static_assert(offsetof(struct q1n1_payload_args, stack_base) == 104, "payload ABI: stack_base");
_Static_assert(offsetof(struct q1n1_payload_args, stack_size) == 112, "payload ABI: stack_size");
_Static_assert(offsetof(struct q1n1_payload_args, ops) == 120, "payload ABI: ops");
_Static_assert(offsetof(struct q1n1_payload_ops, puts) == 0, "payload ABI: ops.puts");
_Static_assert(offsetof(struct q1n1_payload_ops, hex) == 8, "payload ABI: ops.hex");
_Static_assert(offsetof(struct q1n1_payload_ops, load32) == 16, "payload ABI: ops.load32");
_Static_assert(offsetof(struct q1n1_payload_ops, counter) == 24, "payload ABI: ops.counter");
_Static_assert(sizeof(struct q1n1_payload_ops) == 32, "payload ABI: ops size");
_Static_assert(offsetof(struct q1n1_payload_args, reserved) == 152, "payload ABI: reserved");
_Static_assert(sizeof(struct q1n1_payload_args) == 192, "payload ABI: size of version 1");

typedef uint64_t (*q1n1_payload_entry_fn)(const struct q1n1_payload_args *args);
