/* SPDX-License-Identifier: MIT */
/* Surface Pro 11 stick payload runner (docs/SP11-PAYLOAD.md): load reviewed EL2 test code from the boot
 * stick before ExitBootServices, declare it to the paired slbounce's scoped sweep, and call it at EL2
 * after the bounce, without rebuilding q1n1 and without a host link. A manifest may list several
 * payloads (entries named <stem>.BIN, in any case); they are called one after the other in manifest
 * order, each verified again right before its call, and every other entry is data that is never called.
 *
 * Opt-in twice over. Q1N1_SP11_PAYLOAD (default 0) needs SNAP_PLATFORM_SP11=1 and cannot be combined
 * with Q1N1_SP11_STK_SURVEY: each is its own image and its own --el2 flow. With the gate at 0 every file
 * of the runner compiles to nothing and main.c is preprocessed to the same text as before the runner
 * existed, so the default, the plain SP11 and the survey builds are byte-identical to what they were
 * (tools/test-q1n1-sp11-payload-build.py, PayloadDefaultOff). The runner image is a separate build target
 * (platform/uefi/Makefile, PAYLOAD=1) and is run with the unchanged --el2 argument.
 *
 * Split of responsibility, as for the survey: the policy lives in the sp11-payload-*.c files, which the
 * native tests drive against a fake firmware and a fake platform; main.c only supplies what needs its
 * file-static state (the panel, the UART, the recoverable-fault copy) and forwards loads only.
 *
 * Evidence: EXPERIMENTAL throughout. Built and tested on a host and on QEMU's EDK2; hardware NOT RUN. */
#pragma once
#include <stddef.h>
#include <stdint.h>
#include "efi.h"
#include "preload.h"
#include "sp11-ebs-ranges.h"
#include "sp11-fbgop.h"
#include "sp11-payload-abi.h"

#ifndef SNAP_PLATFORM_SP11
#define SNAP_PLATFORM_SP11 0
#endif
#ifndef Q1N1_SP11_PAYLOAD
#define Q1N1_SP11_PAYLOAD 0
#endif
#ifndef Q1N1_SP11_STK_SURVEY
#define Q1N1_SP11_STK_SURVEY 0
#endif
#if Q1N1_SP11_PAYLOAD && !SNAP_PLATFORM_SP11
#error "Q1N1_SP11_PAYLOAD=1 needs SNAP_PLATFORM_SP11=1: the runner loads from the Surface Pro 11's boot stick and declares ranges to its slbounce"
#endif
#if Q1N1_SP11_PAYLOAD && Q1N1_SP11_STK_SURVEY
#error "Q1N1_SP11_PAYLOAD=1 cannot be combined with Q1N1_SP11_STK_SURVEY=1: they are separate images"
#endif
#if Q1N1_SP11_PAYLOAD && defined(Q1N1_STAGE)
#error "the payload runner is part of the EFI image, not of a chainloaded stage"
#endif

#if Q1N1_SP11_PAYLOAD

/* ---- The stick: where the runner looks, and nowhere else ---------------------------------------- */

/* On the volume the image was loaded from, in Q1N1PLD1 format (preload.h). An entry whose file name is
 * <stem>.BIN (any case) is a payload and is called; any other entry is data a payload can find through
 * the preload table. File 0 must be a payload. Deliberately not the A16's \Snapintosh\q1n1-preload.bin:
 * a stick prepared for one flow is never read by the other. */
#define Q1N1_PAYLOAD_MANIFEST_PATH "\\SP11\\PAYLOAD.MAN"
/* Every file the manifest lists must be below this directory (compared without regard to case). */
#define Q1N1_PAYLOAD_DIR "\\SP11\\"

/* slbounce takes at most SP11_EBS_MAX_RANGES declared ranges and each must be inside one descriptor.
 * The image, the memory-map buffer and the preload table are declared first, one range each, so every
 * file the runner loads costs one of the rest. */
#define Q1N1_PAYLOAD_BASE_RANGES 3u
#define Q1N1_PAYLOAD_MAX_FILES (SP11_EBS_MAX_RANGES - Q1N1_PAYLOAD_BASE_RANGES)
/* slbounce splits a range into at most this many chunks (SP11_SWEEP_MAX_OPS in its bounce_main.c) and
 * refuses a range that needs more, so a range may be at most this many times chunk_cap bytes. */
#define Q1N1_PAYLOAD_SWEEP_MAX_OPS 256u
/* The largest file the runner accepts at the chunk cap q1n1 declares (1 MiB): 256 MiB. */
#define Q1N1_PAYLOAD_MAX_FILE_BYTES ((uint64_t)Q1N1_PAYLOAD_SWEEP_MAX_OPS << 20)

/* UEFI memory types for AllocatePages. A payload is code: the firmware marks LoaderCode executable
 * (q1n1.efi itself runs from it, and so does a chainloaded stage) and may mark LoaderData
 * no-execute, which would fault the call. Data files are LoaderData. slbounce sweeps both. The memory
 * type is what tells the two kinds apart after loading: a file is called exactly when it is in
 * LoaderCode. */
#define Q1N1_PAYLOAD_TYPE_CODE 1u
#define Q1N1_PAYLOAD_TYPE_DATA 2u
#define Q1N1_PAYLOAD_ALLOCATE_ANY_PAGES 0u
#define Q1N1_PAYLOAD_FILE_MODE_READ 1u
#define Q1N1_PAYLOAD_STATUS_REFUSED EFI_ERROR(21)   /* EFI_ABORTED: what the Shell gets back */

/* Lines kept from before ExitBootServices for the page that replaces the screen after it. */
#define Q1N1_PAYLOAD_NOTES 8u
/* Lines in the region on the panel, the runner's and the payload's together (the survey's budget). */
#define Q1N1_PAYLOAD_REGION_LINES 60u

/* Why the runner refused, before ExitBootServices. Every value has a name in
 * q1n1_payload_err_name, printed as PAYLOAD REFUSED=<NAME>. */
enum {
    Q1N1_PAYLOAD_OK = 0,
    Q1N1_PAYLOAD_E_NO_IMAGE,        /* no EFI_LOADED_IMAGE for this image */
    Q1N1_PAYLOAD_E_NO_DEVICE,       /* the image has no DeviceHandle */
    Q1N1_PAYLOAD_E_NO_VOLUME,       /* the DeviceHandle has no SimpleFileSystem */
    Q1N1_PAYLOAD_E_OPEN_VOLUME,     /* OpenVolume failed */
    Q1N1_PAYLOAD_E_NO_MANIFEST,     /* the manifest is not on that volume */
    Q1N1_PAYLOAD_E_MANIFEST_OPEN,   /* opening it failed for another reason */
    Q1N1_PAYLOAD_E_MANIFEST_IO,     /* its size or its contents could not be read */
    Q1N1_PAYLOAD_E_MANIFEST_BAD,    /* q1n1_preload_manifest_valid refused it, or it is too large */
    Q1N1_PAYLOAD_E_TOO_MANY_FILES,  /* more files than there are declared ranges to put them in */
    Q1N1_PAYLOAD_E_FILE0_NOT_BIN,   /* file 0 is not named <stem>.BIN, so there is nothing to call */
    Q1N1_PAYLOAD_E_BAD_PATH,        /* a file outside \SP11\, or the manifest itself */
    Q1N1_PAYLOAD_E_FILE_OPEN,
    Q1N1_PAYLOAD_E_FILE_SIZE,       /* not the size the manifest says, or not a plain file */
    Q1N1_PAYLOAD_E_FILE_TOO_BIG,    /* more than Q1N1_PAYLOAD_MAX_FILE_BYTES */
    Q1N1_PAYLOAD_E_NO_MEMORY,
    Q1N1_PAYLOAD_E_FILE_READ,
    Q1N1_PAYLOAD_E_HASH,            /* SHA-256 differs from the manifest's */
    Q1N1_PAYLOAD_E_RANGES,          /* the declared table is unusable (q1n1_payload_plan_name says why) */
    Q1N1_PAYLOAD_E_MAP,             /* no usable memory map to check the ranges against */
    Q1N1_PAYLOAD_E_DECLARE,         /* the declared table could not be written */
};
const char *q1n1_payload_err_name(int err);

/* Which kind a manifest entry is, decided by its file name alone: <stem>.BIN, in any case, is a payload
 * (code, called) and every other name is data (never called). The stem must not be empty. */
int q1n1_payload_path_is_code(const char *path);

/* What was loaded. Lives in q1n1's own image, which is the first range declared. */
struct q1n1_payload_file {
    uint64_t base;          /* AllocatePages result, page aligned */
    uint64_t bytes;         /* the file's size, as the manifest has it */
    uint64_t alloc;         /* bytes rounded up to whole pages: the range declared to the sweep */
    uint32_t memory_type;   /* Q1N1_PAYLOAD_TYPE_CODE for a payload (<stem>.BIN), Q1N1_PAYLOAD_TYPE_DATA for the rest */
    uint32_t reserved;
    uint8_t sha256[32];     /* what the file hashed to, equal to the manifest's */
};
/* A loaded file is called exactly when it is in LoaderCode. */
static inline int q1n1_payload_file_is_code(const struct q1n1_payload_file *file)
{
    return file->memory_type == Q1N1_PAYLOAD_TYPE_CODE;
}
struct q1n1_payload_loaded {
    uint32_t count;
    uint32_t code_count;    /* how many of the files are payloads: at least one, and file 0 is one */
    struct q1n1_payload_file file[Q1N1_PAYLOAD_MAX_FILES];
    uint64_t table_base, table_alloc;   /* a struct q1n1_preload_cache: the payload finds its files in it */
    uint64_t stack_base, stack_alloc;   /* the payload's stack: not declared, nothing is written to it before the bounce */
    uint32_t notes;
    char note[Q1N1_PAYLOAD_NOTES][Q1N1_PAYLOAD_LINE_MAX + 1];
};

/* Where a refusal happened, for the line that reports it. */
struct q1n1_payload_diag {
    efi_status efi;         /* the firmware's status when a firmware call failed, else 0 */
    uint32_t index;         /* the manifest entry concerned */
    uint32_t reserved;
    uint64_t expected, got; /* bytes, for a size or read refusal */
    uint8_t hash_want[8], hash_have[8];     /* the first eight bytes of the manifest's digest and of the file's */
    int plan;               /* Q1N1_PLAN_* behind a Q1N1_PAYLOAD_E_RANGES refusal */
    uint32_t range;         /* and the index of the declared range it concerns */
};

/* ---- Loading (sp11-payload-load.c) ----------------------------------------------------------------- */

/* The volume the image was loaded from and nothing else: EFI_LOADED_IMAGE.DeviceHandle ->
 * SimpleFileSystem -> OpenVolume. It never connects a controller and never enumerates block devices or
 * volumes, so a stick plugged in beside the boot stick, or the internal disk, is not even looked at. */
int q1n1_payload_open_volume(struct efi_boot_services *bs, const struct efi_loaded_image *image,
                             struct efi_file **root, struct q1n1_payload_diag *diag);
/* Everything that allocates, in the order the refusals are listed above: finds and validates the
 * manifest, reads each file exactly as long as the manifest says, checks its SHA-256, allocates the
 * preload table and the stack. Opens files for reading only and writes nothing. On any refusal it frees
 * what it allocated and returns the reason; *out is then not meant to be used. */
int q1n1_payload_prepare(struct efi_boot_services *bs, const struct efi_loaded_image *image,
                         struct q1n1_payload_loaded *out, struct q1n1_payload_diag *diag);
/* Frees everything prepare allocated. Only for a path that does not go on to ExitBootServices. */
void q1n1_payload_release(struct efi_boot_services *bs, struct q1n1_payload_loaded *loaded);
/* "PAYLOAD REFUSED=<NAME> ..." for a firmware console that can show a backslash. Returns the length. */
size_t q1n1_payload_refusal_line(int err, const struct q1n1_payload_diag *diag, char *dst, size_t cap);
/* The note lines prepare keeps for the page after the bounce. */
void q1n1_payload_note(struct q1n1_payload_loaded *loaded, const char *line);

/* ---- Declared ranges (sp11-payload-plan.c) -------------------------------------------------------- */

/* The checks on a table of declared ranges, in this order; the first that fails is the status. */
enum {
    Q1N1_PLAN_OK = 0,
    Q1N1_PLAN_NO_TABLE,         /* nothing declared */
    Q1N1_PLAN_TOO_MANY,         /* more than SP11_EBS_MAX_RANGES */
    Q1N1_PLAN_CHUNK_CAP,        /* chunk_cap is 0 */
    Q1N1_PLAN_EMPTY,            /* a range of size 0 */
    Q1N1_PLAN_WRAP,             /* base + size wraps around the address space */
    Q1N1_PLAN_FRAMEBUFFER,      /* a range overlaps the framebuffer */
    Q1N1_PLAN_OVERLAP,          /* two ranges overlap */
    Q1N1_PLAN_TOO_LARGE,        /* more chunks than slbounce's ops buffer holds */
    /* From here on they need the memory map and mirror slbounce's sp11_sweep_range, in its order. */
    Q1N1_PLAN_NOT_CONTAINED,    /* not inside exactly one descriptor */
    Q1N1_PLAN_WRONG_TYPE,       /* the descriptor's type is not one it sweeps (1-6 and 9) */
    Q1N1_PLAN_NOT_WB,           /* the descriptor lacks EFI_MEMORY_WB */
};
const char *q1n1_payload_plan_name(int status);

/* Appends one range per loaded file (named payload, file1, ...) to a table that already holds the
 * image, the memory-map buffer and the preload table, then checks the whole table. On any status other
 * than Q1N1_PLAN_OK the table and the labels are left as they were. `labels` has one entry per table
 * slot. The framebuffer is passed only to be kept out of the table: it is reserved memory the sweep
 * refuses, and nothing reads it after the bounce. */
int q1n1_payload_plan_append(struct sp11_ebs_ranges_table *table, const char **labels,
                             const struct q1n1_payload_loaded *loaded, uint64_t fb_base, uint64_t fb_bytes);
/* Everything about the table that needs no memory map. */
int q1n1_payload_table_check(const struct sp11_ebs_ranges_table *table, uint64_t fb_base, uint64_t fb_bytes);
/* The rest, against the final memory map: what slbounce will decide for each range, so that a refusal
 * is reported on the firmware console and returned to the Shell instead of failing ExitBootServices.
 * *failing is the index of the first range refused. */
int q1n1_payload_map_check(const struct sp11_ebs_ranges_table *table, const struct q1n1_sp11_gop_map_entry *map,
                           uint32_t map_count, uint32_t *failing);
/* Which refusal the runner makes just before the point of no return, if any, in this order: the plan the
 * declared table was built from, the write of that table, the memory map it is to be checked against, then
 * slbounce's rules for each range. Returns Q1N1_PAYLOAD_OK or a Q1N1_PAYLOAD_E_ value and fills in `diag`
 * (the plan status and range, or the firmware status). plan_status and declared_status are what
 * q1n1_payload_plan_append and the table's SetVariable returned; map_parsed says the map was read and
 * parsed. */
int q1n1_payload_precheck(int plan_status, uint64_t declared_status, uint64_t map_status, int map_parsed,
                          const struct sp11_ebs_ranges_table *table, const struct q1n1_sp11_gop_map_entry *map,
                          uint32_t map_count, struct q1n1_payload_diag *diag);

/* ---- Text and the panel (sp11-payload-text.c) -------------------------------------------------------- */

/* "0X" and the fewest upper-case digits; the text is cut, never overrun. Returns the length. */
size_t q1n1_payload_fmt_hex(char *dst, size_t cap, uint64_t value);
size_t q1n1_payload_fmt_dec(char *dst, size_t cap, uint64_t value);
/* Folds lower case up and replaces everything outside the page font (and the space) with '_'. */
void q1n1_payload_sanitize(char *text);
/* One line being built: a prefix and key=value fields, each after a space, cut at the line cap. */
struct q1n1_payload_line {
    char buf[Q1N1_PAYLOAD_LINE_MAX + 1];
    unsigned len;
};
void q1n1_payload_line_begin(struct q1n1_payload_line *line, const char *prefix);
/* Text appended as it is, with no separator. */
void q1n1_payload_line_raw(struct q1n1_payload_line *line, const char *text);
void q1n1_payload_line_word(struct q1n1_payload_line *line, const char *word);
void q1n1_payload_line_hex(struct q1n1_payload_line *line, const char *key, uint64_t value);
void q1n1_payload_line_dec(struct q1n1_payload_line *line, const char *key, uint64_t value);
/* key=<the first eight bytes of the digest as sixteen hex digits, no 0X>: the hash prefix of a photograph.
 * An empty or NULL key appends the sixteen digits alone. Only the first eight bytes are read. */
void q1n1_payload_line_digest(struct q1n1_payload_line *line, const char *key, const uint8_t *digest);
/* Where the lines go on the panel: the survey's region (docs/SP11-STK-SURVEY.md). */
#define Q1N1_PAYLOAD_REGION_RIGHT 0
#define Q1N1_PAYLOAD_REGION_BELOW 1
struct q1n1_payload_region {
    int placement;
    uint32_t scale, col0, row0, rows;
};
void q1n1_payload_region_place(uint32_t width, uint32_t height, uint32_t page_scale, uint32_t page_rows,
                               struct q1n1_payload_region *out);

/* ---- Running at EL2 (sp11-payload-run.c) ----------------------------------------------------------------- */

/* Guarded memory primitive, the shape of main.c's live_guarded(kind, dst, src, size): `size` bytes (a
 * multiple of 4) are copied from `src` to the RAM at `dst` with the recoverable-fault guard on and the
 * result is non-zero when the access aborted. COPY32 loads from src. SET32 is a store to `src`: the
 * platform primitive has it, the runner never asks for it, and the glue refuses it. */
#define Q1N1_PAYLOAD_G_COPY32 0
#define Q1N1_PAYLOAD_G_SET32 2

/* What the runner needs from the platform. Plain function pointers, no context: there is one platform,
 * main.c's, and the payload's own ops (which have no context argument either) reach it the same way. */
struct q1n1_payload_env {
    /* One finished line, no terminator: drawn on the panel and mirrored to the UART. */
    void (*emit)(const char *line);
    /* Makes the bytes just verified executable: data cache to the point of unification, instruction
     * cache invalidated. The call does not happen before it returns. */
    void (*sync_code)(uint64_t base, uint64_t bytes);
    /* Calls entry(args) on the stack that ends at stack_top and returns its result. */
    uint64_t (*call)(uint64_t entry, const struct q1n1_payload_args *args, uint64_t stack_top);
    int (*guarded)(int kind, uint64_t dst, uint64_t src, uint64_t size);
    uint64_t (*counter)(void);
};
/* What the runner tells the payload about the machine, from main.c's own state. */
struct q1n1_payload_platform {
    uint64_t fb_base, fb_bytes, map_base, map_size, map_stride;
    uint32_t fb_width, fb_height, fb_stride, fb_format;
};
enum {
    Q1N1_PAYLOAD_RUN_OK = 0,        /* every payload was called and came back, whatever it returned */
    Q1N1_PAYLOAD_RUN_NO_PAYLOAD,    /* nothing was loaded, or there is no payload among the files */
    Q1N1_PAYLOAD_RUN_HASH,          /* a payload no longer hashes to its manifest entry: not called, chain stopped */
    Q1N1_PAYLOAD_RUN_STACK,         /* a payload overwrote its stack guard: the chain stopped after it */
};
/* What one payload did: the numbers of its PAYLOAD DONE line. */
struct q1n1_payload_call_result {
    uint32_t index;             /* its manifest entry */
    int stack_ok;               /* the guard words at the low end of the stack are intact */
    uint64_t retval;
    unsigned lines, dropped;    /* lines the payload put on the panel, and lines past its budget */
    unsigned loads, faults, refused;
};
struct q1n1_payload_result {
    int status;
    uint32_t stopped;           /* the manifest entry the chain stopped at (RUN_HASH and RUN_STACK) */
    uint32_t called;            /* payloads called and come back, in order: call[0 .. called - 1] */
    struct q1n1_payload_call_result call[Q1N1_PAYLOAD_MAX_FILES];
};
/* Replays the notes, then runs the chain: for each payload in manifest order, verifies it again where it
 * now is (through the table and against what was hashed before the bounce), makes its pages executable,
 * arms the stack guard words, prints PAYLOAD CALL <index> <hash prefix>, calls it with its own base and
 * size, and prints PAYLOAD DONE for what came back. Data entries are never called. The payload's budgets
 * (lines, loads) start again for every call. The chain stops, with one PAYLOAD CHAIN STOPPED line, at a
 * payload that does not verify (it is not called) or that overwrote its stack guard; what a payload
 * returns never stops it. A payload that hangs or faults ends the boot, named by the last line. */
int q1n1_payload_run(const struct q1n1_payload_env *env, const struct q1n1_payload_loaded *loaded,
                     const struct q1n1_payload_platform *platform, struct q1n1_payload_result *result);
/* The policy of the load32 op, pure. 0 or one of Q1N1_PAYLOAD_LOAD_E_*. */
int q1n1_payload_load32_check(uint64_t addr, const uint32_t *out, uint64_t stack_base, uint64_t stack_size,
                              unsigned loads_done);
/* Payload `index` (a file in LoaderCode) hashes, where it is, to the digest in the table and to the one
 * measured before the bounce, and the table still describes every file the runner loaded. 1 when it does.
 * Only this payload is hashed: a data file can be gigabytes and nothing calls it. */
int q1n1_payload_verify_in_place(const struct q1n1_payload_loaded *loaded, uint32_t index);

/* sp11-payload-call.S, EL2 only. q1n1_payload_call calls entry(args) with SP at stack_top, keeping
 * q1n1's callee-saved registers and SP safe. q1n1_payload_sync_code cleans the data cache and
 * invalidates the instruction cache over [base, base + bytes). */
uint64_t q1n1_payload_call(uint64_t entry, const struct q1n1_payload_args *args, uint64_t stack_top);
void q1n1_payload_sync_code(uint64_t base, uint64_t bytes);

#endif /* Q1N1_SP11_PAYLOAD */
