/* SPDX-License-Identifier: MIT */
/* Host tests for the payload runner's loader (platform/uefi/sp11-payload-load.c) against a fake firmware.
 * Driven by tools/test-q1n1-sp11-payload.py under ASan and UBSan.
 *
 * The fake gives the loader two volumes, an allocator that hands out poisoned pages and records every
 * allocation, and a boot-services table in which every call the loader must NOT make is a tripwire that
 * fails the whole program: ConnectController, LocateHandle, LocateHandleBuffer, LocateProtocol,
 * GetMemoryMap, ExitBootServices, FreePool and the rest. File handles are counted, every open is checked
 * to be a read, and the volumes' bytes are hashed before and after to show nothing was written.
 *
 *   volume     the loader reads the volume the image came from and no other; no controller is connected
 *   manifest   every way the manifest can be missing, short, long, malformed or refused by the runner
 *   files      every way a file can disagree with its manifest entry, and what is freed after each
 *   memory     allocation types, alignment, the poisoned tail, failures at each allocation, release
 *   lines      the refusal lines and the notes kept for the page after the bounce
 *
 * Nothing here runs on EFI or on hardware. Evidence: EXPERIMENTAL (host model only). */
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SNAP_PLATFORM_SP11 1
#define Q1N1_SP11_PAYLOAD 1
#include "sp11-payload.h"
#include "sha256.h"

static unsigned checks;
#define CHECK(x) do { \
        if (!(x)) { fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #x); return 1; } \
        checks++; \
    } while (0)

/* ---- The fake firmware ----------------------------------------------------------------------------- */

static void trip(const char *what)
{
    fprintf(stderr, "FAIL tripwire: the loader called %s\n", what);
    exit(3);
}
static efi_status trip_get_memory_map(uint64_t *a, void *b, uint64_t *c, uint64_t *d, uint32_t *e)
{ (void)a; (void)b; (void)c; (void)d; (void)e; trip("GetMemoryMap"); return 0; }
static efi_status trip_free_pool(void *a) { (void)a; trip("FreePool"); return 0; }
static efi_status trip_locate_handle(uint32_t a, efi_guid *b, void *c, uint64_t *d, efi_handle *e)
{ (void)a; (void)b; (void)c; (void)d; (void)e; trip("LocateHandle"); return 0; }
static efi_status trip_set_watchdog(uint64_t a, uint64_t b, uint64_t c, char16 *d)
{ (void)a; (void)b; (void)c; (void)d; trip("SetWatchdogTimer"); return 0; }
static efi_status trip_connect_controller(efi_handle a, efi_handle *b, void *c, uint8_t d)
{ (void)a; (void)b; (void)c; (void)d; trip("ConnectController"); return 0; }
static efi_status trip_exit_boot_services(efi_handle a, uint64_t b) { (void)a; (void)b; trip("ExitBootServices"); return 0; }
static efi_status trip_locate_handle_buffer(uint32_t a, efi_guid *b, void *c, uint64_t *d, efi_handle **e)
{ (void)a; (void)b; (void)c; (void)d; (void)e; trip("LocateHandleBuffer"); return 0; }
static efi_status trip_locate_protocol(efi_guid *a, void *b, void **c) { (void)a; (void)b; (void)c; trip("LocateProtocol"); return 0; }
static void trip_any(void) { trip("a firmware call that is not in the loader's list"); }

struct fake_entry {
    char path[64];
    const uint8_t *data;
    uint64_t size;
    int is_dir;
    efi_status info_error;       /* GetInfo fails with this */
    uint64_t info_size;          /* GetInfo reports this instead of `size` when non-zero */
    uint64_t read_error_at;      /* Read fails once this many bytes were returned (0: never) */
    int zero_read;               /* Read returns success with 0 bytes */
    int over_report;             /* Read reports one more byte than it was asked for */
    uint64_t max_per_read;       /* Read returns at most this many bytes per call (0: no limit) */
    int info_short;              /* GetInfo reports a reply shorter than the fixed part */
};
struct fake_volume {
    struct efi_simple_fs fs;
    struct fake_entry files[16];
    unsigned count, volume_opens, file_opens;
    efi_status open_volume_error;
};
struct fake_handle {
    struct efi_file f;
    struct fake_volume *vol;
    struct fake_entry *entry;
    uint64_t pos;
};
struct fake_allocation { uint64_t base, pages; uint32_t type; int live; void *memory; };

#define IMAGE_DEVICE ((efi_handle)(uintptr_t)0x1001)
static struct fake_volume volume[2];
static struct fake_allocation alloc_log[64];
static unsigned alloc_count, alloc_calls, fail_alloc_at, fail_alloc_returns_zero, bad_frees, strays, handle_calls;
static int open_handles, non_read_opens, write_flags;
static efi_status fail_alloc_status;
static struct efi_boot_services bs;
static struct efi_loaded_image image;
/* The handle the image was loaded from, and whether it carries a file system. Any question about another
 * handle, or about another protocol, is a stray: the loader has no reason to ask. */
static efi_handle image_device;
static int image_device_has_fs;

static void ascii(const char16 *wide, char *out, size_t cap)
{
    size_t n = 0;
    while (wide[n] && n + 1 < cap) { out[n] = (char)wide[n]; n++; }
    out[n] = 0;
}
static int same_ci(const char *a, const char *b)
{
    for (;; a++, b++) {
        char x = *a, y = *b;
        if (x >= 'A' && x <= 'Z') x = (char)(x + 32);
        if (y >= 'A' && y <= 'Z') y = (char)(y + 32);
        if (x != y) return 0;
        if (!x) return 1;
    }
}

static efi_status fake_close(struct efi_file *f)
{
    struct fake_handle *h = (struct fake_handle *)f;
    open_handles--;
    free(h);
    return 0;
}
static efi_status fake_open(struct efi_file *, struct efi_file **, const char16 *, uint64_t, uint64_t);
static efi_status fake_read(struct efi_file *, uint64_t *, void *);
static efi_status fake_get_info(struct efi_file *, efi_guid *, uint64_t *, void *);
static struct fake_handle *new_handle(struct fake_volume *v, struct fake_entry *e)
{
    struct fake_handle *h = calloc(1, sizeof *h);
    h->f.revision = 0x20000;
    h->f.open = fake_open; h->f.close = fake_close; h->f.read = fake_read; h->f.get_info = fake_get_info;
    h->f.delete_file = (void *)trip_any; h->f.write = (void *)trip_any;
    h->f.get_position = (void *)trip_any; h->f.set_position = (void *)trip_any;
    h->vol = v; h->entry = e;
    open_handles++;
    return h;
}
static efi_status fake_open(struct efi_file *f, struct efi_file **out, const char16 *name, uint64_t mode, uint64_t attrs)
{
    struct fake_handle *h = (struct fake_handle *)f;
    char text[128];
    ascii(name, text, sizeof text);
    if (mode != 1 || attrs != 0) non_read_opens++;
    if (mode & ~UINT64_C(1)) write_flags++;
    h->vol->file_opens++;
    for (unsigned i = 0; i < h->vol->count; i++) {
        if (same_ci(h->vol->files[i].path, text)) {
            *out = &new_handle(h->vol, &h->vol->files[i])->f;
            return 0;
        }
    }
    return EFI_NOT_FOUND;
}
static efi_status fake_read(struct efi_file *f, uint64_t *n, void *buffer)
{
    struct fake_handle *h = (struct fake_handle *)f;
    struct fake_entry *e = h->entry;
    if (!e || e->is_dir) return EFI_UNSUPPORTED;
    uint64_t avail = e->size - h->pos, take = *n < avail ? *n : avail;
    if (e->max_per_read && take > e->max_per_read) take = e->max_per_read;
    if (e->read_error_at && h->pos + take > e->read_error_at) return EFI_ERROR(7);
    if (e->zero_read && h->pos > 0) { *n = 0; return 0; }
    memcpy(buffer, e->data + h->pos, take);
    h->pos += take;
    *n = take + (e->over_report ? 1 : 0);
    return 0;
}
static efi_status fake_get_info(struct efi_file *f, efi_guid *guid, uint64_t *n, void *buffer)
{
    struct fake_handle *h = (struct fake_handle *)f;
    struct fake_entry *e = h->entry;
    uint64_t words[16] = {0};
    static const efi_guid info_guid = {0x09576e92, 0x6d3f, 0x11d2, {0x8e, 0x39, 0, 0xa0, 0xc9, 0x69, 0x72, 0x3b}};
    if (memcmp(guid, &info_guid, sizeof info_guid)) return EFI_UNSUPPORTED;
    if (e->info_error) return e->info_error;
    words[0] = e->info_short ? 40 : 80 + 8;
    words[1] = e->info_size ? e->info_size : e->size;
    words[2] = (words[1] + 4095) & ~UINT64_C(4095);
    words[9] = e->is_dir ? 0x10 : 0;
    uint64_t reply = e->info_short ? 40 : 88;
    if (*n < reply) { *n = reply; return EFI_BUFFER_TOO_SMALL; }
    memcpy(buffer, words, reply);
    *n = reply;
    return 0;
}
static efi_status fake_open_volume(struct efi_simple_fs *fs, struct efi_file **root)
{
    struct fake_volume *v = (struct fake_volume *)fs;
    v->volume_opens++;
    if (v->open_volume_error) return v->open_volume_error;
    *root = &new_handle(v, NULL)->f;
    return 0;
}
static efi_status fake_handle_protocol(efi_handle handle, efi_guid *guid, void **out)
{
    static const efi_guid fs_guid = {0x964e5b22, 0x6459, 0x11d2, {0x8e, 0x39, 0, 0xa0, 0xc9, 0x69, 0x72, 0x3b}};
    handle_calls++;
    if (memcmp(guid, &fs_guid, sizeof fs_guid) || handle != image_device) { strays++; return EFI_UNSUPPORTED; }
    if (!image_device_has_fs) return EFI_UNSUPPORTED;
    *out = &volume[0].fs;
    return 0;
}
static efi_status fake_allocate_pages(uint32_t kind, uint32_t type, uint64_t pages, uint64_t *address)
{
    alloc_calls++;
    if (kind != 0) { strays++; return EFI_UNSUPPORTED; }
    if (fail_alloc_at && alloc_calls == fail_alloc_at) {
        if (fail_alloc_returns_zero) { *address = 0; return 0; }
        return fail_alloc_status;
    }
    void *memory = aligned_alloc(4096, pages * 4096);
    memset(memory, 0xa5, pages * 4096);
    alloc_log[alloc_count] = (struct fake_allocation){(uint64_t)(uintptr_t)memory, pages, type, 1, memory};
    alloc_count++;
    *address = (uint64_t)(uintptr_t)memory;
    return 0;
}
static efi_status fake_free_pages(uint64_t base, uint64_t pages)
{
    for (unsigned i = 0; i < alloc_count; i++) {
        if (alloc_log[i].live && alloc_log[i].base == base) {
            if (alloc_log[i].pages != pages) bad_frees++;
            alloc_log[i].live = 0;
            free(alloc_log[i].memory);
            return 0;
        }
    }
    bad_frees++;
    return EFI_INVALID_PARAMETER;
}
static unsigned live_allocations(void)
{
    unsigned n = 0;
    for (unsigned i = 0; i < alloc_count; i++) n += alloc_log[i].live;
    return n;
}

static uint8_t *blob(uint64_t size, uint8_t seed)
{
    uint8_t *p = malloc(size ? size : 1);
    uint32_t x = seed * 2654435761u + 1;
    for (uint64_t i = 0; i < size; i++) { x = x * 1664525u + 1013904223u; p[i] = (uint8_t)(x >> 24); }
    return p;
}

static void world_reset(void)
{
    for (unsigned v = 0; v < 2; v++) {
        for (unsigned i = 0; i < volume[v].count; i++) {
            if (volume[v].files[i].data) free((void *)volume[v].files[i].data);
        }
        memset(&volume[v], 0, sizeof volume[v]);
        volume[v].fs.revision = 0x10000;
        volume[v].fs.open_volume = fake_open_volume;
    }
    for (unsigned i = 0; i < alloc_count; i++) if (alloc_log[i].live) free(alloc_log[i].memory);
    memset(alloc_log, 0, sizeof alloc_log);
    alloc_count = alloc_calls = fail_alloc_at = fail_alloc_returns_zero = bad_frees = strays = handle_calls = 0;
    open_handles = non_read_opens = write_flags = 0;
    fail_alloc_status = EFI_ERROR(9);
    image_device = IMAGE_DEVICE;
    image_device_has_fs = 1;
    memset(&bs, 0, sizeof bs);
    bs.allocate_pages = fake_allocate_pages;
    bs.free_pages = fake_free_pages;
    bs.handle_protocol = fake_handle_protocol;
    bs.get_memory_map = trip_get_memory_map;
    bs.free_pool = trip_free_pool;
    bs.locate_handle = trip_locate_handle;
    bs.set_watchdog = trip_set_watchdog;
    bs.connect_controller = trip_connect_controller;
    bs.exit_boot_services = trip_exit_boot_services;
    bs.locate_handle_buffer = trip_locate_handle_buffer;
    bs.locate_protocol = trip_locate_protocol;
    bs.raise_tpl = bs.restore_tpl = (void *)trip_any;
    bs.allocate_pool = bs.create_event = bs.set_timer = bs.wait_event = (void *)trip_any;
    bs.signal_event = bs.close_event = bs.check_event = (void *)trip_any;
    bs.install_protocol = bs.reinstall_protocol = bs.uninstall_protocol = (void *)trip_any;
    bs.reserved = bs.register_notify = bs.locate_device_path = (void *)trip_any;
    bs.install_config = bs.load_image = bs.start_image = bs.exit = bs.unload_image = (void *)trip_any;
    bs.get_next_monotonic_count = bs.stall = bs.disconnect_controller = (void *)trip_any;
    bs.open_protocol = bs.close_protocol = bs.open_protocol_information = bs.protocols_per_handle = (void *)trip_any;
    memset(&image, 0, sizeof image);
    image.device = IMAGE_DEVICE;
}

static struct fake_entry *add_file(struct fake_volume *v, const char *path, uint8_t *data, uint64_t size)
{
    struct fake_entry *e = &v->files[v->count++];
    memset(e, 0, sizeof *e);
    snprintf(e->path, sizeof e->path, "%s", path);
    e->data = data;
    e->size = size;
    return e;
}

/* A manifest in memory, byte for byte what tools/preload.py writes. */
struct manifest_build { uint8_t bytes[sizeof(struct q1n1_preload_manifest)]; uint64_t size; };
static void manifest_make(struct manifest_build *m, unsigned count, const char *const paths[], uint8_t *const datas[],
                          const uint64_t sizes[])
{
    struct q1n1_preload_manifest man;
    memset(&man, 0, sizeof man);
    man.magic = Q1N1_PRELOAD_MAGIC; man.version = 1; man.count = count; man.entry_size = sizeof man.files[0];
    for (unsigned i = 0; i < count; i++) {
        man.files[i].size = sizes[i];
        q1n1_sha256(datas[i], sizes[i], man.files[i].sha256);
        snprintf(man.files[i].path, sizeof man.files[i].path, "%s", paths[i]);
    }
    m->size = 32 + count * sizeof man.files[0];
    memcpy(m->bytes, &man, m->size);
}

/* A stick with a manifest and `count` files: file 0 is the payload, the rest data (`.DAT`, which the runner never
 * calls: only <stem>.BIN names are payloads). */
static struct manifest_build good_manifest;
static const char *const names[6] = {"\\SP11\\STATE.BIN", "\\SP11\\DATA1.DAT", "\\SP11\\DATA2.DAT",
                                     "\\SP11\\DATA3.DAT", "\\SP11\\DATA4.DAT", "\\SP11\\DATA5.DAT"};
static uint8_t *good_data[6];
static uint64_t good_sizes[6] = {2000, 5000, 4096, 4097, 1, 100};

/* The same, with the files carrying the names given (file i holds the bytes of file i above). */
static void named_stick(struct fake_volume *v, const char *const paths[], unsigned count)
{
    for (unsigned i = 0; i < count; i++) {
        good_data[i] = blob(good_sizes[i], (uint8_t)(i + 1));
        add_file(v, paths[i], good_data[i], good_sizes[i]);
    }
    /* The manifest holds its own copies of the digests; the file entries own their blobs. */
    uint8_t *copies[6];
    for (unsigned i = 0; i < count; i++) copies[i] = good_data[i];
    manifest_make(&good_manifest, count, paths, copies, good_sizes);
    uint8_t *man = malloc(good_manifest.size);
    memcpy(man, good_manifest.bytes, good_manifest.size);
    add_file(v, Q1N1_PAYLOAD_MANIFEST_PATH, man, good_manifest.size);
}
static void good_stick(struct fake_volume *v, unsigned count)
{
    named_stick(v, names, count);
}
static struct fake_entry *entry_named(struct fake_volume *v, const char *path)
{
    for (unsigned i = 0; i < v->count; i++) if (same_ci(v->files[i].path, path)) return &v->files[i];
    return NULL;
}

static struct q1n1_payload_loaded loaded;
static struct q1n1_payload_diag diag;
static int prepare(void)
{
    return q1n1_payload_prepare(&bs, &image, &loaded, &diag);
}
static uint64_t volume_hash(struct fake_volume *v)
{
    uint64_t h = 1469598103934665603ull;
    for (unsigned i = 0; i < v->count; i++) {
        for (uint64_t k = 0; k < v->files[i].size; k++) h = (h ^ v->files[i].data[k]) * 1099511628211ull;
        h = (h ^ v->files[i].size) * 1099511628211ull;
    }
    return h;
}

/* ---- volume ------------------------------------------------------------------------------------------ */

static int suite_volume(void)
{
    world_reset();
    good_stick(&volume[0], 1);
    uint64_t before = volume_hash(&volume[0]);
    CHECK(prepare() == Q1N1_PAYLOAD_OK);
    CHECK(strays == 0 && handle_calls == 1);                    /* one HandleProtocol, on the image's device */
    CHECK(volume[0].volume_opens == 1 && volume[1].volume_opens == 0);
    CHECK(open_handles == 0);                                   /* the root and every file were closed */
    CHECK(non_read_opens == 0 && write_flags == 0);             /* every open was a plain read */
    CHECK(volume_hash(&volume[0]) == before);                   /* nothing on the volume changed */
    CHECK(volume[0].file_opens == 2);                           /* the manifest and the one file, nothing else */

    /* A manifest on a second volume is not looked at: the image's own volume has none. */
    world_reset();
    good_stick(&volume[1], 1);
    CHECK(prepare() == Q1N1_PAYLOAD_E_NO_MANIFEST);
    CHECK(volume[1].volume_opens == 0 && volume[1].file_opens == 0 && strays == 0);
    CHECK(live_allocations() == 0);

    /* Both volumes have one; the image's own wins, and the other volume is untouched. */
    world_reset();
    good_stick(&volume[0], 1);
    good_stick(&volume[1], 2);
    CHECK(prepare() == Q1N1_PAYLOAD_OK && loaded.count == 1);
    CHECK(volume[1].volume_opens == 0 && volume[1].file_opens == 0);

    /* No image, no device, no file system on the device, a volume that will not open. */
    world_reset();
    good_stick(&volume[0], 1);
    CHECK(q1n1_payload_prepare(&bs, NULL, &loaded, &diag) == Q1N1_PAYLOAD_E_NO_IMAGE);
    CHECK(handle_calls == 0);
    image.device = NULL;
    CHECK(prepare() == Q1N1_PAYLOAD_E_NO_DEVICE && handle_calls == 0);
    image.device = image_device = (efi_handle)(uintptr_t)0x9999;
    image_device_has_fs = 0;
    CHECK(prepare() == Q1N1_PAYLOAD_E_NO_VOLUME && handle_calls == 1 && strays == 0);
    CHECK(volume[0].volume_opens == 0 && volume[1].volume_opens == 0 && alloc_calls == 0);
    world_reset();
    good_stick(&volume[0], 1);
    volume[0].open_volume_error = EFI_ERROR(6);
    CHECK(prepare() == Q1N1_PAYLOAD_E_OPEN_VOLUME && diag.efi == EFI_ERROR(6));
    CHECK(live_allocations() == 0 && open_handles == 0 && alloc_calls == 0);
    return 0;
}

/* ---- manifest --------------------------------------------------------------------------------------- */

static int suite_manifest(void)
{
    struct fake_entry *m;
    world_reset();
    good_stick(&volume[0], 1);
    m = entry_named(&volume[0], Q1N1_PAYLOAD_MANIFEST_PATH);
    m->path[1] = 'X';                                           /* \XP11\PAYLOAD.MAN: the manifest is not there */
    CHECK(prepare() == Q1N1_PAYLOAD_E_NO_MANIFEST && diag.efi == EFI_NOT_FOUND);
    CHECK(alloc_calls == 0);

    /* The path is matched without regard to case, as FAT does. */
    world_reset();
    good_stick(&volume[0], 1);
    snprintf(entry_named(&volume[0], Q1N1_PAYLOAD_MANIFEST_PATH)->path, 64, "\\sp11\\payload.man");
    CHECK(prepare() == Q1N1_PAYLOAD_OK);

    /* GetInfo fails, reports a short reply, or the manifest is a directory. */
    world_reset();
    good_stick(&volume[0], 1);
    entry_named(&volume[0], Q1N1_PAYLOAD_MANIFEST_PATH)->info_error = EFI_ERROR(7);
    CHECK(prepare() == Q1N1_PAYLOAD_E_MANIFEST_IO && diag.efi == EFI_ERROR(7) && alloc_calls == 0);
    world_reset();
    good_stick(&volume[0], 1);
    entry_named(&volume[0], Q1N1_PAYLOAD_MANIFEST_PATH)->info_short = 1;
    CHECK(prepare() == Q1N1_PAYLOAD_E_MANIFEST_IO && alloc_calls == 0);
    world_reset();
    good_stick(&volume[0], 1);
    entry_named(&volume[0], Q1N1_PAYLOAD_MANIFEST_PATH)->is_dir = 1;
    CHECK(prepare() == Q1N1_PAYLOAD_E_MANIFEST_IO && alloc_calls == 0);

    /* Longer than the biggest manifest there is, shorter than a header, empty. */
    world_reset();
    good_stick(&volume[0], 1);
    m = entry_named(&volume[0], Q1N1_PAYLOAD_MANIFEST_PATH);
    free((void *)m->data);
    m->data = blob(sizeof(struct q1n1_preload_manifest) + 1, 9);
    m->size = sizeof(struct q1n1_preload_manifest) + 1;
    CHECK(prepare() == Q1N1_PAYLOAD_E_MANIFEST_BAD && alloc_calls == 0);
    for (uint64_t size = 0; size <= 40; size += 8) {
        world_reset();
        good_stick(&volume[0], 1);
        m = entry_named(&volume[0], Q1N1_PAYLOAD_MANIFEST_PATH);
        m->size = size;                                         /* a truncated copy of the real manifest */
        CHECK(prepare() == Q1N1_PAYLOAD_E_MANIFEST_BAD && alloc_calls == 0);
    }

    /* Corrupt each header field and the entry size: the shared validator refuses all of them. */
    for (unsigned offset = 0; offset < 32; offset += 8) {
        world_reset();
        good_stick(&volume[0], 1);
        m = entry_named(&volume[0], Q1N1_PAYLOAD_MANIFEST_PATH);
        ((uint8_t *)m->data)[offset] ^= 0x40;
        CHECK(prepare() == Q1N1_PAYLOAD_E_MANIFEST_BAD && alloc_calls == 0);
    }

    /* A read that fails, returns nothing, or claims more than it was asked for; one byte too many. */
    world_reset();
    good_stick(&volume[0], 1);
    entry_named(&volume[0], Q1N1_PAYLOAD_MANIFEST_PATH)->read_error_at = 40;
    CHECK(prepare() == Q1N1_PAYLOAD_E_MANIFEST_IO && alloc_calls == 0);
    world_reset();
    good_stick(&volume[0], 1);
    entry_named(&volume[0], Q1N1_PAYLOAD_MANIFEST_PATH)->over_report = 1;
    CHECK(prepare() == Q1N1_PAYLOAD_E_MANIFEST_IO && alloc_calls == 0);
    world_reset();
    good_stick(&volume[0], 1);
    entry_named(&volume[0], Q1N1_PAYLOAD_MANIFEST_PATH)->max_per_read = 7;   /* many short reads are fine */
    CHECK(prepare() == Q1N1_PAYLOAD_OK);
    world_reset();
    good_stick(&volume[0], 1);
    m = entry_named(&volume[0], Q1N1_PAYLOAD_MANIFEST_PATH);
    m->info_size = m->size - 1;                                 /* GetInfo says shorter than the file really is */
    CHECK(prepare() == Q1N1_PAYLOAD_E_MANIFEST_IO && alloc_calls == 0);   /* the probe for one more byte finds one */
    world_reset();
    good_stick(&volume[0], 1);
    m = entry_named(&volume[0], Q1N1_PAYLOAD_MANIFEST_PATH);
    m->zero_read = 1;
    m->max_per_read = 40;                                       /* the second read returns success and nothing */
    CHECK(prepare() == Q1N1_PAYLOAD_E_MANIFEST_IO && alloc_calls == 0);

    /* The runner's own rules, all before anything is allocated. */
    world_reset();
    good_stick(&volume[0], 6);
    CHECK(prepare() == Q1N1_PAYLOAD_E_TOO_MANY_FILES && diag.got == 6 && diag.expected == Q1N1_PAYLOAD_MAX_FILES);
    CHECK(alloc_calls == 0 && volume[0].file_opens == 1);       /* only the manifest was opened */
    world_reset();
    good_stick(&volume[0], 5);
    CHECK(prepare() == Q1N1_PAYLOAD_OK && loaded.count == 5);
    static const char *const bad_paths[] = {"\\EFI\\BOOT\\X.BIN", "\\SP11X\\A.BIN", "\\SP11\\", "\\A.BIN",
                                            "\\SP1\\A.BIN", "\\SP11\\PAYLOAD.MAN", "\\sp11\\payload.man"};
    for (unsigned i = 0; i < sizeof bad_paths / sizeof bad_paths[0]; i++) {
        world_reset();
        uint8_t *data = blob(100, 3);
        add_file(&volume[0], "\\SP11\\X.BIN", data, 100);
        struct manifest_build mb;
        const char *one[1] = {bad_paths[i]};
        uint8_t *datas[1] = {data};
        uint64_t sizes[1] = {100};
        manifest_make(&mb, 1, one, datas, sizes);
        uint8_t *man = malloc(mb.size);
        memcpy(man, mb.bytes, mb.size);
        add_file(&volume[0], Q1N1_PAYLOAD_MANIFEST_PATH, man, mb.size);
        int err = prepare();
        /* "\SP11\" alone and a path with no file name are refused by the shared validator first. */
        CHECK(err == Q1N1_PAYLOAD_E_BAD_PATH || err == Q1N1_PAYLOAD_E_MANIFEST_BAD);
        CHECK(alloc_calls == 0);
    }
    /* Paths below \SP11\ in any case, one level down included, are accepted: the manifest may be written by
     * hand in any case, and FAT does not tell them apart. */
    uint8_t *data = NULL;
    struct manifest_build mb;
    uint8_t *datas[1];
    uint64_t sizes[1] = {100};
    uint8_t *man;
    static const char *const deep_paths[] = {"\\SP11\\SUB\\X.BIN", "\\sp11\\sub\\x.bin", "\\Sp11\\Sub\\X.Bin"};
    for (unsigned c = 0; c < sizeof deep_paths / sizeof deep_paths[0]; c++) {
        world_reset();
        data = blob(100, 3);
        add_file(&volume[0], "\\sp11\\sub\\x.bin", data, 100);
        const char *deep[1] = {deep_paths[c]};
        datas[0] = data;
        manifest_make(&mb, 1, deep, datas, sizes);
        man = malloc(mb.size);
        memcpy(man, mb.bytes, mb.size);
        add_file(&volume[0], Q1N1_PAYLOAD_MANIFEST_PATH, man, mb.size);
        CHECK(prepare() == Q1N1_PAYLOAD_OK);
    }

    /* A file over the sweep's chunk budget is refused before a page is allocated. */
    world_reset();
    data = blob(100, 3);
    add_file(&volume[0], "\\SP11\\BIG.BIN", data, 100);
    const char *big[1] = {"\\SP11\\BIG.BIN"};
    datas[0] = data;
    sizes[0] = 100;
    manifest_make(&mb, 1, big, datas, sizes);
    struct q1n1_preload_manifest *raw = (struct q1n1_preload_manifest *)mb.bytes;
    raw->files[0].size = Q1N1_PAYLOAD_MAX_FILE_BYTES + 1;
    man = malloc(mb.size);
    memcpy(man, mb.bytes, mb.size);
    add_file(&volume[0], Q1N1_PAYLOAD_MANIFEST_PATH, man, mb.size);
    CHECK(prepare() == Q1N1_PAYLOAD_E_FILE_TOO_BIG && diag.got == Q1N1_PAYLOAD_MAX_FILE_BYTES + 1 && alloc_calls == 0);
    return 0;
}

/* ---- files ------------------------------------------------------------------------------------------ */

static int suite_files(void)
{
    struct fake_entry *e;
    world_reset();
    good_stick(&volume[0], 3);
    entry_named(&volume[0], names[1])->path[2] = 'Z';           /* the second file is not on the stick */
    CHECK(prepare() == Q1N1_PAYLOAD_E_FILE_OPEN && diag.index == 1 && diag.efi == EFI_NOT_FOUND);
    CHECK(live_allocations() == 0 && bad_frees == 0 && open_handles == 0);   /* file 0 was freed again */

    world_reset();
    good_stick(&volume[0], 2);
    e = entry_named(&volume[0], names[1]);
    e->info_size = e->size + 1;                                  /* a size the manifest does not have */
    CHECK(prepare() == Q1N1_PAYLOAD_E_FILE_SIZE && diag.index == 1 && diag.got == e->size + 1 && diag.expected == e->size);
    CHECK(live_allocations() == 0 && open_handles == 0);
    world_reset();
    good_stick(&volume[0], 1);
    entry_named(&volume[0], names[0])->is_dir = 1;
    CHECK(prepare() == Q1N1_PAYLOAD_E_FILE_SIZE && live_allocations() == 0 && alloc_calls == 0);
    world_reset();
    good_stick(&volume[0], 1);
    entry_named(&volume[0], names[0])->info_error = EFI_ERROR(7);
    CHECK(prepare() == Q1N1_PAYLOAD_E_FILE_SIZE && diag.efi == EFI_ERROR(7) && alloc_calls == 0);

    /* The file is longer than GetInfo said, so the probe for one more byte finds one. */
    world_reset();
    good_stick(&volume[0], 1);
    e = entry_named(&volume[0], names[0]);
    e->info_size = e->size;
    e->size += 4;
    e->data = realloc((void *)e->data, e->size);
    CHECK(prepare() == Q1N1_PAYLOAD_E_FILE_READ && diag.index == 0 && diag.got == 2000);
    CHECK(live_allocations() == 0);

    /* Reads: an error part way, nothing returned, more than asked, many short ones. */
    world_reset();
    good_stick(&volume[0], 1);
    entry_named(&volume[0], names[0])->read_error_at = 1000;
    CHECK(prepare() == Q1N1_PAYLOAD_E_FILE_READ && diag.efi == EFI_ERROR(7) && live_allocations() == 0);
    world_reset();
    good_stick(&volume[0], 1);
    e = entry_named(&volume[0], names[0]);
    e->zero_read = 1;
    e->max_per_read = 1000;
    CHECK(prepare() == Q1N1_PAYLOAD_E_FILE_READ && live_allocations() == 0);
    world_reset();
    good_stick(&volume[0], 1);
    entry_named(&volume[0], names[0])->over_report = 1;
    CHECK(prepare() == Q1N1_PAYLOAD_E_FILE_READ && live_allocations() == 0);
    world_reset();
    good_stick(&volume[0], 1);
    entry_named(&volume[0], names[0])->max_per_read = 13;
    CHECK(prepare() == Q1N1_PAYLOAD_OK);
    CHECK(!memcmp((void *)(uintptr_t)loaded.file[0].base, good_data[0], good_sizes[0]));

    /* Same size, different bytes: the digest refuses it, and says which prefixes disagreed. */
    world_reset();
    good_stick(&volume[0], 2);
    e = entry_named(&volume[0], names[1]);
    ((uint8_t *)e->data)[e->size - 1] ^= 1;
    CHECK(prepare() == Q1N1_PAYLOAD_E_HASH && diag.index == 1);
    CHECK(memcmp(diag.hash_want, diag.hash_have, 8) != 0);
    CHECK(live_allocations() == 0 && bad_frees == 0);
    char line[200];
    q1n1_payload_refusal_line(Q1N1_PAYLOAD_E_HASH, &diag, line, sizeof line);
    CHECK(!strncmp(line, "PAYLOAD REFUSED=HASH INDEX=1", 28));
    CHECK(strstr(line, " WANT=") && strstr(line, " HAVE="));

    /* The file is right and the manifest's digest is wrong in its last byte only: all 32 bytes count. */
    for (unsigned byte = 0; byte < 32; byte += 31) {
        world_reset();
        good_stick(&volume[0], 1);
        e = entry_named(&volume[0], Q1N1_PAYLOAD_MANIFEST_PATH);
        ((uint8_t *)e->data)[offsetof(struct q1n1_preload_manifest, files[0].sha256) + byte] ^= 0x10;
        CHECK(prepare() == Q1N1_PAYLOAD_E_HASH && diag.index == 0 && live_allocations() == 0);
    }
    return 0;
}

/* ---- memory ------------------------------------------------------------------------------------------ */

static const struct fake_allocation *allocation_at(uint64_t base)
{
    for (unsigned i = 0; i < alloc_count; i++) if (alloc_log[i].base == base) return &alloc_log[i];
    return NULL;
}

static int suite_memory(void)
{
    world_reset();
    good_stick(&volume[0], 5);
    CHECK(prepare() == Q1N1_PAYLOAD_OK && loaded.count == 5 && loaded.code_count == 1);
    /* Five files, the table and the stack: seven allocations, nothing else. */
    CHECK(alloc_calls == 7 && alloc_count == 7 && live_allocations() == 7);
    for (unsigned i = 0; i < 5; i++) {
        const struct q1n1_payload_file *f = &loaded.file[i];
        const struct fake_allocation *a = allocation_at(f->base);
        CHECK(a && a->live && !(f->base & 4095));
        CHECK(f->bytes == good_sizes[i] && f->alloc == (good_sizes[i] + 4095) / 4096 * 4096 && a->pages * 4096 == f->alloc);
        /* The payload is code; the data files are data. */
        CHECK(f->memory_type == (i == 0 ? Q1N1_PAYLOAD_TYPE_CODE : Q1N1_PAYLOAD_TYPE_DATA) && a->type == f->memory_type);
        CHECK(!memcmp((void *)(uintptr_t)f->base, good_data[i], good_sizes[i]));
        /* The rest of the last page is zeros, not what the allocator left there (0xa5). */
        for (uint64_t k = f->bytes; k < f->alloc; k++) CHECK(((uint8_t *)(uintptr_t)f->base)[k] == 0);
        uint8_t digest[32];
        q1n1_sha256(good_data[i], good_sizes[i], digest);
        CHECK(!memcmp(digest, f->sha256, 32));
    }
    CHECK(Q1N1_PAYLOAD_TYPE_CODE == 1 && Q1N1_PAYLOAD_TYPE_DATA == 2);
    const struct fake_allocation *table = allocation_at(loaded.table_base);
    const struct fake_allocation *stack = allocation_at(loaded.stack_base);
    CHECK(table && stack && table->type == 2 && stack->type == 2);
    CHECK(loaded.stack_alloc == Q1N1_PAYLOAD_STACK_BYTES && stack->pages * 4096 == Q1N1_PAYLOAD_STACK_BYTES);
    CHECK(table->pages * 4096 == loaded.table_alloc && loaded.table_alloc >= sizeof(struct q1n1_preload_cache));
    /* The stack is not written before the bounce: it still holds the allocator's poison. */
    CHECK(((uint8_t *)(uintptr_t)loaded.stack_base)[0] == 0xa5);

    /* The table is the A16 layout, so q1n1_preload_verify accepts every entry. */
    const struct q1n1_preload_cache *cache = (const void *)(uintptr_t)loaded.table_base;
    CHECK(cache->magic == Q1N1_CACHE_MAGIC && cache->version == 1 && cache->count == 5);
    CHECK(cache->entry_size == sizeof(cache->files[0]));
    for (unsigned i = 0; i < 5; i++) {
        CHECK(q1n1_preload_verify(cache, i) == 1);
        CHECK(cache->files[i].base == loaded.file[i].base && cache->files[i].allocation == loaded.file[i].alloc);
        CHECK(!strcmp(cache->files[i].file.path, names[i]));
    }
    CHECK(q1n1_preload_verify(cache, 5) == 0);
    /* The distinct allocations do not overlap. */
    for (unsigned i = 0; i < alloc_count; i++)
        for (unsigned j = i + 1; j < alloc_count; j++)
            CHECK(alloc_log[i].base + alloc_log[i].pages * 4096 <= alloc_log[j].base ||
                  alloc_log[j].base + alloc_log[j].pages * 4096 <= alloc_log[i].base);
    q1n1_payload_release(&bs, &loaded);
    CHECK(live_allocations() == 0 && bad_frees == 0 && loaded.count == 0 && loaded.code_count == 0 && loaded.table_base == 0);

    /* A failure at each allocation frees what came before it: the files, then the table, then the stack. */
    for (unsigned at = 1; at <= 4; at++) {
        world_reset();
        good_stick(&volume[0], 2);
        fail_alloc_at = at;
        CHECK(prepare() == Q1N1_PAYLOAD_E_NO_MEMORY && diag.efi == EFI_ERROR(9));
        CHECK(live_allocations() == 0 && bad_frees == 0 && open_handles == 0);
        CHECK(diag.expected != 0);                                  /* the size that could not be had */
    }
    /* A "success" that returns address 0 is no place to load a file. */
    world_reset();
    good_stick(&volume[0], 1);
    fail_alloc_at = 1;
    fail_alloc_returns_zero = 1;
    CHECK(prepare() == Q1N1_PAYLOAD_E_NO_MEMORY && live_allocations() == 0);

    /* Release is safe on a loaded struct that was never filled, and twice. */
    world_reset();
    memset(&loaded, 0, sizeof loaded);
    q1n1_payload_release(&bs, &loaded);
    q1n1_payload_release(&bs, &loaded);
    CHECK(alloc_calls == 0 && bad_frees == 0);
    return 0;
}

/* ---- kinds -------------------------------------------------------------------------------------------- */

/* The kind of every file of a stick, as the allocation types say it: 1 payload, 2 data. */
static int kinds_are(const unsigned want[], unsigned count)
{
    if (loaded.count != count) return 0;
    for (unsigned i = 0; i < count; i++) {
        const struct fake_allocation *a = allocation_at(loaded.file[i].base);
        if (loaded.file[i].memory_type != want[i] || !a || a->type != want[i]) return 0;
    }
    return 1;
}

static int suite_kinds(void)
{
    /* The rule on its own: <stem>.BIN in any case is a payload and nothing else is, so a data file can never be
     * called by being named like a payload in part. The stem must not be empty, and the last component of the
     * path decides. */
    static const struct { const char *path; int code; } rule[] = {
        {"\\SP11\\STATE.BIN", 1}, {"\\SP11\\state.bin", 1}, {"\\SP11\\State.Bin", 1}, {"\\SP11\\sTaTe.bIn", 1},
        {"\\SP11\\A.BIN", 1}, {"\\SP11\\SUB\\X.BIN", 1}, {"\\SP11\\A.B.BIN", 1}, {"\\A.BIN", 1},
        {"\\SP11\\X.TXT\\Y.BIN", 1},
        {"\\SP11\\DATA.DAT", 0}, {"\\SP11\\X.BIN.TXT", 0}, {"\\SP11\\X.BINX", 0}, {"\\SP11\\XBIN", 0}, {"\\SP11\\BIN", 0},
        {"\\SP11\\X.BI", 0}, {"\\SP11\\.BIN", 0}, {"\\.BIN", 0}, {"\\SP11\\SUB.BIN\\X.TXT", 0}, {"\\SP11\\X BIN", 0},
        {"\\SP11\\X-BIN", 0}, {"\\SP11\\X_BIN", 0}, {"BIN", 0}, {".BIN", 0}, {"", 0},
    };
    for (unsigned i = 0; i < sizeof rule / sizeof rule[0]; i++) {
        if (q1n1_payload_path_is_code(rule[i].path) != rule[i].code) fprintf(stderr, "kind of '%s': want %d\n", rule[i].path, rule[i].code);
        CHECK(q1n1_payload_path_is_code(rule[i].path) == rule[i].code);
    }

    /* Mixed order: the kind follows the name, not the index, and the types the firmware was asked for follow the kind. */
    static const char *const mixed[5] = {"\\SP11\\A.BIN", "\\SP11\\B.DAT", "\\SP11\\C.bin", "\\SP11\\D.TXT", "\\SP11\\E.Bin"};
    world_reset();
    named_stick(&volume[0], mixed, 5);
    CHECK(prepare() == Q1N1_PAYLOAD_OK && loaded.count == 5 && loaded.code_count == 3);
    CHECK(kinds_are((const unsigned[]){1, 2, 1, 2, 1}, 5));
    for (unsigned i = 0; i < 5; i++) {
        const struct q1n1_payload_file *f = &loaded.file[i];
        CHECK(q1n1_payload_file_is_code(f) == (i == 0 || i == 2 || i == 4));
        CHECK(!memcmp((void *)(uintptr_t)f->base, good_data[i], good_sizes[i]));      /* every file is read whatever it is */
        CHECK(strstr(loaded.note[i], i == 0 || i == 2 || i == 4 ? " TYPE=1" : " TYPE=2") != NULL);
    }
    /* The table is the same for both kinds, so a payload finds data and other payloads alike. */
    const struct q1n1_preload_cache *cache = (const void *)(uintptr_t)loaded.table_base;
    CHECK(cache->count == 5);
    for (unsigned i = 0; i < 5; i++) CHECK(q1n1_preload_verify(cache, i) == 1 && !strcmp(cache->files[i].file.path, mixed[i]));
    q1n1_payload_release(&bs, &loaded);
    CHECK(live_allocations() == 0 && loaded.code_count == 0);

    /* All five files may be payloads: the limit is on files, not on kinds. Any case of the extension counts. */
    static const char *const all_code[5] = {"\\SP11\\A.BIN", "\\sp11\\b.bin", "\\SP11\\C.Bin", "\\SP11\\D.bIN", "\\SP11\\E.bin"};
    world_reset();
    named_stick(&volume[0], all_code, 5);
    CHECK(prepare() == Q1N1_PAYLOAD_OK && loaded.count == 5 && loaded.code_count == 5);
    CHECK(kinds_are((const unsigned[]){1, 1, 1, 1, 1}, 5));
    world_reset();
    named_stick(&volume[0], names, 6);
    CHECK(prepare() == Q1N1_PAYLOAD_E_TOO_MANY_FILES && alloc_calls == 0);
    static const char *const six_code[6] = {"\\SP11\\A.BIN", "\\SP11\\B.BIN", "\\SP11\\C.BIN", "\\SP11\\D.BIN", "\\SP11\\E.BIN", "\\SP11\\F.BIN"};
    world_reset();
    named_stick(&volume[0], six_code, 6);
    CHECK(prepare() == Q1N1_PAYLOAD_E_TOO_MANY_FILES && diag.got == 6 && diag.expected == 5 && alloc_calls == 0 && live_allocations() == 0);

    /* Names that merely look like a payload's are data: only file 0's rule would otherwise save them. */
    static const char *const lookalikes[5] = {"\\SP11\\X.BIN", "\\SP11\\Y.BIN.TXT", "\\SP11\\Z.BINX", "\\SP11\\BIN", "\\SP11\\.BIN"};
    world_reset();
    named_stick(&volume[0], lookalikes, 5);
    CHECK(prepare() == Q1N1_PAYLOAD_OK && loaded.code_count == 1);
    CHECK(kinds_are((const unsigned[]){1, 2, 2, 2, 2}, 5));

    /* File 0 must be a payload: a manifest that starts with data is refused before anything is allocated, whatever
     * follows it, and without opening a single file but the manifest. */
    static const char *const starts_with_data[][2] = {
        {"\\SP11\\STATE.DAT", "\\SP11\\B.BIN"}, {"\\SP11\\state.dat", "\\SP11\\B.BIN"}, {"\\SP11\\X.BINX", "\\SP11\\B.BIN"},
        {"\\SP11\\BIN", "\\SP11\\B.BIN"}, {"\\SP11\\.BIN", "\\SP11\\B.BIN"}, {"\\SP11\\X.BIN.TXT", "\\SP11\\B.BIN"},
    };
    for (unsigned i = 0; i < sizeof starts_with_data / sizeof starts_with_data[0]; i++) {
        world_reset();
        named_stick(&volume[0], starts_with_data[i], 2);
        int err = prepare();
        if (err != Q1N1_PAYLOAD_E_FILE0_NOT_BIN) fprintf(stderr, "file 0 '%s': got %d\n", starts_with_data[i][0], err);
        CHECK(err == Q1N1_PAYLOAD_E_FILE0_NOT_BIN);
        CHECK(alloc_calls == 0 && live_allocations() == 0 && volume[0].file_opens == 1 && open_handles == 0);
        CHECK(loaded.count == 0 && loaded.code_count == 0);
    }
    char text[200];
    q1n1_payload_refusal_line(Q1N1_PAYLOAD_E_FILE0_NOT_BIN, &diag, text, sizeof text);
    CHECK(!strcmp(text, "PAYLOAD REFUSED=FILE0_NOT_BIN"));
    CHECK(strcmp(q1n1_payload_err_name(Q1N1_PAYLOAD_E_FILE0_NOT_BIN), "UNKNOWN") != 0);
    /* The count rule is checked first, so that six files that start with data are told what they are first told. */
    static const char *const six_data_first[6] = {"\\SP11\\A.DAT", "\\SP11\\B.BIN", "\\SP11\\C.BIN", "\\SP11\\D.BIN", "\\SP11\\E.BIN", "\\SP11\\F.BIN"};
    world_reset();
    named_stick(&volume[0], six_data_first, 6);
    CHECK(prepare() == Q1N1_PAYLOAD_E_TOO_MANY_FILES);
    /* A lone data file is no stick either. */
    static const char *const lone_data[1] = {"\\SP11\\A.DAT"};
    world_reset();
    named_stick(&volume[0], lone_data, 1);
    CHECK(prepare() == Q1N1_PAYLOAD_E_FILE0_NOT_BIN && alloc_calls == 0);
    /* And a lone payload in any case is a stick. */
    static const char *const lone_code[1] = {"\\SP11\\a.bin"};
    world_reset();
    named_stick(&volume[0], lone_code, 1);
    CHECK(prepare() == Q1N1_PAYLOAD_OK && loaded.count == 1 && loaded.code_count == 1);
    return 0;
}

/* ---- lines ------------------------------------------------------------------------------------------- */

static int suite_lines(void)
{
    world_reset();
    good_stick(&volume[0], 2);
    CHECK(prepare() == Q1N1_PAYLOAD_OK);
    CHECK(loaded.notes == 2);
    for (unsigned i = 0; i < 2; i++) {
        char want[128];
        uint8_t digest[32];
        q1n1_sha256(good_data[i], good_sizes[i], digest);
        snprintf(want, sizeof want, "PAYLOAD LOADED INDEX=%u BASE=0X%" PRIX64 " BYTES=%" PRIu64
                 " SHA=%02X%02X%02X%02X%02X%02X%02X%02X TYPE=%u", i, loaded.file[i].base, good_sizes[i],
                 digest[0], digest[1], digest[2], digest[3], digest[4], digest[5], digest[6], digest[7], i ? 2u : 1u);
        CHECK(!strcmp(loaded.note[i], want));
        CHECK(strlen(loaded.note[i]) <= Q1N1_PAYLOAD_LINE_MAX && !strchr(loaded.note[i], '\\'));
    }
    /* Notes stop at their capacity and are cut to the font. */
    for (unsigned i = 0; i < 20; i++) q1n1_payload_note(&loaded, "payload \\ note");
    CHECK(loaded.notes == Q1N1_PAYLOAD_NOTES);
    CHECK(!strcmp(loaded.note[Q1N1_PAYLOAD_NOTES - 1], "PAYLOAD _ NOTE"));
    char longline[300];
    memset(longline, 'a', sizeof longline - 1);
    longline[sizeof longline - 1] = 0;
    loaded.notes = 0;
    q1n1_payload_note(&loaded, longline);
    CHECK(strlen(loaded.note[0]) == Q1N1_PAYLOAD_LINE_MAX && loaded.note[0][0] == 'A');

    /* The refusal line: the name, the entry for a per-file error, the firmware status, byte counts. */
    struct q1n1_payload_diag d;
    memset(&d, 0, sizeof d);
    char text[200];
    CHECK(q1n1_payload_refusal_line(Q1N1_PAYLOAD_E_NO_MANIFEST, &d, text, sizeof text) == strlen(text));
    CHECK(!strcmp(text, "PAYLOAD REFUSED=NO_MANIFEST"));
    d.efi = EFI_ERROR(14);
    q1n1_payload_refusal_line(Q1N1_PAYLOAD_E_NO_MANIFEST, &d, text, sizeof text);
    CHECK(!strcmp(text, "PAYLOAD REFUSED=NO_MANIFEST EFI=0X800000000000000E"));
    d.efi = 0; d.index = 3; d.got = 7; d.expected = 9;
    q1n1_payload_refusal_line(Q1N1_PAYLOAD_E_FILE_SIZE, &d, text, sizeof text);
    CHECK(!strcmp(text, "PAYLOAD REFUSED=FILE_SIZE INDEX=3 GOT=7 WANT=9"));
    d.plan = Q1N1_PLAN_NOT_WB; d.range = 2; d.got = d.expected = 0;
    q1n1_payload_refusal_line(Q1N1_PAYLOAD_E_RANGES, &d, text, sizeof text);
    CHECK(!strcmp(text, "PAYLOAD REFUSED=RANGES REASON=NOT_WRITE_BACK RANGE=2"));
    CHECK(q1n1_payload_refusal_line(Q1N1_PAYLOAD_E_MAP, &d, text, 12) == 11 && !strcmp(text, "PAYLOAD REF"));
    CHECK(q1n1_payload_refusal_line(Q1N1_PAYLOAD_E_MAP, &d, text, 0) == 0);
    for (int err = Q1N1_PAYLOAD_OK; err <= Q1N1_PAYLOAD_E_DECLARE; err++)
        CHECK(strcmp(q1n1_payload_err_name(err), "UNKNOWN") != 0);
    CHECK(!strcmp(q1n1_payload_err_name(999), "UNKNOWN"));
    return 0;
}

int main(int argc, char **argv)
{
    static const struct { const char *name; int (*run)(void); } suites[] = {
        {"volume", suite_volume}, {"manifest", suite_manifest}, {"files", suite_files}, {"memory", suite_memory},
        {"kinds", suite_kinds}, {"lines", suite_lines},
    };
    unsigned ran = 0;
    for (unsigned i = 0; i < sizeof suites / sizeof suites[0]; i++) {
        if (argc > 1 && strcmp(argv[1], "all") && strcmp(argv[1], suites[i].name)) continue;
        if (suites[i].run()) { fprintf(stderr, "FAIL: suite %s\n", suites[i].name); return 1; }
        ran++;
    }
    printf("PASS: %u payload loader suites, %u checks\n", ran, checks);
    return 0;
}
