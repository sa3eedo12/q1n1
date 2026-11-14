/* SPDX-License-Identifier: MIT */
/* The runner's loader (sp11-payload.h). Everything here runs before ExitBootServices, through firmware
 * calls, and every refusal returns to the Shell without anything having been bounced.
 *
 * What it must never do, because a Surface Pro 11 stick is plugged into a machine with an internal
 * disk and no console to undo a mistake: connect a controller, enumerate block devices or volumes,
 * touch any volume other than the one the image came from, or write. It therefore makes only these
 * firmware calls: HandleProtocol on one handle (the image's DeviceHandle), OpenVolume, Open (read
 * mode), GetInfo, Read and Close on files, and AllocatePages and FreePages. A test
 * (tools/test-q1n1-sp11-payload-load.c) gives it a firmware in which every other call fails the run.
 *
 * Unlike the A16's q1n1_preload (preload.c), which connects every block device and scans every volume
 * for \Snapintosh\q1n1-preload.bin, this finds one manifest on one volume. It reuses that file's
 * manifest validator, so the format and its limits are shared. The read helpers below are a small copy
 * of preload.c's static ones: preload.c is part of every other image and cannot change here. */
#include "sp11-payload.h"
#include "sha256.h"

#if Q1N1_SP11_PAYLOAD

#define EFI_DEVICE_ERROR EFI_ERROR(7)
#define EFI_FILE_DIRECTORY 0x10u
#define PAGE_BYTES UINT64_C(4096)
#define READ_CHUNK UINT64_C(1048576)

/* EFI_SIMPLE_FILE_SYSTEM_PROTOCOL and EFI_FILE_INFO (UEFI 2.x 13.4 and 13.5). */
static efi_guid fs_guid = {0x964e5b22, 0x6459, 0x11d2, {0x8e, 0x39, 0, 0xa0, 0xc9, 0x69, 0x72, 0x3b}};
static efi_guid file_info_guid = {0x09576e92, 0x6d3f, 0x11d2, {0x8e, 0x39, 0, 0xa0, 0xc9, 0x69, 0x72, 0x3b}};
/* EFI_FILE_INFO: Size, FileSize, PhysicalSize, three EFI_TIMEs of 16 bytes, Attribute at byte 72, then
 * the name from byte 80. */
#define FILE_INFO_FILE_SIZE_WORD 1u
#define FILE_INFO_ATTRIBUTE_WORD 9u
#define FILE_INFO_NAME_OFFSET 80u

const char *q1n1_payload_err_name(int err)
{
    switch (err) {
    case Q1N1_PAYLOAD_OK: return "OK";
    case Q1N1_PAYLOAD_E_NO_IMAGE: return "NO_IMAGE";
    case Q1N1_PAYLOAD_E_NO_DEVICE: return "NO_DEVICE";
    case Q1N1_PAYLOAD_E_NO_VOLUME: return "NO_VOLUME";
    case Q1N1_PAYLOAD_E_OPEN_VOLUME: return "OPEN_VOLUME";
    case Q1N1_PAYLOAD_E_NO_MANIFEST: return "NO_MANIFEST";
    case Q1N1_PAYLOAD_E_MANIFEST_OPEN: return "MANIFEST_OPEN";
    case Q1N1_PAYLOAD_E_MANIFEST_IO: return "MANIFEST_IO";
    case Q1N1_PAYLOAD_E_MANIFEST_BAD: return "MANIFEST_BAD";
    case Q1N1_PAYLOAD_E_TOO_MANY_FILES: return "TOO_MANY_FILES";
    case Q1N1_PAYLOAD_E_FILE0_NOT_BIN: return "FILE0_NOT_BIN";
    case Q1N1_PAYLOAD_E_BAD_PATH: return "BAD_PATH";
    case Q1N1_PAYLOAD_E_FILE_OPEN: return "FILE_OPEN";
    case Q1N1_PAYLOAD_E_FILE_SIZE: return "FILE_SIZE";
    case Q1N1_PAYLOAD_E_FILE_TOO_BIG: return "FILE_TOO_BIG";
    case Q1N1_PAYLOAD_E_NO_MEMORY: return "NO_MEMORY";
    case Q1N1_PAYLOAD_E_FILE_READ: return "FILE_READ";
    case Q1N1_PAYLOAD_E_HASH: return "HASH";
    case Q1N1_PAYLOAD_E_RANGES: return "RANGES";
    case Q1N1_PAYLOAD_E_MAP: return "MAP";
    case Q1N1_PAYLOAD_E_DECLARE: return "DECLARE";
    default: return "UNKNOWN";
    }
}

static unsigned char fold(unsigned char c)
{
    return c >= 'A' && c <= 'Z' ? (unsigned char)(c + 32) : c;
}

static int starts_with_nocase(const char *text, const char *prefix)
{
    for (; *prefix; prefix++, text++)
        if (fold((unsigned char)*text) != fold((unsigned char)*prefix)) return 0;
    return 1;
}

static int equal_nocase(const char *a, const char *b)
{
    for (;; a++, b++) {
        if (fold((unsigned char)*a) != fold((unsigned char)*b)) return 0;
        if (!*a) return 1;
    }
}

/* The kind is decided by the file name alone, the last component of the path: <stem>.BIN is a payload
 * and anything else is data, so a name that merely contains or starts with it (X.BIN.TXT, BIN, .BIN) is
 * data. A file that is not called can only be misread, never run. */
int q1n1_payload_path_is_code(const char *path)
{
    size_t length = 0, name = 0;
    for (; path[length]; length++)
        if (path[length] == '\\') name = length + 1;
    if (length < name + 5) return 0;
    return equal_nocase(path + length - 4, ".BIN");
}

static void wide(char16 *dst, const char *src)
{
    do { *dst++ = (uint8_t)*src; } while (*src++);
}

static void zero(void *where, uint64_t bytes)
{
    uint8_t *p = where;
    while (bytes--) *p++ = 0;
}

static int digest_equal(const uint8_t *a, const uint8_t *b)
{
    uint8_t different = 0;
    for (unsigned i = 0; i < 32; i++) different |= (uint8_t)(a[i] ^ b[i]);
    return different == 0;
}

int q1n1_payload_open_volume(struct efi_boot_services *bs, const struct efi_loaded_image *image,
                             struct efi_file **root, struct q1n1_payload_diag *diag)
{
    struct efi_simple_fs *fs = NULL;
    *root = NULL;
    if (!image) return Q1N1_PAYLOAD_E_NO_IMAGE;
    if (!image->device) return Q1N1_PAYLOAD_E_NO_DEVICE;
    efi_status status = bs->handle_protocol(image->device, &fs_guid, (void **)&fs);
    if (status || !fs) {
        diag->efi = status;
        return Q1N1_PAYLOAD_E_NO_VOLUME;
    }
    status = fs->open_volume(fs, root);
    if (status || !*root) {
        diag->efi = status;
        *root = NULL;
        return Q1N1_PAYLOAD_E_OPEN_VOLUME;
    }
    return Q1N1_PAYLOAD_OK;
}

static efi_status file_size(struct efi_file *file, uint64_t *size)
{
    uint64_t data[128], n = sizeof data;
    efi_status status = file->get_info(file, &file_info_guid, &n, data);
    if (status) return status;
    /* A reply that is shorter than the fixed part, longer than the buffer, claims more than it holds,
     * or is a directory is not a file whose size can be trusted. */
    if (n < FILE_INFO_NAME_OFFSET || n > sizeof data || data[0] < FILE_INFO_NAME_OFFSET || data[0] > n ||
        (data[FILE_INFO_ATTRIBUTE_WORD] & EFI_FILE_DIRECTORY))
        return EFI_INVALID_PARAMETER;
    *size = data[FILE_INFO_FILE_SIZE_WORD];
    return 0;
}

/* Exactly `size` bytes and not one more: a file that is longer than the manifest says is not the file
 * that was reviewed. Reads in 1 MiB requests, as the A16 loader does. */
static efi_status read_exact(struct efi_file *file, void *data, uint64_t size, uint64_t *got)
{
    uint8_t *p = data;
    *got = 0;
    while (size) {
        uint64_t want = size > READ_CHUNK ? READ_CHUNK : size, n = want;
        efi_status status = file->read(file, &n, p);
        if (status) return status;
        if (!n || n > want) return EFI_DEVICE_ERROR;
        p += n;
        size -= n;
        *got += n;
    }
    uint8_t extra;
    uint64_t n = 1;
    efi_status status = file->read(file, &n, &extra);
    return status ? status : n ? EFI_INVALID_PARAMETER : 0;
}

void q1n1_payload_note(struct q1n1_payload_loaded *loaded, const char *line)
{
    if (loaded->notes >= Q1N1_PAYLOAD_NOTES) return;
    char *dst = loaded->note[loaded->notes];
    unsigned n = 0;
    while (line[n] && n < Q1N1_PAYLOAD_LINE_MAX) {
        dst[n] = line[n];
        n++;
    }
    dst[n] = 0;
    q1n1_payload_sanitize(dst);
    loaded->notes++;
}

/* The parser buffer lives outside the stack: the freestanding COFF target has no __chkstk runtime, and
 * the EFI entry is single threaded. */
static struct q1n1_preload_manifest manifest;

static int read_manifest(struct efi_file *root, struct q1n1_payload_diag *diag)
{
    char16 name[256];
    struct efi_file *file = NULL;
    wide(name, Q1N1_PAYLOAD_MANIFEST_PATH);
    efi_status status = root->open(root, &file, name, Q1N1_PAYLOAD_FILE_MODE_READ, 0);
    if (status || !file) {
        diag->efi = status;
        return status == EFI_NOT_FOUND ? Q1N1_PAYLOAD_E_NO_MANIFEST : Q1N1_PAYLOAD_E_MANIFEST_OPEN;
    }
    uint64_t bytes = 0, got = 0;
    status = file_size(file, &bytes);
    if (!status && bytes > sizeof manifest) {
        file->close(file);
        diag->expected = sizeof manifest;
        diag->got = bytes;
        return Q1N1_PAYLOAD_E_MANIFEST_BAD;
    }
    zero(&manifest, sizeof manifest);
    if (!status) status = read_exact(file, &manifest, bytes, &got);
    file->close(file);
    if (status) {
        diag->efi = status;
        diag->expected = bytes;
        diag->got = got;
        return Q1N1_PAYLOAD_E_MANIFEST_IO;
    }
    if (!q1n1_preload_manifest_valid(&manifest, bytes)) return Q1N1_PAYLOAD_E_MANIFEST_BAD;
    return Q1N1_PAYLOAD_OK;
}

/* What the runner adds to the manifest's own rules, all of it before anything is allocated. */
static int check_manifest(struct q1n1_payload_diag *diag)
{
    if (manifest.count > Q1N1_PAYLOAD_MAX_FILES) {
        diag->expected = Q1N1_PAYLOAD_MAX_FILES;
        diag->got = manifest.count;
        return Q1N1_PAYLOAD_E_TOO_MANY_FILES;
    }
    for (uint32_t i = 0; i < manifest.count; i++) {
        const struct q1n1_preload_file *f = &manifest.files[i];
        diag->index = i;
        if (!starts_with_nocase(f->path, Q1N1_PAYLOAD_DIR) || equal_nocase(f->path, Q1N1_PAYLOAD_MANIFEST_PATH))
            return Q1N1_PAYLOAD_E_BAD_PATH;
        if (f->size > Q1N1_PAYLOAD_MAX_FILE_BYTES) {
            diag->expected = Q1N1_PAYLOAD_MAX_FILE_BYTES;
            diag->got = f->size;
            return Q1N1_PAYLOAD_E_FILE_TOO_BIG;
        }
    }
    diag->index = 0;
    /* The chain starts at file 0, so a manifest whose first entry is data has nothing to call. Asked after
     * the rules about where a file may be, which are the more serious. */
    if (!q1n1_payload_path_is_code(manifest.files[0].path)) return Q1N1_PAYLOAD_E_FILE0_NOT_BIN;
    return Q1N1_PAYLOAD_OK;
}

/* Allocates whole pages of one memory type. A result that is zero or not page aligned is not a place
 * q1n1_preload_verify would accept, so it is a failure too. */
static int allocate(struct efi_boot_services *bs, uint32_t type, uint64_t bytes, uint64_t *base,
                    struct q1n1_payload_diag *diag)
{
    uint64_t address = 0;
    efi_status status = bs->allocate_pages(Q1N1_PAYLOAD_ALLOCATE_ANY_PAGES, type, bytes / PAGE_BYTES, &address);
    if (!status && (!address || (address & (PAGE_BYTES - 1)))) {
        bs->free_pages(address, bytes / PAGE_BYTES);
        status = EFI_INVALID_PARAMETER;
    }
    if (status) {
        diag->efi = status;
        diag->expected = bytes;     /* which allocation: a file, the table or the stack */
        diag->got = 0;
        return Q1N1_PAYLOAD_E_NO_MEMORY;
    }
    *base = address;
    return Q1N1_PAYLOAD_OK;
}

static int load_file(struct efi_boot_services *bs, struct efi_file *root, struct q1n1_payload_loaded *out,
                     uint32_t index, struct q1n1_payload_diag *diag)
{
    const struct q1n1_preload_file *want = &manifest.files[index];
    char16 name[256];
    struct efi_file *file = NULL;
    diag->index = index;
    wide(name, want->path);
    efi_status status = root->open(root, &file, name, Q1N1_PAYLOAD_FILE_MODE_READ, 0);
    if (status || !file) {
        diag->efi = status;
        return Q1N1_PAYLOAD_E_FILE_OPEN;
    }
    uint64_t bytes = 0, got = 0;
    status = file_size(file, &bytes);
    if (status || bytes != want->size) {
        file->close(file);
        diag->efi = status;
        diag->expected = want->size;
        diag->got = bytes;
        return Q1N1_PAYLOAD_E_FILE_SIZE;
    }
    struct q1n1_payload_file *entry = &out->file[index];
    entry->bytes = bytes;
    entry->alloc = (bytes + PAGE_BYTES - 1) & ~(PAGE_BYTES - 1);
    entry->memory_type = q1n1_payload_path_is_code(want->path) ? Q1N1_PAYLOAD_TYPE_CODE : Q1N1_PAYLOAD_TYPE_DATA;
    int err = allocate(bs, entry->memory_type, entry->alloc, &entry->base, diag);
    if (err) {
        file->close(file);
        return err;
    }
    out->count = index + 1;     /* from here on release() frees it */
    out->code_count += q1n1_payload_file_is_code(entry);
    status = read_exact(file, (void *)(uintptr_t)entry->base, bytes, &got);
    file->close(file);
    if (status) {
        diag->efi = status;
        diag->expected = bytes;
        diag->got = got;
        return Q1N1_PAYLOAD_E_FILE_READ;
    }
    /* The rest of the last page is not the file's: a payload that reads past its end sees zeros, not
     * whatever the firmware left there. */
    zero((uint8_t *)(uintptr_t)entry->base + bytes, entry->alloc - bytes);
    q1n1_sha256((const void *)(uintptr_t)entry->base, (size_t)bytes, entry->sha256);
    if (!digest_equal(entry->sha256, want->sha256)) {
        for (unsigned i = 0; i < 8; i++) {
            diag->hash_want[i] = want->sha256[i];
            diag->hash_have[i] = entry->sha256[i];
        }
        return Q1N1_PAYLOAD_E_HASH;
    }
    return Q1N1_PAYLOAD_OK;
}

/* The table a payload finds its files in: the A16's resident cache, so a payload and the host tools
 * that already know that layout read it alike. It is declared to the sweep like any other range. */
static int build_table(struct efi_boot_services *bs, struct q1n1_payload_loaded *out,
                       struct q1n1_payload_diag *diag)
{
    uint64_t bytes = (sizeof(struct q1n1_preload_cache) + PAGE_BYTES - 1) & ~(PAGE_BYTES - 1);
    int err = allocate(bs, Q1N1_PAYLOAD_TYPE_DATA, bytes, &out->table_base, diag);
    if (err) return err;
    out->table_alloc = bytes;
    struct q1n1_preload_cache *cache = (void *)(uintptr_t)out->table_base;
    zero(cache, bytes);
    cache->magic = Q1N1_CACHE_MAGIC;
    cache->version = 1;
    cache->count = manifest.count;
    cache->entry_size = sizeof(cache->files[0]);
    for (uint32_t i = 0; i < manifest.count; i++) {
        cache->files[i].base = out->file[i].base;
        cache->files[i].allocation = out->file[i].alloc;
        cache->files[i].file = manifest.files[i];
    }
    return Q1N1_PAYLOAD_OK;
}

static void add_notes(struct q1n1_payload_loaded *out)
{
    for (uint32_t i = 0; i < out->count; i++) {
        struct q1n1_payload_line line;
        q1n1_payload_line_begin(&line, "PAYLOAD LOADED");
        q1n1_payload_line_dec(&line, "INDEX", i);
        q1n1_payload_line_hex(&line, "BASE", out->file[i].base);
        q1n1_payload_line_dec(&line, "BYTES", out->file[i].bytes);
        q1n1_payload_line_digest(&line, "SHA", out->file[i].sha256);
        q1n1_payload_line_dec(&line, "TYPE", out->file[i].memory_type);
        q1n1_payload_note(out, line.buf);
    }
}

void q1n1_payload_release(struct efi_boot_services *bs, struct q1n1_payload_loaded *loaded)
{
    for (uint32_t i = 0; i < loaded->count && i < Q1N1_PAYLOAD_MAX_FILES; i++)
        if (loaded->file[i].base) bs->free_pages(loaded->file[i].base, loaded->file[i].alloc / PAGE_BYTES);
    if (loaded->table_base) bs->free_pages(loaded->table_base, loaded->table_alloc / PAGE_BYTES);
    if (loaded->stack_base) bs->free_pages(loaded->stack_base, loaded->stack_alloc / PAGE_BYTES);
    zero(loaded, sizeof *loaded);
}

int q1n1_payload_prepare(struct efi_boot_services *bs, const struct efi_loaded_image *image,
                         struct q1n1_payload_loaded *out, struct q1n1_payload_diag *diag)
{
    zero(out, sizeof *out);
    zero(diag, sizeof *diag);
    struct efi_file *root = NULL;
    int err = q1n1_payload_open_volume(bs, image, &root, diag);
    if (err) return err;
    err = read_manifest(root, diag);
    if (!err) err = check_manifest(diag);
    for (uint32_t i = 0; !err && i < manifest.count; i++) err = load_file(bs, root, out, i, diag);
    root->close(root);
    if (!err) err = build_table(bs, out, diag);
    if (!err) {
        err = allocate(bs, Q1N1_PAYLOAD_TYPE_DATA, Q1N1_PAYLOAD_STACK_BYTES, &out->stack_base, diag);
        if (!err) out->stack_alloc = Q1N1_PAYLOAD_STACK_BYTES;
    }
    if (err) {
        q1n1_payload_release(bs, out);
        return err;
    }
    add_notes(out);
    return Q1N1_PAYLOAD_OK;
}

/* Which refusals concern one manifest entry. */
static int names_an_entry(int err)
{
    return err == Q1N1_PAYLOAD_E_BAD_PATH || err == Q1N1_PAYLOAD_E_FILE_OPEN || err == Q1N1_PAYLOAD_E_FILE_SIZE ||
           err == Q1N1_PAYLOAD_E_FILE_TOO_BIG || err == Q1N1_PAYLOAD_E_FILE_READ || err == Q1N1_PAYLOAD_E_HASH;
}

size_t q1n1_payload_refusal_line(int err, const struct q1n1_payload_diag *diag, char *dst, size_t cap)
{
    struct q1n1_payload_line line;
    q1n1_payload_line_begin(&line, "PAYLOAD REFUSED=");
    q1n1_payload_line_raw(&line, q1n1_payload_err_name(err));
    if (names_an_entry(err)) q1n1_payload_line_dec(&line, "INDEX", diag->index);
    if (diag->efi) q1n1_payload_line_hex(&line, "EFI", diag->efi);
    if (diag->expected || diag->got) {
        q1n1_payload_line_dec(&line, "GOT", diag->got);
        q1n1_payload_line_dec(&line, "WANT", diag->expected);
    }
    if (err == Q1N1_PAYLOAD_E_HASH) {
        q1n1_payload_line_digest(&line, "WANT", diag->hash_want);
        q1n1_payload_line_digest(&line, "HAVE", diag->hash_have);
    }
    if (err == Q1N1_PAYLOAD_E_RANGES) {
        q1n1_payload_line_raw(&line, " REASON=");
        q1n1_payload_line_raw(&line, q1n1_payload_plan_name(diag->plan));
        q1n1_payload_line_dec(&line, "RANGE", diag->range);
    }
    size_t n = 0;
    if (cap) {
        while (line.buf[n] && n + 1 < cap) {
            dst[n] = line.buf[n];
            n++;
        }
        dst[n] = 0;
    }
    return n;
}

#endif /* Q1N1_SP11_PAYLOAD */
