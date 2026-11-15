/* SPDX-License-Identifier: MIT */
/* Payload "hashbig": how fast a payload at EL2 can hash the biggest file the runner loaded, whether that file's memory is mapped
 * cacheable, and where the firmware put it (docs/SP11-PAYLOAD-HASHBIG.md). READ ONLY: MRS, one AT S1E2R, ISB, plain loads, and stores
 * only to its own stack (tools/sp11_payload_memcheck.py proves the stores from the binary). EXPERIMENTAL; hardware NOT RUN.
 *
 * Why. The monitor's wrapper must verify its bundle itself: the runner re-hashes payloads at EL2 but not data files ("data files are
 * not re-hashed at EL2", docs/SP11-PAYLOAD.md), and the bundle is a 115 to 144 MiB data file. Whether plain C at EL2 can do that
 * in seconds or in minutes depends on the memory attributes of the loaded file (U6), which AT S1E2R answers without touching it.
 *
 * What it does, in this order, and what it refuses.
 *  1. CurrentEL; not at EL2 it prints one line and does nothing else (AT S1E2R is UNDEFINED below EL2). The map must pass the same
 *     checks as in el2mem (payload-mmu.h), and the arguments must carry the counter op.
 *  2. The data file: the preload table (a->preload_table, struct q1n1_preload_cache) is checked (magic, version, entry size, count and
 *     size against preload_size) and its largest entry that is not a payload is chosen: not named <stem>.BIN in any case and not this
 *     payload's own base. The first of equal sizes wins. No such entry: refused.
 *  3. The extent: base page aligned, a size of at least one byte and at most 256 MiB (the runner's own cap), the whole of
 *     [base, base + size) inside descriptors of type 1 or 2 of the final map (the memory the runner allocated), else refused. Nothing
 *     is read of the file before this passes.
 *  4. AT S1E2R at the first, middle and last page of the file: attribute and shareability are printed. A page that is not mapped
 *     refuses the hash (the load would abort). Device and non-cacheable mappings are reported and still hashed: slow is the answer.
 *  5. SHA-256 over the file in 64 KiB steps with plain loads, timed with ops.counter. After every step the time box (25 s) and a stuck
 *     counter (256 steps in a row with the same value: no tick in 16 MiB) are checked, so that a counter that does not run ends the
 *     loop too. A file is at most 256 MiB, so the loop ends by its own bound as well. TIMEBOX, COUNTER_STUCK or the digest ends it.
 *
 * Loads: only the stack, the arguments, the map, the preload table and, in the one function pl_sha256_blocks and the tail copy, the
 * extent that step 3 verified. The tail beyond the file's last byte is never read. Stores: the payload's own stack. Lines: at most
 * 12, each at most 100 characters. Return: 0 for MATCH, TIMEBOX and COUNTER_STUCK, 1 bad arguments, 2 not at EL2, 3 map refused,
 * 4 no data file or a bad table, 5 extent refused, 6 digest differs, 7 a page of the file is not mapped. */
#define PL_PAGE_PREFIX "PAYLOAD HASHBIG "
#ifndef PL_PAGE_LINES
#define PL_PAGE_LINES 12u       /* a test may build a smaller page to see the budget work; the shipped binary never does */
#endif
#include "payload-page.h"
#include "payload-mmu.h"
#include "payload-sha256.h"
#include "preload.h"

#ifdef Q1N1_PAYLOAD_HOST_TEST
uint64_t pl_host_sysreg(const char *name);
#define SYSREG(name) pl_host_sysreg(#name)
#else
#define SYSREG(name) ({ uint64_t value_; __asm__ volatile("mrs %0, " #name : "=r"(value_)); value_; })
#endif

#define OUT_OF_LINE static __attribute__((noinline))

#define ESSENTIAL_LINES 2u              /* the NEXT line and the DONE line */
#define MIB (UINT64_C(1) << 20)
#define FILE_BYTES_MAX (UINT64_C(256) << 20)
#define TIME_BOX_S 25u
#define CHECK_BLOCKS 1024u              /* 64 KiB between two looks at the counter */
#define STUCK_CHECKS 256u
#define COUNTER_HZ_DEFAULT 19200000u
#define COUNTER_HZ_MIN 1000000u
#define COUNTER_HZ_MAX 1000000000u
#define TICKS_SHOWN_MAX (UINT64_C(1) << 43)     /* keeps ticks * 1000 and ticks * 2^20 inside 64 bits */

enum {
    RET_OK = 0, RET_NOT_EL2 = 2, RET_MAP = 3, RET_NO_FILE = 4, RET_EXTENT = 5, RET_DIFFER = 6, RET_NOT_MAPPED = 7,
};
enum { TABLE_OK, TABLE_NONE, TABLE_HEADER, TABLE_SIZE, TABLE_NO_DATA_FILE };
enum { EXTENT_OK, EXTENT_ALIGN, EXTENT_SIZE, EXTENT_WRAPS, EXTENT_NOT_ALLOCATED };
enum { HASH_DONE, HASH_TIMEBOX, HASH_STUCK };

struct file {
    uint64_t index, base, size;
};

struct hash_result {
    uint64_t hashed, ticks;
    unsigned state;
    uint8_t digest[32];
};

OUT_OF_LINE void add_walk(const struct q1n1_payload_args *a, struct pl_page *p, const char *key, const struct pl_walk *w)
{
    struct pl_line item;
    pl_begin(&item);
    pl_text(&item, key);
    pl_text(&item, "=");
    pl_put_walk(a, &item, w);
    pl_page_add(a, p, item.buf);
}

/* ---- The preload table, read in place through the arguments' pointer -------------------------------------------------------- */

/* Inline on purpose: a pointer returned by a call would lose where it came from, and the binary check proves reads from that. */
static inline const struct q1n1_cached_file *entry(const struct q1n1_payload_args *a, uint64_t index)
{
    return &((const struct q1n1_preload_cache *)(uintptr_t)a->preload_table)->files[index];
}

/* A file name that ends in .BIN in any case, after the last backslash and with something before the dot, is a payload; so is a path
 * with no terminator in its 256 bytes, which is never a file to hash. */
OUT_OF_LINE int path_is_payload(const char *path)
{
    uint32_t length = 0, name = 0;
    while (length < sizeof(((struct q1n1_preload_file *)0)->path) && path[length]) {
        if (path[length] == '\\') name = length + 1;
        length++;
    }
    if (length == sizeof(((struct q1n1_preload_file *)0)->path)) return 1;
    if (length - name < 5) return 0;
    return path[length - 4] == '.' && (path[length - 3] | 32) == 'b' && (path[length - 2] | 32) == 'i' && (path[length - 1] | 32) == 'n';
}

/* TABLE_OK and the largest data file, or why not. Reads the table only inside preload_size. */
OUT_OF_LINE unsigned find_file(const struct q1n1_payload_args *a, struct file *f)
{
    const struct q1n1_preload_cache *t = (const struct q1n1_preload_cache *)(uintptr_t)a->preload_table;
    uint64_t found = 0;
    if (!a->preload_table || (a->preload_table & 7u) || a->preload_table >= PL_ADDRESS_LIMIT || a->preload_size < 32u ||
        a->preload_size > PL_ADDRESS_LIMIT - a->preload_table)
        return TABLE_NONE;
    if (t->magic != Q1N1_CACHE_MAGIC || t->version != 1 || t->entry_size != sizeof(struct q1n1_cached_file)) return TABLE_HEADER;
    if (t->count > Q1N1_PRELOAD_MAX || 32u + t->count * sizeof(struct q1n1_cached_file) > a->preload_size) return TABLE_SIZE;
    for (uint64_t i = 0; i < t->count; i++) {
        const struct q1n1_cached_file *e = entry(a, i);
        if (e->base == a->payload_base || !e->file.size || path_is_payload(e->file.path)) continue;
        if (!found || e->file.size > f->size) {
            f->index = i;
            f->base = e->base;
            f->size = e->file.size;
            found = 1;
        }
    }
    return found ? TABLE_OK : TABLE_NO_DATA_FILE;
}

/* ---- The extent ---------------------------------------------------------------------------------------------------------------- */

/* EXTENT_OK when every byte of [base, base + size) is inside descriptors of type 1 or 2, which the loader allocated, and the number of
 * descriptors it took; *at is where it stopped on a refusal. */
OUT_OF_LINE unsigned extent_check(const struct q1n1_payload_args *a, uint64_t base, uint64_t size, uint64_t *segments, uint64_t *at)
{
    struct pl_desc d;
    uint64_t count = a->map_size / a->map_stride, cursor = base, end;
    *segments = 0;
    if (base & (PL_PAGE_BYTES - 1)) return EXTENT_ALIGN;
    if (!size || size > FILE_BYTES_MAX) return EXTENT_SIZE;
    if (base >= PL_ADDRESS_LIMIT || size > PL_ADDRESS_LIMIT - base) return EXTENT_WRAPS;
    end = base + size;
    while (cursor < end) {
        uint64_t next = cursor;
        for (uint64_t i = 0; i < count; i++) {
            if (pl_desc_read(a, i, &d) && (d.type == PL_EFI_LOADER_CODE || d.type == PL_EFI_LOADER_DATA) && d.start <= cursor &&
                cursor < d.end && d.end > next)
                next = d.end;
        }
        if (next == cursor) {
            *at = cursor;
            return EXTENT_NOT_ALLOCATED;
        }
        cursor = next;
        (*segments)++;
    }
    return EXTENT_OK;
}

OUT_OF_LINE void say_extent_refusal(const struct q1n1_payload_args *a, struct pl_page *p, unsigned code, uint64_t at)
{
    pl_page_open(p, "EXTENT", 0);
    switch (code) {
    case EXTENT_ALIGN: pl_page_add(a, p, "REFUSED=BASE_NOT_PAGE_ALIGNED"); break;
    case EXTENT_SIZE: pl_page_add(a, p, "REFUSED=SIZE_ZERO_OR_OVER_256_MIB"); break;
    case EXTENT_WRAPS: pl_page_add(a, p, "REFUSED=BEYOND_THE_48_BIT_SPACE"); break;
    default:
        pl_page_add(a, p, "REFUSED=NOT_IN_ALLOCATED_DESCRIPTORS");
        pl_add_hex(a, p, "AT", at);
        break;
    }
    pl_page_flush(a, p);
}

/* ---- The hash ------------------------------------------------------------------------------------------------------------------ */

/* The bytes after the last whole block: the only reads of the file that are not whole blocks, and never past its last byte. */
OUT_OF_LINE void copy_tail(uint8_t *block, const uint8_t *from, uint32_t bytes)
{
    for (uint32_t i = 0; i < bytes; i++) block[i] = from[i];
}

OUT_OF_LINE void hash_file(const struct q1n1_payload_args *a, uint64_t freq, uint64_t base, uint64_t size, struct hash_result *r)
{
    struct pl_sha256 state;
    uint8_t block[128] __attribute__((aligned(8)));
    const uint8_t *p = (const uint8_t *)(uintptr_t)base;
    uint64_t blocks = size / 64, done = 0, limit = TIME_BOX_S * freq;
    uint64_t start = a->ops.counter(), last = start, now = start;
    uint32_t same = 0;
    pl_sha256_init(&state);
    r->state = HASH_DONE;
    while (done < blocks) {
        uint64_t n = blocks - done < CHECK_BLOCKS ? blocks - done : CHECK_BLOCKS;
        pl_sha256_blocks(&state, p + done * 64, n);
        done += n;
        now = a->ops.counter();
        if (done == blocks) break;
        if (now < start || now - start >= limit) {
            r->state = HASH_TIMEBOX;
            break;
        }
        if (now == last) {
            if (++same >= STUCK_CHECKS) {
                r->state = HASH_STUCK;
                break;
            }
        } else {
            last = now;
            same = 0;
        }
    }
    r->hashed = done * 64;
    if (r->state == HASH_DONE) {
        pl_zero(block, sizeof block);
        copy_tail(block, p + blocks * 64, (uint32_t)(size % 64));
        pl_sha256_finish(&state, block, (uint32_t)(size % 64), size, r->digest);
        r->hashed = size;
        now = a->ops.counter();
    }
    r->ticks = now - start;
}

/* ---- Reports ------------------------------------------------------------------------------------------------------------------- */

/* The first eight bytes of a digest as 16 upper-case hex digits (ops.hex drops leading zeros). */
OUT_OF_LINE void put_hex16(struct pl_line *line, const uint8_t *bytes)
{
    for (unsigned i = 0; i < 8; i++) {
        pl_text(line, (const char[]){"0123456789ABCDEF"[bytes[i] >> 4], 0});
        pl_text(line, (const char[]){"0123456789ABCDEF"[bytes[i] & 15], 0});
    }
}

/* Does the digest the loop made equal the runner's? 32 bytes, all of them. */
OUT_OF_LINE int digest_matches(const struct q1n1_payload_args *a, const struct file *f, const uint8_t *digest)
{
    const struct q1n1_cached_file *e = entry(a, f->index);
    unsigned different = 0;
    for (unsigned i = 0; i < 32; i++) different |= digest[i] ^ e->file.sha256[i];
    return !different;
}

OUT_OF_LINE void report_rate(const struct q1n1_payload_args *a, struct pl_page *p, uint64_t freq, const struct hash_result *r)
{
    pl_page_open(p, "HASH", 0);
    pl_add_dec(a, p, "BYTES", r->hashed);
    pl_add_dec(a, p, "TICKS", r->ticks);
    if (!r->ticks || r->ticks >= TICKS_SHOWN_MAX) {
        pl_page_add(a, p, "RATE=UNKNOWN_COUNTER");
    } else {
        pl_add_dec(a, p, "MS", r->ticks * 1000u / freq);
        pl_add_dec(a, p, "MIBS", r->hashed * freq / (r->ticks * MIB));
    }
    pl_page_flush(a, p);
}

OUT_OF_LINE void report_digest(const struct q1n1_payload_args *a, struct pl_page *p, const struct file *f, const struct hash_result *r,
                               int match)
{
    struct pl_line item;
    pl_page_open(p, "DIGEST", 0);
    pl_begin(&item);
    put_hex16(&item, r->digest);
    pl_page_add(a, p, item.buf);
    pl_page_add(a, p, match ? "MATCH" : "DIFFER");
    if (!match) {
        pl_begin(&item);
        pl_text(&item, "WANT=");
        put_hex16(&item, entry(a, f->index)->file.sha256);
        pl_page_add(a, p, item.buf);
    }
    pl_page_flush(a, p);
}

OUT_OF_LINE void report_incomplete(const struct q1n1_payload_args *a, struct pl_page *p, const struct file *f, const struct hash_result *r)
{
    pl_page_open(p, r->state == HASH_TIMEBOX ? "TIMEBOX" : "COUNTER_STUCK", 0);
    pl_add_dec(a, p, "HASHED", r->hashed);
    pl_page_add(a, p, "OF");
    {
        struct pl_line item;
        pl_begin(&item);
        pl_dec(&item, f->size);
        pl_page_add(a, p, item.buf);
    }
    pl_add_dec(a, p, "TICKS", r->ticks);
    pl_page_flush(a, p);
}

OUT_OF_LINE void report_file(const struct q1n1_payload_args *a, struct pl_page *p, const struct file *f)
{
    pl_page_open(p, "FILE", 0);
    pl_add_dec(a, p, "INDEX", f->index);
    pl_add_hex(a, p, "BASE", f->base);
    pl_add_dec(a, p, "BYTES", f->size);
    pl_add_dec(a, p, "MIB", f->size / MIB);
    pl_page_flush(a, p);
}

OUT_OF_LINE void report_attributes(const struct q1n1_payload_args *a, struct pl_page *p, const struct file *f, unsigned *mapped)
{
    struct pl_walk first, middle, last;
    uint64_t last_page = (f->base + f->size - 1) & ~(PL_PAGE_BYTES - 1);
    pl_walk_page(f->base, &first);
    pl_walk_page(f->base + ((last_page - f->base) / 2 & ~(PL_PAGE_BYTES - 1)), &middle);
    pl_walk_page(last_page, &last);
    pl_page_open(p, "ATTR", 0);
    add_walk(a, p, "FIRST", &first);
    add_walk(a, p, "MID", &middle);
    add_walk(a, p, "LAST", &last);
    pl_page_flush(a, p);
    *mapped = first.mapped && middle.mapped && last.mapped;
}

uint64_t payload_entry(const struct q1n1_payload_args *a);
uint64_t payload_entry(const struct q1n1_payload_args *a)
{
    struct pl_page p;
    struct file f;
    struct hash_result r;
    uint64_t current_el, freq, segments = 0, at = 0, rc = RET_OK;
    unsigned code, mapped = 0;
    if (!pl_args_ok(a) || !a->ops.counter) return Q1N1_PAYLOAD_RET_BAD_ARGS;
    pl_page_init(&p, ESSENTIAL_LINES);
    pl_zero(&f, sizeof f);
    pl_zero(&r, sizeof r);
    current_el = SYSREG(CurrentEL);
    freq = SYSREG(CNTFRQ_EL0);
    if (freq < COUNTER_HZ_MIN || freq > COUNTER_HZ_MAX) freq = COUNTER_HZ_DEFAULT;
    pl_page_open(&p, "START", 0);
    pl_add_hex(a, &p, "CURRENTEL", current_el);
    pl_add_dec(a, &p, "FREQ", freq);
    pl_page_flush(a, &p);
    if ((current_el >> 2 & 3) != 2) {
        pl_say(a, &p, "REFUSED", "NOT_AT_EL2", 1);
        return RET_NOT_EL2;
    }
    code = pl_map_check(a);
    if (code != PL_MAP_OK) {
        struct pl_line reason;
        pl_begin(&reason);
        pl_put_map_refusal(&reason, code);
        pl_say(a, &p, "MAP_REFUSED", reason.buf, 0);
        return RET_MAP;
    }
    code = find_file(a, &f);
    if (code != TABLE_OK) {
        pl_say(a, &p, "TABLE_REFUSED",
               code == TABLE_NONE ? "NO_TABLE" : code == TABLE_HEADER ? "BAD_HEADER" : code == TABLE_SIZE ? "TABLE_OVERRUNS_ITS_SIZE" : "NO_DATA_FILE",
               0);
        return RET_NO_FILE;
    }
    report_file(a, &p, &f);
    code = extent_check(a, f.base, f.size, &segments, &at);
    if (code != EXTENT_OK) {
        say_extent_refusal(a, &p, code, at);
        return RET_EXTENT;
    }
    pl_page_open(&p, "EXTENT", 0);
    pl_page_add(a, &p, "ALLOCATED");
    pl_add_dec(a, &p, "DESCRIPTORS", segments);
    pl_page_flush(a, &p);
    report_attributes(a, &p, &f, &mapped);
    if (!mapped) {
        pl_say(a, &p, "REFUSED", "A_PAGE_OF_THE_FILE_IS_NOT_MAPPED", 0);
        return RET_NOT_MAPPED;
    }

    pl_say(a, &p, "NEXT", "SHA256 BOX=25 S", 1);
    hash_file(a, freq, f.base, f.size, &r);
    if (r.state == HASH_DONE) {
        int match = digest_matches(a, &f, r.digest);
        report_rate(a, &p, freq, &r);
        report_digest(a, &p, &f, &r, match);
        rc = match ? RET_OK : RET_DIFFER;
        pl_page_open(&p, "DONE", 1);
        pl_page_add(a, &p, match ? "MATCH" : "DIFFER");
    } else {
        report_incomplete(a, &p, &f, &r);
        report_rate(a, &p, freq, &r);
        pl_page_open(&p, "DONE", 1);
        pl_page_add(a, &p, r.state == HASH_TIMEBOX ? "TIMEBOX" : "COUNTER_STUCK");
    }
    if (p.suppressed) pl_add_dec(a, &p, "SUPPRESSED", p.suppressed);
    pl_page_flush(a, &p);
    return rc;
}
