/* SPDX-License-Identifier: MIT */
/* Host test for the hashbig payload (payloads/hashbig.c and payloads/payload-sha256.h), built natively with Q1N1_PAYLOAD_HOST_TEST: its
 * register reads and its AT S1E2R come from the modelled machine of tools/test-q1n1-sp11-payload-mmu-world.h, and the file it hashes is
 * real memory between two PROT_NONE pages, so that one byte read outside the file's pages is a SEGV. Driven by
 * tools/test-q1n1-sp11-payload-hashbig.py under ASan and UBSan.
 *
 * Suites: vectors (the FIPS 180-4 digests, including the empty message and a million 'a', through the payload and the header), sizes (every
 * block-boundary size against the runner's own sha256.c), normal (the page, the AT calls, the rate from the model clock), choice (which
 * file is picked), table, extent and map (every refusal, with the file memory made PROT_NONE where nothing may be read), attr (Device,
 * non-cacheable, write-through, mixed, an unmapped page), differ (a corrupted file, a corrupted digest), timebox, stuck (a counter that
 * stands still or goes back), el and args, fuzz. Modes: `sha FILE HEX64 [step]` hashes a file through the payload against a digest
 * (Python's hashlib supplies it); `page` and `lines-report` print what the document and the chain budget are checked against.
 *
 * What it cannot show: what the unit's firmware maps the file as, or how fast the unit hashes it: the counter is a model clock. Evidence:
 * EXPERIMENTAL (host model only); hardware NOT RUN. */
#include "test-q1n1-sp11-payload-mmu-world.h"
#include "preload.h"
#include "sha256.h"
#include "payload-sha256.h"

#define FREQ 19200000u
#define P "PAYLOAD HASHBIG "

static uint64_t rng = 0x9e3779b97f4a7c15ull;
static uint64_t next_rand(void)
{
    rng ^= rng << 13;
    rng ^= rng >> 7;
    rng ^= rng << 17;
    return rng;
}
static void fill(uint8_t *p, uint64_t n)
{
    for (uint64_t i = 0; i < n; i++) p[i] = (uint8_t)(next_rand() >> 24);
}
static uint64_t up4k(uint64_t n)
{
    return (n + PAGE_ - 1) & ~(PAGE_ - 1);
}

/* ---- A world: a preload table, the files it lists, the map that describes them ---------------------------------------------------- */

struct spec {
    const char *path;
    uint64_t size;
    int payload;                /* a payload entry: no memory is allocated, its base is made up */
    int self;                   /* the entry whose base is the payload's own */
};
struct knobs {
    int corrupt_file, flip_digest, unmap_mid, protect_files, no_terminator;
    uint32_t desc_type;         /* of every data file's descriptor; 0 = 2 */
    uint64_t shrink_pages, gap_page, split_page;   /* the descriptor stops this many pages short; a hole at this page; split here into types 1 and 2 */
    uint8_t attr, sh, attr_last;
    int64_t base_shift;         /* what the table says the base is, minus the real one */
    uint64_t base_force;        /* what the table says the base of every data file is (0 = the real one) */
    uint64_t claim_size;        /* what the table says the size is (0 = the real one) */
    uint64_t magic, version, entry_size, count_extra;
    uint64_t table_bytes;       /* what preload_size says (0 = exact) */
    int no_table;
    const uint8_t *content;     /* the file's bytes instead of random ones (the last data file) */
    const uint8_t *digest_override;      /* the digest the table carries instead of the oracle's */
};
struct hw {
    struct guarded table, mem[6];
    struct world_map map;
    struct q1n1_payload_args a;
    uint64_t base[6], size[6];
    uint8_t digest[6][32];
    unsigned n;
};

static void put64(uint8_t *p, uint64_t v)
{
    memcpy(p, &v, 8);
}

static struct hw build(const struct spec *spec, unsigned n, const struct knobs *k)
{
    struct hw w;
    struct d {
        uint32_t type;
        uint64_t start, pages;
    } descs[24];
    unsigned nd = 0;
    uint64_t table_bytes = 32 + (uint64_t)n * sizeof(struct q1n1_cached_file);
    static uint8_t scratch[32 + 6 * sizeof(struct q1n1_cached_file)];
    memset(&w, 0, sizeof w);
    w.n = n;
    w.a = args_new();
    world_reset();
    reg_reset();
    reg_set("CurrentEL", 8);
    reg_set("CNTFRQ_EL0", FREQ);
    w.table = guarded_alloc(k->table_bytes ? k->table_bytes : table_bytes, 1);
    memset(scratch, 0, sizeof scratch);
    put64(scratch, k->magic ? k->magic : Q1N1_CACHE_MAGIC);
    put64(scratch + 8, k->version ? k->version : 1);
    put64(scratch + 16, n + k->count_extra);
    put64(scratch + 24, k->entry_size ? k->entry_size : sizeof(struct q1n1_cached_file));
    descs[nd++] = (struct d){7, 0x90000000, 4096};
    for (unsigned i = 0; i < n; i++) {
        uint8_t *e = scratch + 32 + (uint64_t)i * sizeof(struct q1n1_cached_file);
        uint64_t size = spec[i].size, pages = up4k(size) / PAGE_;
        if (spec[i].payload) {
            w.base[i] = 0xcc200000 + (uint64_t)i * 0x100000;
            descs[nd++] = (struct d){1, w.base[i], 1};
            tr_map(w.base[i], w.base[i] + PAGE_, ATTR_WB, SH_INNER);
            memset(w.digest[i], 0x11 * (i + 1), 32);
        } else {
            w.mem[i] = guarded_alloc(up4k(size), 0);
            if (k->content && i == n - 1) memcpy(w.mem[i].data, k->content, size);
            else fill(w.mem[i].data, size);
            memset(w.mem[i].data + size, 0xa5, up4k(size) - size);          /* the tail of the last page: poison */
            w.base[i] = (uint64_t)(uintptr_t)w.mem[i].data;
            q1n1_sha256(w.mem[i].data, size, w.digest[i]);
            if (k->digest_override && i == n - 1) memcpy(w.digest[i], k->digest_override, 32);
            if (k->corrupt_file) w.mem[i].data[size / 2] ^= 0x40;
            uint32_t type = k->desc_type ? k->desc_type : 2;
            uint64_t kept = pages > k->shrink_pages ? pages - k->shrink_pages : 0;
            if (k->split_page && k->split_page < kept) {
                descs[nd++] = (struct d){type == 2 ? 1u : 2u, w.base[i], k->split_page};
                descs[nd++] = (struct d){type, w.base[i] + k->split_page * PAGE_, kept - k->split_page};
            } else if (k->gap_page && k->gap_page < kept) {
                descs[nd++] = (struct d){type, w.base[i], k->gap_page};
                descs[nd++] = (struct d){type, w.base[i] + (k->gap_page + 1) * PAGE_, kept - k->gap_page - 1};
            } else {
                descs[nd++] = (struct d){type, w.base[i], kept};
            }
            uint8_t attr = k->attr ? k->attr : ATTR_WB, sh = k->sh == 0xff ? SH_NONE : k->sh ? k->sh : SH_INNER;
            if (k->attr == 0xee) attr = ATTR_DEVICE;
            tr_map(w.base[i], w.base[i] + pages * PAGE_, attr, sh);
            if (k->attr_last) tr_map(w.base[i] + (pages - 1) * PAGE_, w.base[i] + pages * PAGE_, k->attr_last, sh);
            if (k->unmap_mid) {
                uint64_t mid = w.base[i] + (((pages - 1) * PAGE_ / 2) & ~(PAGE_ - 1));          /* the page the payload asks about */
                tr_fault(mid, mid + PAGE_, 0x07);
            }
            if (k->protect_files) mprotect(w.mem[i].data, up4k(size) > 16384 ? up4k(size) : 16384, PROT_NONE);
        }
        w.size[i] = size;
        put64(e, spec[i].payload || !k->base_force ? (uint64_t)((int64_t)w.base[i] + k->base_shift) : k->base_force);
        put64(e + 8, up4k(size));
        put64(e + 16, k->claim_size ? k->claim_size : size);
        memcpy(e + 24, w.digest[i], 32);
        if (k->flip_digest) e[24 + (k->flip_digest == 2 ? 31 : 0)] ^= 1;       /* 1: the first byte of the table's digest, 2: the last */
        memset(e + 56, 'A', 256);
        if (!k->no_terminator) snprintf((char *)e + 56, 256, "%s", spec[i].path);
        if (spec[i].self) w.a.payload_base = w.base[i];
    }
    w.map = map_new(48, nd);
    for (unsigned i = 0; i < nd; i++) map_put(&w.map, i, descs[i].type, descs[i].start, descs[i].pages, 0xf);
    for (unsigned i = 0; i < nd; i++)
        if (descs[i].type == 7) tr_map(descs[i].start, descs[i].start + descs[i].pages * PAGE_, ATTR_WB, SH_INNER);
    args_map(&w.a, &w.map);
    memcpy(w.table.data, scratch, w.table.bytes < sizeof scratch ? w.table.bytes : sizeof scratch);
    w.a.preload_table = k->no_table ? 0 : (uint64_t)(uintptr_t)w.table.data;
    w.a.preload_size = k->no_table ? 0 : (k->table_bytes ? k->table_bytes : table_bytes);
    return w;
}

static void release(struct hw *w)
{
    for (unsigned i = 0; i < 6; i++)
        if (w->mem[i].all) {
            mprotect(w->mem[i].data, 16384, PROT_READ | PROT_WRITE);
            guarded_free(&w->mem[i]);
        }
    guarded_free(&w->table);
    guarded_free(&w->map.mem);
}

static uint64_t run(struct hw *w)
{
    page_clear();
    read_count = 0;
    at_count = 0;
    load_count = 0;
    return payload_entry(&w->a);
}

static const struct spec trio[] = {
    {"\\SP11\\EL2MEM.BIN", 12800, 1, 0}, {"\\SP11\\HASHBIG.BIN", 9500, 1, 1}, {"\\SP11\\BIG.DAT", 4 * 1024 * 1024, 0, 0},
};
static const struct knobs plain;

/* The digest line the payload printed for a given 32-byte digest: its first 16 hex digits. */
static void hex16(const uint8_t *d, char *out)
{
    for (int i = 0; i < 8; i++) snprintf(out + 2 * i, 3, "%02X", d[i]);
}

/* Ticks, milliseconds and MiB/s from the model clock, worked out here from the call count, another way. */
static int expect_rate(uint64_t bytes, char *out, size_t cap)
{
    uint64_t ticks = (clock_calls - 1) * clock_step;
    snprintf(out, cap, ticks ? "BYTES=%llu TICKS=%llu MS=%llu MIBS=%llu" : "BYTES=%llu TICKS=%llu RATE=UNKNOWN_COUNTER", (unsigned long long)bytes,
             (unsigned long long)ticks, (unsigned long long)(ticks * 1000 / FREQ), (unsigned long long)(bytes * FREQ / (ticks * MIB_ ? ticks * MIB_ : 1)));
    return 0;
}

static int suite_normal(void)
{
    struct hw w = build(trio, 3, &plain);
    char line[160], digest[17];
    uint64_t base = w.base[2], pages = (4 * MIB_) / PAGE_;
    CHECK_EQ(run(&w), 0);
    CHECK(font_violations == 0 && long_lines == 0 && line_count <= 12);
    snprintf(line, sizeof line, P "FILE INDEX=2 BASE=0X%llX BYTES=4194304 MIB=4", (unsigned long long)base);
    CHECK(has_line(line));
    CHECK(has_line(P "EXTENT ALLOCATED DESCRIPTORS=1"));
    CHECK(has_line(P "ATTR FIRST=WB.IS MID=WB.IS LAST=WB.IS"));
    CHECK(has_line(P "NEXT SHA256 BOX=25 S"));
    expect_rate(4 * MIB_, line, sizeof line);
    char want[200];
    snprintf(want, sizeof want, P "HASH %s", line);
    CHECK(has_line(want));
    hex16(w.digest[2], digest);
    snprintf(want, sizeof want, P "DIGEST %s MATCH", digest);
    CHECK(has_line(want));
    CHECK(!strcmp(lines[line_count - 1], P "DONE MATCH"));
    CHECK(!strcmp(lines[0], P "START CURRENTEL=0X8 FREQ=19200000"));
    /* AT: the first, middle and last page of the file, and nothing else; no load32 and no register but CurrentEL and CNTFRQ_EL0. */
    CHECK_EQ(at_count, 3);
    CHECK_EQ(at_log[0], base);
    CHECK_EQ(at_log[1], base + (((pages - 1) * PAGE_ / 2) & ~(PAGE_ - 1)));
    CHECK_EQ(at_log[2], base + (pages - 1) * PAGE_);
    CHECK_EQ(load_count, 0);
    CHECK_EQ(read_count, 2);
    CHECK_EQ(clock_calls, 1 + 64 + 1);          /* the start, one look per 64 KiB, and the end */
    release(&w);
    return 0;
}

/* ---- Digests ---------------------------------------------------------------------------------------------------------------------- */

static void unhex(const char *text, uint8_t *out)
{
    for (int i = 0; i < 32; i++) {
        unsigned v;
        sscanf(text + 2 * i, "%2x", &v);
        out[i] = (uint8_t)v;
    }
}

/* One file of `content` through the payload, against `want` (hex) as the runner's digest; returns the payload's value. */
static uint64_t hash_content(const uint8_t *content, uint64_t size, const char *want_hex, char *page_digest)
{
    struct spec s[3] = {trio[0], trio[1], {"\\SP11\\V.DAT", size, 0, 0}};
    struct knobs k = {0};
    uint8_t want[32];
    uint64_t rc;
    k.content = content;
    if (want_hex) {
        unhex(want_hex, want);
        k.digest_override = want;
    }
    struct hw w = build(s, 3, &k);
    rc = run(&w);
    if (page_digest) {
        int at = find_line(P "DIGEST ");
        snprintf(page_digest, 17, "%s", at >= 0 ? lines[at] + sizeof P - 1 + 7 : "");
    }
    release(&w);
    return rc;
}

static int suite_vectors(void)
{
    /* The header alone: the empty message, which no file of the payload can be. */
    struct pl_sha256 s;
    uint8_t block[128] __attribute__((aligned(8))) = {0}, out[32], want[32];
    pl_sha256_init(&s);
    pl_sha256_finish(&s, block, 0, 0, out);
    unhex("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", want);
    CHECK(!memcmp(out, want, 32));
    static const struct { const char *text; const char *hex; } known[] = {
        {"abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"},
        {"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"},
        {"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
         "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1"},
    };
    for (unsigned i = 0; i < sizeof known / sizeof known[0]; i++) {
        char digest[17], first[17];
        uint8_t oracle[32];
        q1n1_sha256(known[i].text, strlen(known[i].text), oracle);
        unhex(known[i].hex, want);
        CHECK(!memcmp(oracle, want, 32));                                      /* the oracle is right, too */
        CHECK_EQ(hash_content((const uint8_t *)known[i].text, strlen(known[i].text), known[i].hex, digest), 0);
        hex16(want, first);
        CHECK(!strcmp(digest, first));
    }
    uint8_t *million = malloc(1000000);
    char digest[17];
    memset(million, 'a', 1000000);
    CHECK_EQ(hash_content(million, 1000000, "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0", digest), 0);
    CHECK(!strcmp(digest, "CDC76E5C9914FB92"));
    free(million);
    return 0;
}

static int suite_sizes(void)
{
    static const uint64_t sizes[] = {1, 2, 3, 4, 5, 55, 56, 57, 63, 64, 65, 119, 120, 121, 127, 128, 129, 191, 192, 193, 255, 256, 257, 1000,
                                     4095, 4096, 4097, 65535, 65536, 65537, 65536 + 63, 65536 + 64, 131072 + 5, 300001};
    for (unsigned i = 0; i < sizeof sizes / sizeof sizes[0]; i++) {
        struct spec s[3] = {trio[0], trio[1], {"\\SP11\\S.DAT", sizes[i], 0, 0}};
        struct hw w = build(s, 3, &plain);
        CHECK_EQ(run(&w), 0);
        CHECK(!strcmp(lines[line_count - 1], P "DONE MATCH"));
        release(&w);
    }
    return 0;
}

/* ---- Which file --------------------------------------------------------------------------------------------------------------- */

static int picks(const struct spec *spec, unsigned n, const struct knobs *k, int index)
{
    struct hw w = build(spec, n, k);
    char want[96];
    CHECK_EQ(run(&w), 0);
    snprintf(want, sizeof want, P "FILE INDEX=%d BASE=0X%llX", index, (unsigned long long)w.base[index]);
    CHECK_ANY(P "FILE ", want);
    release(&w);
    return 0;
}

static int suite_choice(void)
{
    /* Payload names in any case are never hashed, however big; the payload's own entry is never hashed even when it is named like data. */
    static const struct spec names[] = {
        {"\\SP11\\HB.BIN", 9500, 1, 1}, {"\\SP11\\HUGE.bin", 200000, 0, 0}, {"\\SP11\\Z.Bin", 190000, 0, 0}, {"\\SP11\\Y.bIN", 180000, 0, 0},
        {"\\SP11\\DATA.DAT", 5000, 0, 0},
    };
    CHECK(!picks(names, 5, &plain, 4));
    static const struct spec self[] = {{"\\SP11\\SELF.DAT", 300000, 0, 1}, {"\\SP11\\B.DAT", 7000, 0, 0}};
    CHECK(!picks(self, 2, &plain, 1));
    static const struct spec equal[] = {{"\\SP11\\X.BIN", 1000, 1, 1}, {"\\SP11\\A.DAT", 8192, 0, 0}, {"\\SP11\\B.DAT", 8192, 0, 0}, {"\\SP11\\C.DAT", 8000, 0, 0}};
    CHECK(!picks(equal, 4, &plain, 1));
    static const struct spec zero[] = {{"\\SP11\\X.BIN", 1000, 1, 1}, {"\\SP11\\A.DAT", 0, 0, 0}, {"\\SP11\\B.DAT", 100, 0, 0}};
    CHECK(!picks(zero, 3, &plain, 2));
    /* A name of only ".BIN" has nothing before the dot: data; ".BINX" does not end in .BIN: data. */
    static const struct spec odd[] = {{"\\SP11\\X.BIN", 1000, 1, 1}, {"\\SP11\\.BIN", 6000, 0, 0}, {"\\SP11\\A.DAT", 3000, 0, 0}};
    CHECK(!picks(odd, 3, &plain, 1));
    static const struct spec trail[] = {{"\\SP11\\X.BIN", 1000, 1, 1}, {"\\SP11\\A.BINX", 6000, 0, 0}, {"\\SP11\\B.DAT", 3000, 0, 0}};
    CHECK(!picks(trail, 3, &plain, 1));
    /* A path with no terminator in its 256 bytes is never a file to hash: with every entry like that there is none. */
    struct knobs k = {0};
    k.no_terminator = 1;
    struct hw w = build(trio, 3, &k);
    CHECK_EQ(run(&w), 4);
    CHECK(has_line(P "TABLE_REFUSED NO_DATA_FILE"));
    release(&w);
    return 0;
}

/* ---- Refusals: nothing is hashed, and nothing is read that must not be ----------------------------------------------------------- */

static int refusal(const struct knobs *k, uint64_t rc, const char *line, unsigned lines_wanted)
{
    struct hw w = build(trio, 3, k);
    CHECK_EQ(run(&w), rc);
    CHECK_ANY(P, line);
    CHECK_EQ(line_count, lines_wanted);
    CHECK_EQ(clock_calls, 0);                   /* no hash was started */
    CHECK_EQ(load_count, 0);
    release(&w);
    return 0;
}

static int suite_table(void)
{
    struct knobs k = {0};
    k.no_table = 1;
    CHECK(!refusal(&k, 4, "TABLE_REFUSED NO_TABLE", 2));
    k = (struct knobs){0};
    k.table_bytes = 31;
    CHECK(!refusal(&k, 4, "TABLE_REFUSED NO_TABLE", 2));
    k = (struct knobs){0};
    k.magic = Q1N1_PRELOAD_MAGIC;
    CHECK(!refusal(&k, 4, "TABLE_REFUSED BAD_HEADER", 2));
    k = (struct knobs){0};
    k.version = 2;
    CHECK(!refusal(&k, 4, "TABLE_REFUSED BAD_HEADER", 2));
    k = (struct knobs){0};
    k.entry_size = 300;
    CHECK(!refusal(&k, 4, "TABLE_REFUSED BAD_HEADER", 2));
    /* The count says more entries than preload_size holds (the buffer ends at preload_size against a PROT_NONE page), or more than 16. */
    k = (struct knobs){0};
    k.count_extra = 1;
    CHECK(!refusal(&k, 4, "TABLE_REFUSED TABLE_OVERRUNS_ITS_SIZE", 2));
    k = (struct knobs){0};
    k.count_extra = 20;
    CHECK(!refusal(&k, 4, "TABLE_REFUSED TABLE_OVERRUNS_ITS_SIZE", 2));
    static const struct spec only_payloads[] = {{"\\SP11\\A.BIN", 1000, 1, 1}, {"\\SP11\\B.BIN", 1000, 1, 0}};
    struct hw w = build(only_payloads, 2, &plain);
    CHECK_EQ(run(&w), 4);
    CHECK(has_line(P "TABLE_REFUSED NO_DATA_FILE"));
    release(&w);
    w = build(trio, 3, &plain);
    w.a.preload_table += 4;                                     /* not 8-byte aligned */
    CHECK_EQ(run(&w), 4);
    CHECK(has_line(P "TABLE_REFUSED NO_TABLE"));
    w.a.preload_table -= 4;
    release(&w);
    return 0;
}

static int suite_extent(void)
{
    struct knobs k = {0};
    k.base_shift = 8;
    k.protect_files = 1;
    CHECK(!refusal(&k, 5, "EXTENT REFUSED=BASE_NOT_PAGE_ALIGNED", 3));
    k = (struct knobs){0};
    k.claim_size = 300 * MIB_;
    k.protect_files = 1;
    CHECK(!refusal(&k, 5, "EXTENT REFUSED=SIZE_ZERO_OR_OVER_256_MIB", 3));
    k.claim_size = 256 * MIB_ + 1;
    CHECK(!refusal(&k, 5, "EXTENT REFUSED=SIZE_ZERO_OR_OVER_256_MIB", 3));
    k = (struct knobs){0};
    k.base_force = (UINT64_C(1) << 48) - PAGE_;
    k.protect_files = 1;
    CHECK(!refusal(&k, 5, "EXTENT REFUSED=BEYOND_THE_48_BIT_SPACE", 3));
    /* Memory the runner did not allocate: boot-services data, conventional memory, runtime code. */
    static const uint32_t types[] = {3, 4, 5, 6, 7, 9};
    for (unsigned i = 0; i < sizeof types / sizeof types[0]; i++) {
        k = (struct knobs){0};
        k.desc_type = types[i];
        k.protect_files = 1;
        CHECK(!refusal(&k, 5, "EXTENT REFUSED=NOT_IN_ALLOCATED_DESCRIPTORS", 3));
    }
    /* The last page outside the descriptor, a hole in the middle, a descriptor that is one page short at the start of a second. */
    k = (struct knobs){0};
    k.shrink_pages = 1;
    k.protect_files = 1;
    struct hw w = build(trio, 3, &k);
    CHECK_EQ(run(&w), 5);
    char want[96];
    snprintf(want, sizeof want, "AT=0X%llX", (unsigned long long)(w.base[2] + 4 * MIB_ - PAGE_));
    CHECK_ANY(P "EXTENT ", want);
    release(&w);
    k = (struct knobs){0};
    k.gap_page = 5;
    k.protect_files = 1;
    w = build(trio, 3, &k);
    CHECK_EQ(run(&w), 5);
    snprintf(want, sizeof want, "AT=0X%llX", (unsigned long long)(w.base[2] + 5 * PAGE_));
    CHECK_ANY(P "EXTENT ", want);
    release(&w);
    /* Accepted: the exact fit, a file split over a loader-code and a loader-data descriptor, and one over two of the same type. */
    CHECK(!picks(trio, 3, &plain, 2));
    k = (struct knobs){0};
    k.split_page = 100;
    w = build(trio, 3, &k);
    CHECK_EQ(run(&w), 0);
    CHECK(has_line(P "EXTENT ALLOCATED DESCRIPTORS=2"));
    release(&w);
    k.desc_type = 1;
    w = build(trio, 3, &k);
    CHECK_EQ(run(&w), 0);
    CHECK(has_line(P "EXTENT ALLOCATED DESCRIPTORS=2"));
    release(&w);
    return 0;
}

static int suite_attr(void)
{
    static const struct { uint8_t attr, sh; const char *name; } kinds[] = {
        {0xee, SH_OUTER, "DEVICE.OS"}, {ATTR_NC, SH_OUTER, "NC.OS"}, {ATTR_WT, SH_INNER, "WT.IS"}, {0x4f, SH_INNER, "OTHER=0X4F.IS"}, {ATTR_WB, 0xff, "WB.NSH"},
    };
    for (unsigned i = 0; i < sizeof kinds / sizeof kinds[0]; i++) {
        struct knobs k = {0};
        char want[96];
        k.attr = kinds[i].attr;
        k.sh = kinds[i].sh;
        struct hw w = build(trio, 3, &k);
        CHECK_EQ(run(&w), 0);                                   /* slow memory is reported, and still hashed */
        snprintf(want, sizeof want, P "ATTR FIRST=%s MID=%s LAST=%s", kinds[i].name, kinds[i].name, kinds[i].name);
        CHECK(has_line(want));
        CHECK(!strcmp(lines[line_count - 1], P "DONE MATCH"));
        release(&w);
    }
    struct knobs k = {0};
    k.attr_last = ATTR_NC;
    struct hw w = build(trio, 3, &k);
    CHECK_EQ(run(&w), 0);
    CHECK(has_line(P "ATTR FIRST=WB.IS MID=WB.IS LAST=NC.IS"));
    release(&w);
    /* A page of the file that is not mapped: refused, and the file's memory is made unreadable to prove nothing is read. */
    k = (struct knobs){0};
    k.unmap_mid = 1;
    k.protect_files = 1;
    w = build(trio, 3, &k);
    CHECK_EQ(run(&w), 7);
    CHECK(has_line(P "ATTR FIRST=WB.IS MID=FAULT=0X7:TRANS_L3 LAST=WB.IS"));
    CHECK(has_line(P "REFUSED A_PAGE_OF_THE_FILE_IS_NOT_MAPPED"));
    CHECK_EQ(clock_calls, 0);
    release(&w);
    return 0;
}

static int suite_differ(void)
{
    struct knobs k = {0};
    k.corrupt_file = 1;
    struct hw w = build(trio, 3, &k);
    char ours[17], theirs[17], want[160];
    CHECK_EQ(run(&w), 6);
    q1n1_sha256(w.mem[2].data, w.size[2], w.digest[0]);                      /* what the corrupted file really hashes to */
    hex16(w.digest[0], ours);
    snprintf(want, sizeof want, P "DIGEST %s DIFFER WANT=", ours);
    CHECK_ANY(P "DIGEST ", want);
    CHECK(!strcmp(lines[line_count - 1], P "DONE DIFFER"));
    release(&w);
    k = (struct knobs){0};
    k.flip_digest = 1;
    w = build(trio, 3, &k);
    CHECK_EQ(run(&w), 6);
    hex16(w.digest[2], ours);
    w.digest[2][0] ^= 1;
    hex16(w.digest[2], theirs);
    snprintf(want, sizeof want, P "DIGEST %s DIFFER WANT=%s", ours, theirs);
    CHECK(has_line(want));
    release(&w);
    /* The page shows eight bytes of each digest; the verdict is over all thirty-two, so a difference in the last byte is a difference. */
    k = (struct knobs){0};
    k.flip_digest = 2;
    w = build(trio, 3, &k);
    CHECK_EQ(run(&w), 6);
    hex16(w.digest[2], ours);
    snprintf(want, sizeof want, P "DIGEST %s DIFFER WANT=%s", ours, ours);
    CHECK(has_line(want));
    CHECK(!strcmp(lines[line_count - 1], P "DONE DIFFER"));
    release(&w);
    return 0;
}

/* ---- The clock ------------------------------------------------------------------------------------------------------------------ */

static int suite_clock(void)
{
    static const struct spec two_mib[] = {{"\\SP11\\A.BIN", 1000, 1, 1}, {"\\SP11\\B.DAT", 2 * 1024 * 1024, 0, 0}};
    static const struct spec box_edge[] = {{"\\SP11\\A.BIN", 1000, 1, 1}, {"\\SP11\\B.DAT", 5 * 65536, 0, 0}};
    /* The time box: 25 s is 480,000,000 ticks; at 100,000,000 a look it is passed after five looks, 320 KiB. */
    struct hw w = build(two_mib, 2, &plain);
    clock_set(0, 100000000, 0);
    CHECK_EQ(run(&w), 0);
    CHECK(has_line(P "TIMEBOX HASHED=327680 OF 2097152 TICKS=500000000"));
    CHECK(has_line(P "HASH BYTES=327680 TICKS=500000000 MS=26041 MIBS=0"));
    CHECK(!strcmp(lines[line_count - 1], P "DONE TIMEBOX"));
    CHECK_EQ(find_line(P "DIGEST "), -1);
    release(&w);
    /* A file that ends on the look that passes the box is hashed to the end, not called a time-out. */
    w = build(box_edge, 2, &plain);
    clock_set(0, 100000000, 0);
    CHECK_EQ(run(&w), 0);
    CHECK(!strcmp(lines[line_count - 1], P "DONE MATCH"));
    release(&w);
    /* A counter that stands still: with a 32 MiB file the loop ends after 256 looks, 16 MiB, and says why. */
    static const struct spec big[] = {{"\\SP11\\A.BIN", 1000, 1, 1}, {"\\SP11\\B.DAT", 32 * 1024 * 1024, 0, 0}};
    w = build(big, 2, &plain);
    clock_set(5000, 0, 1);
    CHECK_EQ(run(&w), 0);
    CHECK(has_line(P "COUNTER_STUCK HASHED=16777216 OF 33554432 TICKS=0"));
    CHECK(has_line(P "HASH BYTES=16777216 TICKS=0 RATE=UNKNOWN_COUNTER"));
    CHECK(!strcmp(lines[line_count - 1], P "DONE COUNTER_STUCK"));
    CHECK_EQ(clock_calls, 257);
    release(&w);
    /* ... a small file ends before that and is hashed, with no rate. */
    w = build(trio, 3, &plain);
    clock_set(5000, 0, 1);
    CHECK_EQ(run(&w), 0);
    CHECK(has_line(P "HASH BYTES=4194304 TICKS=0 RATE=UNKNOWN_COUNTER"));
    CHECK(!strcmp(lines[line_count - 1], P "DONE MATCH"));
    release(&w);
    /* A counter that goes back ends the loop at the first look; the absurd distance is not shown as a rate. */
    w = build(two_mib, 2, &plain);
    clock_set(1000000, 1000, 2);
    CHECK_EQ(run(&w), 0);
    CHECK(has_line(P "TIMEBOX HASHED=65536 OF 2097152 TICKS=18446744073709550616"));
    CHECK(has_line(P "HASH BYTES=65536 TICKS=18446744073709550616 RATE=UNKNOWN_COUNTER"));
    release(&w);
    /* A CNTFRQ_EL0 that is no frequency falls back to 19.2 MHz; a valid one is used for the box and the rate. */
    w = build(two_mib, 2, &plain);
    reg_set("CNTFRQ_EL0", 0);
    clock_set(0, 100000000, 0);
    CHECK_EQ(run(&w), 0);
    CHECK(has_line(P "START CURRENTEL=0X8 FREQ=19200000"));
    CHECK(has_line(P "TIMEBOX HASHED=327680 OF 2097152 TICKS=500000000"));
    release(&w);
    w = build(two_mib, 2, &plain);
    reg_set("CNTFRQ_EL0", 1000000000);
    clock_set(0, 100000000, 0);
    CHECK_EQ(run(&w), 0);
    CHECK(!strcmp(lines[line_count - 1], P "DONE MATCH"));       /* 25 s is 25e9 ticks now: never reached */
    release(&w);
    return 0;
}

static int suite_gates(void)
{
    struct hw w = build(trio, 3, &plain);
    /* Not at EL2: one START line and the refusal, nothing read but CurrentEL and CNTFRQ_EL0, no AT, no counter, no table. */
    for (uint64_t el = 0; el <= 3; el++) {
        if (el == 2) continue;
        reg_set("CurrentEL", el << 2);
        CHECK_EQ(run(&w), 2);
        CHECK_EQ(line_count, 2);
        CHECK(!strcmp(lines[1], P "REFUSED NOT_AT_EL2"));
        CHECK_EQ(read_count, 2);
        CHECK_EQ(at_count, 0);
        CHECK_EQ(clock_calls, 0);
    }
    reg_set("CurrentEL", 8);
    /* Bad arguments, and no counter op, which this payload cannot do without. */
    struct q1n1_payload_args good = w.a;
    CHECK_EQ(payload_entry(0), Q1N1_PAYLOAD_RET_BAD_ARGS);
    for (int variant = 0; variant < 5; variant++) {
        w.a = good;
        if (variant == 0) w.a.magic ^= 1;
        else if (variant == 1) w.a.version = 2;
        else if (variant == 2) w.a.size = sizeof w.a - 8;
        else if (variant == 3) w.a.ops.hex = 0;
        else w.a.ops.counter = 0;
        CHECK_EQ(run(&w), Q1N1_PAYLOAD_RET_BAD_ARGS);
        CHECK_EQ(line_total, 0);
        CHECK_EQ(read_count, 0);
    }
    w.a = good;
    release(&w);
    return 0;
}

/* A map that cannot be read: refused before one byte of it is read (the buffer ends at a PROT_NONE page), and nothing else happens. */
static int map_refused(uint64_t stride, uint64_t size, const char *reason)
{
    struct hw w = build(trio, 3, &plain);
    struct guarded g = guarded_alloc(size ? size : 8, 1);
    w.a.map_base = (uint64_t)(uintptr_t)g.data;
    w.a.map_size = size;
    w.a.map_stride = stride;
    CHECK_EQ(run(&w), 3);
    CHECK_ANY(P "MAP_REFUSED ", reason);
    CHECK_EQ(line_count, 2);
    CHECK_EQ(at_count, 0);
    CHECK_EQ(clock_calls, 0);
    guarded_free(&g);
    release(&w);
    return 0;
}

static int suite_map(void)
{
    CHECK(!map_refused(0, 96, "STRIDE_BELOW_40"));
    CHECK(!map_refused(39, 78, "STRIDE_BELOW_40"));
    CHECK(!map_refused(44, 88, "STRIDE_NOT_A_MULTIPLE_OF_8"));
    CHECK(!map_refused(48, 100, "SIZE_NOT_WHOLE_DESCRIPTORS"));
    CHECK(!map_refused(48, 0, "SIZE_NOT_WHOLE_DESCRIPTORS"));
    CHECK(!map_refused(48, 48 * 1025, "TOO_MANY_DESCRIPTORS"));
    struct hw w = build(trio, 3, &plain);
    w.a.map_base = 0x10004;
    CHECK_EQ(run(&w), 3);
    CHECK_ANY(P "MAP_REFUSED ", "BUFFER_OUT_OF_RANGE");
    w.a.map_base = UINT64_C(1) << 48;
    CHECK_EQ(run(&w), 3);
    release(&w);
    return 0;
}

/* ---- Random worlds -------------------------------------------------------------------------------------------------------------- */

static int suite_fuzz(void)
{
    for (unsigned world = 0; world < 300; world++) {
        struct spec s[5];
        struct knobs k = {0};
        unsigned n = 2 + (unsigned)(next_rand() % 4), data = 0;
        uint64_t rc_want, biggest = 0;
        static char paths[5][40];
        for (unsigned i = 0; i < n; i++) {
            int payload_name = i == 0 || next_rand() % 4 == 0;
            snprintf(paths[i], sizeof paths[i], "\\SP11\\F%u.%s", i, payload_name ? (next_rand() & 1 ? "BIN" : "bIn") : "DAT");
            s[i] = (struct spec){paths[i], 1 + next_rand() % 200000, 0, i == 0};
            if (i == 0) s[i].size = 5000;
            if (!payload_name && s[i].size > biggest) {
                biggest = s[i].size;
                data++;
            }
        }
        s[0].payload = 1;
        s[1].payload = 0;
        unsigned flavour = (unsigned)(next_rand() % 9);
        k.corrupt_file = flavour == 1;
        k.flip_digest = flavour == 2 ? 1 + (world & 1) : 0;
        k.unmap_mid = flavour == 3;
        k.desc_type = flavour == 4 ? 4 : 0;
        k.shrink_pages = flavour == 5;
        k.base_shift = flavour == 6 ? 16 : 0;
        k.attr = flavour == 7 ? 0xee : 0;
        k.sh = flavour == 7 ? SH_OUTER : 0;
        k.protect_files = flavour == 3 || flavour == 4 || flavour == 5 || flavour == 6;
        if (!data) {
            s[1].path = "\\SP11\\F1.DAT";
            s[1].size = 1 + next_rand() % 200000;
            biggest = s[1].size;
        }
        for (unsigned i = 1; i < n; i++) {
            const char *dot = strrchr(s[i].path, '.');
            if (strcmp(dot, ".DAT") && i > 0) s[i].payload = 0;
        }
        struct hw w = build(s, n, &k);
        if (getenv("HASHBIG_TRACE")) {
            fprintf(stderr, "world %u flavour %u n %u:", world, flavour, n);
            for (unsigned i = 0; i < n; i++) fprintf(stderr, " %s/%llu/%d/%d", s[i].path, (unsigned long long)s[i].size, s[i].payload, s[i].self);
            fprintf(stderr, "\n");
        }
        uint64_t rc = run(&w);
        rc_want = flavour == 6 ? 5 : flavour == 4 || flavour == 5 ? 5 : flavour == 3 ? 7 : flavour == 1 || flavour == 2 ? 6 : 0;
        CHECK_EQ(rc, rc_want);
        CHECK(font_violations == 0 && long_lines == 0 && line_count <= 12);
        CHECK(find_line(P "START ") == 0);
        CHECK(rc == 5 || rc == 7 ? clock_calls == 0 : clock_calls >= 2);
        CHECK(!w.mem[0].all);
        release(&w);
    }
    return 0;
}

/* The files of the staging plan at the real size, from a file the driver wrote: `sha FILE HEX64 [step]`. */
static int mode_sha(const char *path, const char *hex, uint64_t step)
{
    FILE *f = fopen(path, "rb");
    if (!f) return 2;
    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);
    uint8_t *data = malloc((size_t)size);
    if (fread(data, 1, (size_t)size, f) != (size_t)size) return 2;
    fclose(f);
    struct spec s[3] = {trio[0], trio[1], {"\\SP11\\BIG.DAT", (uint64_t)size, 0, 0}};
    struct knobs k = {0};
    uint8_t want[32];
    unhex(hex, want);
    k.content = data;
    k.digest_override = want;
    struct hw w = build(s, 3, &k);
    clock_set(0, step, 0);
    uint64_t rc = run(&w);
    for (unsigned i = 0; i < line_count; i++) printf("%s\n", lines[i]);
    printf("RETURN=%llu\n", (unsigned long long)rc);
    release(&w);
    free(data);
    return rc == 0 ? 0 : 1;
}

static unsigned most_lines;
static int report_lines(void)
{
    struct hw w = build(trio, 3, &plain);
    run(&w);
    most_lines = line_count;
    release(&w);
    struct knobs k = {0};
    k.attr_last = ATTR_NC;
    w = build(trio, 3, &k);
    clock_set(0, 100000000, 0);
    run(&w);
    if (line_count > most_lines) most_lines = line_count;
    release(&w);
    k = (struct knobs){0};
    k.corrupt_file = 1;
    w = build(trio, 3, &k);
    run(&w);
    if (line_count > most_lines) most_lines = line_count;
    release(&w);
    printf("LINES_MAX=%u\n", most_lines);
    return 0;
}

static int dump_page(void)
{
    struct hw w = build(trio, 3, &plain);
    run(&w);
    for (unsigned i = 0; i < line_count; i++) {
        /* The file's base is a host address that changes from run to run: shown as a fixed example of where the firmware might put it. */
        char *at = strstr(lines[i], "BASE=0X");
        if (at) {
            char *end = strchr(at, ' ');
            char rest[128];
            snprintf(rest, sizeof rest, "%s", end ? end : "");
            snprintf(at, sizeof lines[i] - (size_t)(at - lines[i]), "BASE=0XCF000000%s", rest);
        }
        printf("%s\n", lines[i]);
    }
    release(&w);
    return 0;
}

int main(int argc, char **argv)
{
    static const struct { const char *name; int (*run)(void); } suites[] = {
        {"vectors", suite_vectors}, {"sizes", suite_sizes}, {"normal", suite_normal}, {"choice", suite_choice}, {"table", suite_table},
        {"extent", suite_extent}, {"attr", suite_attr}, {"differ", suite_differ}, {"clock", suite_clock}, {"gates", suite_gates},
        {"map", suite_map}, {"fuzz", suite_fuzz},
    };
    if (argc > 3 && !strcmp(argv[1], "sha")) return mode_sha(argv[2], argv[3], argc > 4 ? strtoull(argv[4], 0, 0) : 1000000);
    if (argc > 1 && !strcmp(argv[1], "lines-report")) return report_lines();
    if (argc > 1 && !strcmp(argv[1], "page")) return dump_page();
    unsigned ran = 0;
    for (unsigned i = 0; i < sizeof suites / sizeof suites[0]; i++) {
        if (argc > 1 && strcmp(argv[1], "all") && strcmp(argv[1], suites[i].name)) continue;
        if (suites[i].run()) {
            fprintf(stderr, "FAIL: suite %s\n", suites[i].name);
            return 1;
        }
        ran++;
    }
    printf("PASS: %u payload hashbig suites, %u checks\n", ran, checks);
    return 0;
}
