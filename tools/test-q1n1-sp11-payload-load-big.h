/* SPDX-License-Identifier: MIT */
/* The big-file cases of the loader program (tools/test-q1n1-sp11-payload-load.c), compiled in only with Q1N1_SP11_BIGFILE=1 (docs/SP11-PAYLOAD-BIGFILE.md). They use the
 * program's own fake firmware and its checks; tools/test-q1n1-sp11-payload.py builds the program twice with the gate on, at the default 8 MiB chunk cap (the limit is 2 GiB:
 * the cases that need memory use a file of 300 MiB, the limit's own edge is reached through an allocation that fails) and at 64 KiB (the limit is 16 MiB, so a file of
 * exactly the limit is loaded for real and one byte more is refused), and with the gate off the program is what it was.
 *
 *   big   the limit derived from the cap, refusals by name before anything is allocated or read, a 300 MiB file loaded, hashed and printed, the progress lines
 *   top   data files asked of the top of RAM, never of AnyPages, the allocation that fails or lies, q1n1_payload_top_ok at its edges
 *
 * The bytes of a big file are generated (gen_byte), never stored: a file the fake serves costs nothing until the loader's own buffer is allocated. Nothing here runs on EFI
 * or on hardware. Evidence: EXPERIMENTAL (host model only). */

static void gen_digest(uint64_t size, uint8_t digest[32])
{
    static uint8_t chunk[1u << 20];
    struct q1n1_sha256 state;
    q1n1_sha256_init(&state);
    for (uint64_t at = 0; at < size; at += sizeof chunk) {
        uint64_t n = size - at < sizeof chunk ? size - at : sizeof chunk;
        gen_fill(chunk, at, n);
        q1n1_sha256_update(&state, chunk, (size_t)n);
    }
    q1n1_sha256_final(&state, digest);
}

/* The data file's Read returns at most this many bytes per call (0: no limit), so that a read can end between two 64 MiB boundaries and across one. */
static uint64_t short_reads;

/* A stick of two files: STATE.BIN (a real blob, the payload) and DATA1.DAT, `big` bytes generated. The manifest says `listed` bytes for it and carries `digest`
 * (all zero when the case never reaches the hash). */
static void big_stick(uint64_t big, uint64_t listed, const uint8_t digest[32])
{
    static struct manifest_build mb;
    struct q1n1_preload_manifest man;
    uint8_t *state = blob(good_sizes[0], 1);
    world_reset();
    add_file(&volume[0], names[0], state, good_sizes[0]);
    struct fake_entry *data_entry = add_file(&volume[0], names[1], NULL, big);
    data_entry->generated = 1;
    data_entry->max_per_read = short_reads;
    memset(&man, 0, sizeof man);
    man.magic = Q1N1_PRELOAD_MAGIC; man.version = 1; man.count = 2; man.entry_size = sizeof man.files[0];
    man.files[0].size = good_sizes[0];
    q1n1_sha256(state, good_sizes[0], man.files[0].sha256);
    snprintf(man.files[0].path, sizeof man.files[0].path, "%s", names[0]);
    man.files[1].size = listed;
    memcpy(man.files[1].sha256, digest, 32);
    snprintf(man.files[1].path, sizeof man.files[1].path, "%s", names[1]);
    mb.size = 32 + 2 * sizeof man.files[0];
    memcpy(mb.bytes, &man, mb.size);
    uint8_t *copy = malloc(mb.size);
    memcpy(copy, mb.bytes, mb.size);
    add_file(&volume[0], Q1N1_PAYLOAD_MANIFEST_PATH, copy, mb.size);
}

static const uint8_t no_digest[32];
#define MIB_ (UINT64_C(1) << 20)

/* A stick whose manifest has one entry, a payload that is `size` bytes long, so that the shared validator's total (4 GiB) leaves room for sizes near 2^32. */
static void lone_stick(uint64_t size)
{
    struct manifest_build mb;
    struct q1n1_preload_manifest man;
    world_reset();
    memset(&man, 0, sizeof man);
    man.magic = Q1N1_PRELOAD_MAGIC; man.version = 1; man.count = 1; man.entry_size = sizeof man.files[0];
    man.files[0].size = size;
    snprintf(man.files[0].path, sizeof man.files[0].path, "\\SP11\\LONE.BIN");
    mb.size = 32 + sizeof man.files[0];
    memcpy(mb.bytes, &man, mb.size);
    uint8_t *copy = malloc(mb.size);
    memcpy(copy, mb.bytes, mb.size);
    add_file(&volume[0], Q1N1_PAYLOAD_MANIFEST_PATH, copy, mb.size);
}

/* One manifest entry of a size the loader must refuse by name, with the firmware untouched: the refusal comes before the file is opened. `lone` puts it alone in
 * the manifest (entry 0), for the sizes that leave no room for another file under the shared 4 GiB total. */
static int refused_by_size(uint64_t size, int lone)
{
    unsigned index = lone ? 0 : 1;
    if (lone) lone_stick(size);
    else big_stick(size, size, no_digest);
    CHECK(prepare() == Q1N1_PAYLOAD_E_FILE_TOO_BIG);
    CHECK(diag.index == index && diag.got == size && diag.expected == Q1N1_PAYLOAD_MAX_FILE_BYTES);
    CHECK(alloc_calls == 0 && volume[0].file_opens == 1 && live_allocations() == 0 && progress_count == 0);
    char line[200];
    char want[200];
    q1n1_payload_refusal_line(Q1N1_PAYLOAD_E_FILE_TOO_BIG, &diag, line, sizeof line);
    snprintf(want, sizeof want, "PAYLOAD REFUSED=FILE_TOO_BIG INDEX=%u GOT=%" PRIu64 " WANT=%" PRIu64, index, size, (uint64_t)Q1N1_PAYLOAD_MAX_FILE_BYTES);
    CHECK(!strcmp(line, want));
    return 0;
}

/* A manifest the shared validator (preload.c, the A16's rules, unchanged) refuses before the runner's own rules are asked. */
static int refused_by_manifest(uint64_t size)
{
    big_stick(size, size, no_digest);
    CHECK(prepare() == Q1N1_PAYLOAD_E_MANIFEST_BAD);
    CHECK(alloc_calls == 0 && volume[0].file_opens == 1);
    return 0;
}

/* One file of `size` bytes loaded for real: its digest, its place, its progress lines. `lines` is how many 64 MiB boundaries it crosses. */
static int loaded_big(uint64_t size, unsigned lines)
{
    uint8_t digest[32], whole[32];
    gen_digest(size, digest);
    big_stick(size, size, digest);
    CHECK(prepare() == Q1N1_PAYLOAD_OK && loaded.count == 2 && loaded.code_count == 1);
    const struct q1n1_payload_file *f = &loaded.file[1];
    CHECK(f->bytes == size && f->alloc == (size + 4095) / 4096 * 4096 && f->memory_type == Q1N1_PAYLOAD_TYPE_DATA);
    CHECK(!memcmp(f->sha256, digest, 32));
    q1n1_sha256((const void *)(uintptr_t)f->base, (size_t)size, whole);
    CHECK(!memcmp(whole, digest, 32));
    /* The bytes are the generated ones at both ends and in the middle, and the rest of the last page is zeros. */
    uint8_t probe[4096];
    uint64_t at[3] = {0, size / 2 / 4096 * 4096, size > 4096 ? (size - 1) / 4096 * 4096 : 0};
    for (unsigned i = 0; i < 3; i++) {
        uint64_t n = size - at[i] < sizeof probe ? size - at[i] : sizeof probe;
        gen_fill(probe, at[i], n);
        CHECK(!memcmp((void *)(uintptr_t)(f->base + at[i]), probe, n));
    }
    for (uint64_t k = f->bytes; k < f->alloc; k++) CHECK(((uint8_t *)(uintptr_t)f->base)[k] == 0);
    /* The note for the page keeps its shape. */
    char want[128];
    snprintf(want, sizeof want, "PAYLOAD LOADED INDEX=1 BASE=0X%" PRIX64 " BYTES=%" PRIu64 " SHA=%02X%02X%02X%02X%02X%02X%02X%02X TYPE=2", f->base, size,
             digest[0], digest[1], digest[2], digest[3], digest[4], digest[5], digest[6], digest[7]);
    CHECK(!strcmp(loaded.note[1], want));
    /* One line per 64 MiB read, then one per 64 MiB hashed, and nothing for the payload or per request. */
    CHECK(progress_count == 2 * lines);
    for (unsigned i = 0; i < lines; i++) {
        snprintf(want, sizeof want, "PAYLOAD READ INDEX=1 MIB=%u OF=%" PRIu64, 64 * (i + 1), (size + MIB_ - 1) / MIB_);
        CHECK(!strcmp(progress_text[i], want));
        snprintf(want, sizeof want, "PAYLOAD HASH INDEX=1 MIB=%u", 64 * (i + 1));
        CHECK(!strcmp(progress_text[lines + i], want));
    }
    CHECK(max_read_request == MIB_);
    /* The data file came from the top of RAM, the payload, the table and the stack did not. */
    CHECK(top_calls == 1 && any_calls == 3 && alloc_count == 4);
    CHECK(alloc_log[0].kind == 0 && alloc_log[1].kind == Q1N1_PAYLOAD_ALLOCATE_MAX_ADDRESS && alloc_log[1].asked == Q1N1_PAYLOAD_TOP_ADDRESS);
    CHECK(alloc_log[1].type == Q1N1_PAYLOAD_TYPE_DATA && alloc_log[1].pages * 4096 == f->alloc);
    q1n1_payload_release(&bs, &loaded);
    CHECK(live_allocations() == 0 && bad_frees == 0 && strays == 0 && open_handles == 0);
    return 0;
}

static int suite_big(void)
{
    const uint64_t max = Q1N1_PAYLOAD_MAX_FILE_BYTES;
    /* The limit is the number of ops slbounce allows times the unit the runner declares, and at most 2 GiB. */
    CHECK(max == Q1N1_PAYLOAD_SWEEP_MAX_OPS * (uint64_t)Q1N1_PAYLOAD_CHUNK_BYTES && max <= (UINT64_C(2) << 30));
    CHECK(Q1N1_PAYLOAD_CHUNK_BYTES >= 65536 && Q1N1_PAYLOAD_CHUNK_BYTES <= 8 * MIB_ && !(Q1N1_PAYLOAD_CHUNK_BYTES & (Q1N1_PAYLOAD_CHUNK_BYTES - 1)));

    /* One byte over, 2 GiB and one byte, 2^32 - 1 and 2^32 (each valid for the shared validator, whose total is 4 GiB: these two stand alone in the manifest): refused by
     * name, before the file is opened. */
    CHECK(refused_by_size(max + 1, 0) == 0);
    CHECK(refused_by_size((UINT64_C(2) << 30) + 1, 0) == 0);
    CHECK(refused_by_size(UINT64_C(0xFFFFFFFF), 1) == 0);
    CHECK(refused_by_size(UINT64_C(0x100000000), 1) == 0);
    /* Sizes that overflow 32 bits, a size of 0 and a total over 4 GiB never get as far as the runner's rule: the shared validator refuses them. */
    CHECK(refused_by_manifest(UINT64_C(0x100000001)) == 0);
    CHECK(refused_by_manifest(UINT64_C(0x200000000)) == 0);
    CHECK(refused_by_manifest(UINT64_MAX) == 0);
    CHECK(refused_by_manifest(0) == 0);
    {
        /* 2000 bytes of payload plus 2^32 - 1999 bytes is 4 GiB + 1 in all. */
        big_stick(UINT64_C(0x100000000) - 1999, UINT64_C(0x100000000) - 1999, no_digest);
        CHECK(prepare() == Q1N1_PAYLOAD_E_MANIFEST_BAD && alloc_calls == 0);
    }

    /* Exactly the limit. A limit of 16 MiB is loaded for real; at 2 GiB the file is accepted by size and stops at the allocation, which the fake refuses. */
    if (max <= 64 * MIB_) {
        CHECK(loaded_big(max, 0) == 0);
        big_stick(max, max, no_digest);
        CHECK(prepare() == Q1N1_PAYLOAD_E_HASH && diag.index == 1 && live_allocations() == 0);       /* a wrong digest still refuses it by name */
    } else {
        big_stick(max, max, no_digest);
        top_fail_status = EFI_ERROR(9);
        CHECK(prepare() == Q1N1_PAYLOAD_E_FILE_NO_MEMORY && diag.index == 1 && diag.efi == EFI_ERROR(9) && diag.expected == max && diag.got == 0);
        CHECK(top_calls == 1 && any_calls == 1 && live_allocations() == 0 && bad_frees == 0 && open_handles == 0);
    }

    if (max > 256 * MIB_) {
        /* A file over the old limit of 256 MiB, the size of the big runs: loaded, hashed, printed; 301 MiB is four 64 MiB boundaries. */
        CHECK(loaded_big(300 * MIB_ + 13, 4) == 0);
        /* The boundary itself: 64 MiB less a byte crosses none, 64 MiB and 64 MiB and a byte cross one. */
        CHECK(loaded_big(64 * MIB_ - 1, 0) == 0);
        CHECK(loaded_big(64 * MIB_, 1) == 0);
        CHECK(loaded_big(64 * MIB_ + 1, 1) == 0);
        /* Short reads of 999,983 bytes (a prime: none ends on a 64 MiB boundary) still print one line per boundary, at the read that crosses it. */
        short_reads = 999983;
        CHECK(loaded_big(130 * MIB_ + 7, 2) == 0);
        short_reads = 0;
        /* Without a hook nothing is printed and nothing breaks. */
        uint8_t digest[32];
        gen_digest(64 * MIB_, digest);
        big_stick(64 * MIB_, 64 * MIB_, digest);
        q1n1_payload_set_progress(NULL);
        CHECK(prepare() == Q1N1_PAYLOAD_OK && progress_count == 0);
        q1n1_payload_release(&bs, &loaded);
        CHECK(live_allocations() == 0);
        /* A byte changed in the last slice, which a hash over a truncated length would not see. */
        gen_digest(300 * MIB_ + 13, digest);
        digest[31] ^= 1;
        big_stick(300 * MIB_ + 13, 300 * MIB_ + 13, digest);
        CHECK(prepare() == Q1N1_PAYLOAD_E_HASH && diag.index == 1 && live_allocations() == 0);
        digest[31] ^= 1;
        digest[0] ^= 0x80;
        big_stick(300 * MIB_ + 13, 300 * MIB_ + 13, digest);
        CHECK(prepare() == Q1N1_PAYLOAD_E_HASH && live_allocations() == 0);
    }
    return 0;
}

static int suite_top(void)
{
    /* Data files ask for the top of RAM and the payload, the table and the stack do not: five files are four MaxAddress calls and three AnyPages calls. */
    world_reset();
    good_stick(&volume[0], 5);
    CHECK(prepare() == Q1N1_PAYLOAD_OK && top_calls == 4 && any_calls == 3 && alloc_count == 7 && strays == 0);
    for (unsigned i = 0; i < 5; i++) {
        const struct fake_allocation *a = allocation_at(loaded.file[i].base);
        CHECK(a && a->kind == (i ? Q1N1_PAYLOAD_ALLOCATE_MAX_ADDRESS : 0) && a->asked == (i ? Q1N1_PAYLOAD_TOP_ADDRESS : 0));
    }
    CHECK(allocation_at(loaded.table_base)->kind == 0 && allocation_at(loaded.stack_base)->kind == 0);
    q1n1_payload_release(&bs, &loaded);
    CHECK(live_allocations() == 0 && bad_frees == 0);
    world_reset();
    good_stick(&volume[0], 1);
    CHECK(prepare() == Q1N1_PAYLOAD_OK && top_calls == 0 && any_calls == 3);
    q1n1_payload_release(&bs, &loaded);

    /* The firmware has no room at the top: a named refusal for that file, the firmware's status and the size, no second try with AnyPages, nothing left allocated. */
    for (unsigned count = 2; count <= 5; count++) {
        for (unsigned fail_after = 0; fail_after + 2 <= count; fail_after++) {
            world_reset();
            good_stick(&volume[0], count);
            /* Let `fail_after` data files succeed, then refuse every MaxAddress call. */
            top_fail_status = EFI_ERROR(9);
            fail_top_after = fail_after;
            CHECK(prepare() == Q1N1_PAYLOAD_E_FILE_NO_MEMORY);
            CHECK(diag.index == fail_after + 1 && diag.efi == EFI_ERROR(9) && diag.got == 0);
            CHECK(diag.expected == (good_sizes[fail_after + 1] + 4095) / 4096 * 4096);
            CHECK(any_calls == 1 && top_calls == fail_after + 1 && live_allocations() == 0 && bad_frees == 0 && open_handles == 0);
            char line[200], want[200];
            q1n1_payload_refusal_line(Q1N1_PAYLOAD_E_FILE_NO_MEMORY, &diag, line, sizeof line);
            snprintf(want, sizeof want, "PAYLOAD REFUSED=FILE_NO_MEMORY INDEX=%u EFI=0X8000000000000009 GOT=0 WANT=%" PRIu64, fail_after + 1, diag.expected);
            CHECK(!strcmp(line, want));
        }
    }
    fail_top_after = 0;

    /* A success that is no place for the file: above the bound, ending above it, at zero, off a page. The pages are given back and the refusal is the same. */
    for (unsigned lie = 1; lie <= 4; lie++) {
        world_reset();
        good_stick(&volume[0], 2);
        top_lie = lie;
        CHECK(prepare() == Q1N1_PAYLOAD_E_FILE_NO_MEMORY && diag.index == 1 && diag.efi == EFI_INVALID_PARAMETER);
        CHECK(live_allocations() == 0 && bad_frees == 0 && any_calls == 1 && top_calls == 1);
    }

    /* The bound at its edges. */
    const uint64_t top = Q1N1_PAYLOAD_TOP_ADDRESS, end = top + 1;
    CHECK(top % 4096 == 4095);
    CHECK(q1n1_payload_top_ok(end - 4096, 4096) == 1);                     /* ends exactly at the bound */
    CHECK(q1n1_payload_top_ok(end - 8192, 8192) == 1 && q1n1_payload_top_ok(4096, 4096) == 1);
    CHECK(q1n1_payload_top_ok(end - 4096, 4097) == 0);                     /* one byte over */
    CHECK(q1n1_payload_top_ok(end, 4096) == 0 && q1n1_payload_top_ok(end - 4096, 8192) == 0);
    CHECK(q1n1_payload_top_ok(0, 4096) == 0 && q1n1_payload_top_ok(4097, 4096) == 0 && q1n1_payload_top_ok(4096, 0) == 0);
    CHECK(q1n1_payload_top_ok(4096, top) == 0);                            /* 4096 + top - 1 is above it */
    CHECK(q1n1_payload_top_ok(UINT64_MAX & ~UINT64_C(4095), 8192) == 0);   /* a wrap-around */
    CHECK(q1n1_payload_top_ok(UINT64_MAX & ~UINT64_C(4095), UINT64_MAX) == 0);

    /* The new refusal has its name and the same spot in the list: appended after the old ones. */
    CHECK(Q1N1_PAYLOAD_E_FILE_NO_MEMORY == Q1N1_PAYLOAD_E_DECLARE + 1);
    CHECK(!strcmp(q1n1_payload_err_name(Q1N1_PAYLOAD_E_FILE_NO_MEMORY), "FILE_NO_MEMORY"));
    CHECK(!strcmp(q1n1_payload_err_name(Q1N1_PAYLOAD_E_FILE_NO_MEMORY + 1), "UNKNOWN"));
    return 0;
}
