/* SPDX-License-Identifier: MIT */
/* Host test for the payload "retprobe" (payloads/retprobe.c), built natively with Q1N1_PAYLOAD_HOST_TEST so that its register reads, its
 * SMCs, its translation requests and its cache maintenance come from the model of tools/test-q1n1-sp11-payload-retprobe-world.h. Driven by
 * tools/test-q1n1-sp11-payload-retprobe.py under ASan and UBSan. Evidence: EXPERIMENTAL (host model only); hardware NOT RUN.
 *
 * What it pins, each against the oracle of the world header and the numbers of docs/SP11-PAYLOAD-RETPROBE.md:
 *   args      bad arguments and a missing op print nothing and call nothing; below EL2 one line and nothing else
 *   phase1    PSCI_FEATURES for the two reset functions and nothing else, a NEXT line before it, every answer decoded; no configuration
 *             (or a table, a file or a pair of files that cannot be the configuration) writes and resets nothing
 *   config    every refusal (CRC, version, path, countdown, page count, reserved bytes, alignment, range, distinct pages): PHASE 1 ran,
 *             no load, no store, no cache operation, no reset call
 *   pages     every refusal of a page (not in the map, another type, an overlap, the payload's own ranges, no translation, no write, not
 *             write-back, not identity, read and write translations that differ) for each of the three pages, and the map and the cache
 *             line size: all checked before the first store
 *   previous  the previous pages are read first, 3072 guarded loads: whole, damaged in every way the format names, unreadable; the boot
 *             counter and the states in the new header follow them; a counter at its limit is refused
 *   write     the pages written are the oracle's, byte for byte, in the cache view and in DRAM, and nothing else in memory changes
 *   cache     every line of every page is cleaned (CVAC) and fenced, then cleaned and invalidated (CIVAC) and fenced, in that order, for
 *             every line size; a page that does not verify (a clean that never reaches DRAM) is never followed by a reset
 *   reset     none, SYSTEM_RESET and SYSTEM_RESET2 (SMC64, type 0, cookie 0): after the stores and the countdown, once, last; refused
 *             before any store when PSCI_FEATURES says no; a call that returns; a counter that does not advance
 *   lines     the page of one run, line by line, in the font, at most 100 characters and 40 lines
 *   fuzz      random worlds (configurations, answers, caches, previous pages of every kind): the invariants above
 * and, only when asked, `corpus FILE` (the payload reads every triple of pages in a file made by the Python test and prints what it
 * found, for a comparison with the host tool) and `lines-report`. */
#include "test-q1n1-sp11-payload-retprobe-world.h"

/* ---- args and the exception level ----------------------------------------------------------------------------------------- */

static int suite_args(void)
{
    struct q1n1_payload_args a;
    fresh(0, 8);
    CHECK(go(NULL, NULL) == RET_BAD);
    a = build_args(); a.magic ^= 1;
    CHECK(go(&a, NULL) == RET_BAD && smc_n() == 0 && lines_n() == 0);
    a = build_args(); a.version = 2;
    CHECK(go(&a, NULL) == RET_BAD && smc_n() == 0);
    a = build_args(); a.size = sizeof a - 1;
    CHECK(go(&a, NULL) == RET_BAD && smc_n() == 0);
    a = build_args(); a.ops.puts = NULL;
    CHECK(go(&a, NULL) == RET_BAD && smc_n() == 0);
    a = build_args(); a.ops.hex = NULL;
    CHECK(go(&a, NULL) == RET_BAD && smc_n() == 0);
    a = build_args(); a.ops.load32 = NULL;
    CHECK(go(&a, NULL) == RET_BAD && smc_n() == 0 && lines_n() == 0);
    a = build_args(); a.ops.counter = NULL;
    CHECK(go(&a, NULL) == RET_BAD && smc_n() == 0 && lines_n() == 0);
    CHECK(pages_unchanged() && arena_outside_pages_unchanged());
    for (uint64_t el = 0; el <= 3; el++) {
        if (el == 2) continue;
        fresh(1, 8);
        w.el = el;
        CHECK(run(NULL) == RET_NOT_EL2);
        CHECK(nev == 1 && line_has("SKIPPED NOT_AT_EL2") == 0 && pages_unchanged() && arena_outside_pages_unchanged());
    }
    return 0;
}

/* ---- PHASE 1 and the run without a configuration -------------------------------------------------------------------------- */

static int suite_phase1(void)
{
    static const struct { uint64_t raw; const char *text; } answers[] = {
        {0, "=0X0:IMPLEMENTED"}, {1, "=0X1:IMPLEMENTED"}, {0x7fffffff, "=0X7FFFFFFF:IMPLEMENTED"},
        {~UINT64_C(0), "=0XFFFFFFFFFFFFFFFF:NOT_SUPPORTED(-1)"}, {0xffffffff, "=0XFFFFFFFF:NOT_SUPPORTED(-1)"},
        {0xfffffffe, "=0XFFFFFFFE:INVALID_PARAMETERS(-2)"}, {0xfffffff7, "=0XFFFFFFF7:INVALID_ADDRESS(-9)"},
        {0xfffffff6, "=0XFFFFFFF6:NEGATIVE"}, {0x80000000, "=0X80000000:NEGATIVE"},
    };
    struct q1n1_preload_cache *t;
    struct q1n1_payload_args a;
    int reset;
    char want[200];
    for (unsigned i = 0; i < sizeof answers / sizeof answers[0]; i++)
        for (unsigned which = 0; which < 2; which++) {
            fresh(0, 8);
            w.have_config = 0;
            w.feat[which] = answers[i].raw;
            w.feat[!which] = 0;
            CHECK(run(NULL) == RET_OK);
            snprintf(want, sizeof want, "%s%s", which ? "SYSTEM_RESET2" : "SYSTEM_RESET", answers[i].text);
            CHECK(line_contains(want) >= 0);
        }
    /* Without a configuration: the two PSCI_FEATURES calls with the two documented arguments, in order, and nothing else. */
    fresh(1, 8);
    w.have_config = 0;
    CHECK(run(NULL) == RET_OK && smc_n() == 2);
    CHECK(ev[smc_index(ID_FEATURES)].x1 == ID_RESET && smc_with(ID_RESET) == 0 && smc_with(ID_RESET2) == 0);
    CHECK(line_has("CONFIG NONE=NO_FILE") == 0 && line_has("NEXT FEATURES") > 0 && line_has("NEXT FEATURES") < smc_index(ID_FEATURES));
    CHECK(line_has("SKIPPED PHASE2=NO_CONFIG") > 0 && line_contains("WARM_TYPE ARCH=0X0 QUERY=NONE SYSTEM_RESET2=NO") >= 0);
    CHECK(cache_n("cvac") == 0 && cache_n("dsb") == 0 && loads == 0 && counter_calls == 0 && nev == lines_n() + 2);
    CHECK(pages_unchanged() && arena_outside_pages_unchanged() && no_stray_calls());
    fresh(0, 8);
    w.have_config = 0;
    w.feat[1] = 0;
    CHECK(run(NULL) == RET_OK && line_contains("WARM_TYPE ARCH=0X0 QUERY=NONE SYSTEM_RESET2=YES") >= 0);
    /* A table that cannot be read: PHASE 1 only, and the reason is printed. */
    fresh(1, 8);
    a = build_args(); a.preload_table = 0;
    CHECK(go(&a, NULL) == RET_OK && line_has("CONFIG NONE=NO_TABLE") == 0 && smc_n() == 2 && cache_n("cvac") == 0);
    a = build_args(); a.preload_table |= 4;
    CHECK(go(&a, NULL) == RET_OK && line_has("CONFIG NONE=NO_TABLE") == 0);
    a = build_args(); a.preload_size = 8;
    CHECK(go(&a, NULL) == RET_OK && line_has("CONFIG NONE=NO_TABLE") == 0);
    a = build_args(); ((struct q1n1_preload_cache *)table_buf)->version = 2;
    CHECK(go(&a, NULL) == RET_OK && line_has("CONFIG NONE=NO_TABLE") == 0);
    /* Two files that can be the configuration, a file one byte short, a wrong magic, and the payload's own entry. */
    fresh(1, 8);
    a = build_args();
    t = (struct q1n1_preload_cache *)table_buf;
    t->files[t->count] = t->files[1];
    t->count++;
    a.preload_size = 32 + t->count * sizeof(struct q1n1_cached_file);
    CHECK(go(&a, NULL) == RET_OK && line_has("CONFIG NONE=TWO_FILES") == 0 && left_alone());
    fresh(1, 8);
    a = build_args();
    ((struct q1n1_preload_cache *)table_buf)->files[1].file.size = 63;
    CHECK(go(&a, NULL) == RET_OK && line_has("CONFIG NONE=NO_FILE") == 0 && left_alone());
    fresh(1, 8);
    memcpy(w.config, "RETCFG02", 8);
    CHECK(run(NULL) == RET_OK && line_has("CONFIG NONE=NO_FILE") == 0 && left_alone());
    fresh(1, 8);
    a = build_args();
    ((struct q1n1_preload_cache *)table_buf)->files[1].base = PAYLOAD_BASE;       /* the configuration's entry is the payload's own */
    CHECK(go(&a, NULL) == RET_OK && line_has("CONFIG NONE=NO_FILE") == 0 && left_alone());
    /* Other data files in the table do not matter: the configuration is still found and used. */
    fresh(0, 8);
    w.extra_entries = 3;
    CHECK(run(&reset) == RET_OK && line_has("CONFIG OK PATH=NONE COUNTDOWN=8 PAGES=3") == 0 && cache_n("cvac") > 0);
    return 0;
}

/* ---- The configuration ------------------------------------------------------------------------------------------------------ */

static int suite_config(void)
{
    char want[100];
    struct { const char *reason; unsigned offset; uint32_t value; int fix_crc; } cases[] = {
        {"BAD_CRC", 12, 2, 0},          /* a changed word with the old CRC */
        {"BAD_CRC", 24, 0x1000, 0},
        {"BAD_VERSION", 8, 2, 1}, {"BAD_VERSION", 8, 0, 1},
        {"BAD_PATH", 12, 3, 1}, {"BAD_PATH", 12, 0xffffffff, 1},
        {"BAD_COUNTDOWN", 16, 0, 1}, {"BAD_COUNTDOWN", 16, 61, 1}, {"BAD_COUNTDOWN", 16, 0xffffffff, 1},
        {"BAD_PAGE_COUNT", 20, 2, 1}, {"BAD_PAGE_COUNT", 20, 4, 1},
        {"RESERVED_NOT_ZERO", 48, 1, 1}, {"RESERVED_NOT_ZERO", 52, 1, 1}, {"RESERVED_NOT_ZERO", 56, 0x80000000u, 1},
    };
    uint64_t pages[3];
    for (unsigned i = 0; i < sizeof cases / sizeof cases[0]; i++) {
        fresh(1, 8);
        put32(w.config + cases[i].offset, cases[i].value);
        if (cases[i].fix_crc) config_fix_crc(w.config);
        CHECK(run(NULL) == RET_CONFIG);
        snprintf(want, sizeof want, "CONFIG REFUSED=%s", cases[i].reason);
        CHECK(line_has(want) == 0 && line_has("REFUSED CONFIG") > 0 && loads == 0 && left_alone());
    }
    /* Page addresses: not aligned, zero, beyond the 48-bit space, and two pages that are one. */
    for (unsigned variant = 0; variant < 6; variant++) {
        const char *reason = variant == 0 ? "PAGE_UNALIGNED" : variant < 3 ? "PAGE_RANGE" : "PAGES_NOT_DISTINCT";
        fresh(1, 8);
        memcpy(pages, slot_addr, sizeof pages);
        if (variant == 0) pages[0] += 0x10;
        if (variant == 1) pages[1] = 0;
        if (variant == 2) pages[2] = UINT64_C(1) << 48;
        if (variant == 3) pages[2] = pages[0];
        if (variant == 4) pages[0] = pages[1];
        if (variant == 5) pages[1] = pages[2];
        config_blob(w.config, 1, 8, pages);
        CHECK(run(NULL) == RET_CONFIG);
        snprintf(want, sizeof want, "CONFIG REFUSED=%s", reason);
        CHECK(line_has(want) == 0 && loads == 0 && left_alone());
    }
    /* A good configuration is shown whole: the path, the countdown and the number of pages. */
    for (uint32_t path = 0; path < 3; path++) {
        fresh(path, 1 + path * 29);
        w.reset_returns = 1;
        w.feat[1] = 0;
        run(NULL);
        snprintf(want, sizeof want, "CONFIG OK PATH=%s COUNTDOWN=%u PAGES=3", path_names[path], 1 + path * 29);
        CHECK(line_has(want) == 0);
    }
    return 0;
}

/* ---- Pages, the map and the cache line size -------------------------------------------------------------------------------------- */

/* The arena as descriptors around the page of `slot`: conventional before it, `type` on it (nothing when type is ~0u), conventional
 * after; the loader's own descriptors stay. */
static void map_around(unsigned slot, uint32_t type)
{
    struct desc loader[5];
    memcpy(loader, w.desc + 1, sizeof loader);
    w.ndesc = 0;
    w.desc[w.ndesc++] = (struct desc){7, (uint64_t)(uintptr_t)arena, slot_page[slot]};
    if (type != ~0u) w.desc[w.ndesc++] = (struct desc){type, slot_addr[slot], 1};
    w.desc[w.ndesc++] = (struct desc){7, slot_addr[slot] + PAGE, ARENA_PAGES - slot_page[slot] - 1};
    memcpy(w.desc + w.ndesc, loader, sizeof loader);
    w.ndesc += 5;
}
static int refused_page(const char *reason, unsigned slot)
{
    char want[160];
    uint64_t value = run(NULL);
    snprintf(want, sizeof want, "REFUSED PAGE=%s INDEX=%u BASE=0X", reason, slot);
    if (value != RET_PAGE || line_has(want) < 0 || !left_alone()) {
        fprintf(stderr, "FAIL: wanted a refusal %s of page %u, the run returned %" PRIu64 "\n", reason, slot, value);
        return 0;
    }
    return 1;
}

static int suite_pages(void)
{
    static const uint32_t other_types[] = {0, 1, 2, 3, 4, 5, 6, 8, 9, 10, 11};
    static const unsigned bad_attrs[] = {0x00, 0x04, 0x44, 0xBB, 0x88, 0xFB, 0xBF, 0x0C};
    struct q1n1_payload_args a;
    char want[100];
    world_memory();                                 /* the page addresses, before the first scenario names them */
    for (unsigned slot = 0; slot < SLOTS; slot++) {
        uint64_t page = slot_addr[slot];
        fresh(0, 8); map_around(slot, ~0u);
        CHECK(refused_page("NOT_IN_MAP", slot));
        fresh(0, 8); map_around(slot, ~0u); w.desc[w.ndesc++] = (struct desc){7, page + 0x800, 1};     /* not page aligned: not a range */
        CHECK(refused_page("NOT_IN_MAP", slot));
        for (unsigned t = 0; t < sizeof other_types / sizeof other_types[0]; t++) {
            fresh(0, 8); map_around(slot, other_types[t]);
            CHECK(refused_page("OVERLAPS_OTHER", slot));
        }
        fresh(0, 8); w.desc[w.ndesc++] = (struct desc){2, page, 1};                       /* loader data over a conventional page */
        CHECK(refused_page("OVERLAPS_OTHER", slot));
        fresh(0, 8); w.stack_base = page + 128;                                           /* the map says conventional, the arguments do not */
        CHECK(refused_page("PROTECTED", slot));
        fresh(0, 8);
        a = build_args(); a.payload_base = page;
        CHECK(go(&a, NULL) == RET_PAGE && left_alone());
        snprintf(want, sizeof want, "REFUSED PAGE=PROTECTED INDEX=%u", slot);
        CHECK(line_has(want) > 0);
        fresh(0, 8); w.at_read[slot] = par_fault(5);
        CHECK(refused_page("NOT_MAPPED", slot));
        fresh(0, 8); w.at_write[slot] = par_fault(0xd);
        CHECK(refused_page("NOT_WRITABLE", slot));
        for (unsigned i = 0; i < sizeof bad_attrs / sizeof bad_attrs[0]; i++) {
            fresh(0, 8); w.at_read[slot] = w.at_write[slot] = par_ok(page, bad_attrs[i], 3);
            CHECK(refused_page("NOT_WRITE_BACK", slot));
        }
        fresh(0, 8); w.at_read[slot] = w.at_write[slot] = par_ok(page + PAGE, 0xFF, 3);
        CHECK(refused_page("NOT_IDENTITY", slot));
        fresh(0, 8); w.at_read[slot] = par_ok(page + PAGE, 0xFF, 3);
        CHECK(refused_page("READ_WRITE_DIFFER", slot));
        fresh(0, 8); w.at_write[slot] = par_ok(page, 0xFF, 2);
        CHECK(refused_page("READ_WRITE_DIFFER", slot));
        fresh(0, 8); w.at_write[slot] = par_ok(page, 0xBB, 3);
        CHECK(refused_page("READ_WRITE_DIFFER", slot));
    }
    /* The preload table and the map buffer are the payload's own, too: a page on either is refused even where the map says free. */
    for (unsigned which = 0; which < 2; which++) {
        fresh(0, 8);
        slot_addr[1] = (uint64_t)(uintptr_t)(which ? map_buf : table_buf);
        set_config(0, 8);
        w.desc[which ? 4 : 3].type = 7;
        CHECK(refused_page("PROTECTED", 1));
    }
    /* The map itself. */
    static const uint64_t strides[] = {0, 39, 44};
    for (unsigned i = 0; i < sizeof strides / sizeof strides[0]; i++) {
        fresh(0, 8);
        w.map_stride_override = strides[i];
        a = build_args();
        a.map_stride = strides[i];
        CHECK(go(&a, NULL) == RET_MAP && line_has("REFUSED MAP") > 0 && left_alone());
    }
    fresh(0, 8);
    a = build_args(); a.map_size += 1;
    CHECK(go(&a, NULL) == RET_MAP && left_alone());
    a = build_args(); a.map_size = 0;
    CHECK(go(&a, NULL) == RET_MAP && left_alone());
    a = build_args(); a.map_base = 0;
    CHECK(go(&a, NULL) == RET_MAP && left_alone());
    a = build_args(); a.map_base |= 1;
    CHECK(go(&a, NULL) == RET_MAP && left_alone());
    a = build_args(); a.map_size = 1100u * 48u;
    CHECK(go(&a, NULL) == RET_MAP && left_alone());
    /* The cache line size: DminLine 2 to 9 are accepted, the others refused before any store. */
    for (unsigned dmin = 0; dmin < 16; dmin++) {
        fresh(0, 8);
        set_cache_line(dmin);
        if (dmin >= 2 && dmin <= 9) {
            CHECK(run(NULL) == RET_OK);
        } else {
            CHECK(run(NULL) == RET_CACHE && line_has("REFUSED CACHE_LINE_SIZE") > 0 && left_alone());
        }
    }
    return 0;
}

/* ---- The previous boot's pages --------------------------------------------------------------------------------------------- */

static void replace_page(unsigned slot, const uint8_t *page) { put_page_bytes(slot, page); }

static int suite_previous(void)
{
    char want[160];
    uint8_t page[PAGE];
    struct stamp s;
    /* The first boot: noise, zero and ones. The counter is 1. */
    for (unsigned fill = 0; fill < 3; fill++) {
        fresh(0, 8);
        for (unsigned k = 0; k < 3; k++) {
            if (fill == 1) memset(page, 0, PAGE);
            else if (fill == 2) memset(page, 0xff, PAGE);
            else memcpy(page, arena + (size_t)slot_page[k] * PAGE, PAGE);
            replace_page(k, page);
        }
        CHECK(run(NULL) == RET_OK);
        for (unsigned k = 0; k < 3; k++) {
            snprintf(want, sizeof want, "PREV INDEX=%u NONE", k);
            CHECK(line_has(want) > 0);
        }
        CHECK(line_has("COUNTER THIS=1 PREVIOUS=0") > 0);
    }
    /* Whole pages: the next counter is the highest plus one, whatever the order. */
    static const uint32_t sets[][3] = {{5, 5, 5}, {3, 9, 7}, {9, 3, 7}, {1, 1, 1}, {COUNTER_MAX - 1, 4, 4}};
    for (unsigned i = 0; i < sizeof sets / sizeof sets[0]; i++) {
        uint32_t high = sets[i][0] > sets[i][1] ? sets[i][0] : sets[i][1];
        if (sets[i][2] > high) high = sets[i][2];
        fresh(0, 8); previous_whole(sets[i][0], sets[i][1], sets[i][2]);
        CHECK(run(NULL) == RET_OK);
        for (unsigned k = 0; k < 3; k++) {
            snprintf(want, sizeof want, "PREV INDEX=%u WHOLE COUNTER=%u", k, sets[i][k]);
            CHECK(line_has(want) > 0);
        }
        snprintf(want, sizeof want, "COUNTER THIS=%u PREVIOUS=%u", high + 1, high);
        CHECK(line_has(want) > 0);
        unsigned whole[3] = {S_WHOLE, S_WHOLE, S_WHOLE};
        CHECK(all_truth_pages_are(high + 1, high, whole));
    }
    /* A counter at the limit of the body word is refused: one more would not fit. */
    fresh(0, 8); previous_whole(COUNTER_MAX, COUNTER_MAX, COUNTER_MAX);
    CHECK(run(NULL) == RET_OVERFLOW && line_has("REFUSED COUNTER_OVERFLOW") > 0 && loads == 3072 && left_alone());
    /* One page damaged in each way the format names; the other two whole. The expectation is written down, and the oracle agrees. */
    static const struct { const char *name; unsigned state; int bad_words; int crc_ok; } damages[] = {
        {"one body bit", S_PARTIAL, 1, 0}, {"the crc word", S_PARTIAL, 0, 0}, {"a timestamp byte", S_PARTIAL, 0, 0},
        {"the body zeroed", S_PARTIAL, 992, 0}, {"half the body zeroed", S_PARTIAL, 496, 0}, {"the header zeroed", S_PARTIAL, 0, 0},
        {"another page's address", S_PARTIAL, 0, 0}, {"another page's index", S_PARTIAL, 0, 0}, {"the magic", S_PARTIAL, 0, 0},
        {"the version", S_PARTIAL, 0, 0}, {"a counter of zero", S_PARTIAL, 0, 0}, {"a body word, the CRC redone", S_PARTIAL, 1, 1},
        {"the header zeroed, 16 body words left", S_PARTIAL, 976, 0}, {"the header zeroed, 15 body words left", S_NONE, 977, 0},
        {"zero", S_NONE, -1, 0}, {"ones", S_NONE, -1, 0},
        {"a valid page that names another index", S_PARTIAL, 0, 1}, {"a valid page of layout version 2", S_PARTIAL, 0, 1},
        {"a valid page that names another address", S_PARTIAL, 0, 1}, {"a valid page of counter zero", S_PARTIAL, 0, 1},
        {"two epochs in one body, the header gone", S_PARTIAL, 392, 0},
    };
    for (unsigned d = 0; d < sizeof damages / sizeof damages[0]; d++) {
        fresh(0, 8); previous_whole(4, 4, 4);
        uint8_t *p = arena + (size_t)slot_page[1] * PAGE;
        memcpy(page, p, PAGE);
        switch (d) {
        case 0: page[128 + 7 * 4 + 1] ^= 0x10; break;
        case 1: page[124] ^= 1; break;
        case 2: page[34] ^= 0x40; break;
        case 3: memset(page + 128, 0, PAGE - 128); break;
        case 4: memset(page + 128, 0, (PAGE - 128) / 2); break;
        case 5: memset(page, 0, 128); break;
        case 6: put64(page + 16, slot_addr[1] + PAGE); break;
        case 7: put32(page + 12, 2); break;
        case 8: page[0] ^= 1; break;
        case 9: put32(page + 8, 2); break;
        case 10: put32(page + 24, 0); break;
        case 11: page[128 + 200] ^= 0x20; put32(page + 124, 0); put32(page + 124, crc32_ref(page, PAGE)); break;
        case 12: case 13:
            memset(page, 0, 128);
            for (unsigned i = 0; i < 992; i++) if (i >= (d == 12 ? 16u : 15u)) memset(page + 128 + 4 * i, 0xA5, 4);
            break;
        case 14: memset(page, 0, PAGE); break;
        case 15: memset(page, 0xff, PAGE); break;
        case 16: make_page(page, 0, slot_addr[1], 4); break;
        case 17: put32(page + 8, 2); put32(page + 124, 0); put32(page + 124, crc32_ref(page, PAGE)); break;
        case 18: make_page(page, 1, slot_addr[0], 4); break;
        case 19: make_page(page, 1, slot_addr[1], 0); break;
        default:
            memset(page, 0, 128);
            for (unsigned i = 0; i < 992; i++) put32(page + 128 + 4 * i, (i < 600 ? 7u : 3u) << 12 | 1u << 10 | i);
            break;
        }
        replace_page(1, page);
        struct verdict v = oracle_classify(page, 1, slot_addr[1]);
        CHECK(v.state == damages[d].state);
        CHECK(run(NULL) == RET_OK);
        snprintf(want, sizeof want, "PREV INDEX=1 %s", state_names[damages[d].state]);
        int at = line_has(want);
        CHECK(at > 0);
        if (damages[d].state == S_PARTIAL) {
            snprintf(want, sizeof want, "BAD_WORDS=%d CRC=%s", damages[d].bad_words, damages[d].crc_ok ? "OK" : "BAD");
            CHECK(strstr(ev[at].text, want) != NULL && (int)v.bad_words == damages[d].bad_words);
        }
        CHECK(line_has("COUNTER THIS=5 PREVIOUS=4") > 0 && line_has("PREV INDEX=0 WHOLE COUNTER=4") > 0 && line_has("PREV INDEX=2 WHOLE COUNTER=4") > 0);
    }
    /* A damaged page never lends its counter: whole pages of 3 and 7 and a damaged one that says 9 give 8. */
    fresh(0, 8); previous_whole(3, 9, 7);
    memcpy(page, arena + (size_t)slot_page[1] * PAGE, PAGE);
    page[128 + 100] ^= 1;
    replace_page(1, page);
    CHECK(run(NULL) == RET_OK && line_has("COUNTER THIS=8 PREVIOUS=7") > 0 && line_has("PREV INDEX=1 PARTIAL BAD_WORDS=1 CRC=BAD") > 0);
    /* A whole page of the right epoch in the wrong place is not whole: the header names the slot and the address. */
    fresh(0, 8); previous_whole(6, 6, 6);
    replace_page(2, arena + (size_t)slot_page[0] * PAGE);
    CHECK(run(NULL) == RET_OK && line_has("PREV INDEX=2 PARTIAL") > 0 && line_has("PREV INDEX=0 WHOLE COUNTER=6") > 0);
    /* A page that cannot be read: the abort is an error, the page is UNREADABLE, the others are read, and the run goes on. */
    for (unsigned word = 0; word < 1024; word += 341) {
        fresh(0, 8); previous_whole(2, 2, 2);
        w.fault_slot = 1; w.fault_word = word;
        CHECK(run(NULL) == RET_OK);
        snprintf(want, sizeof want, "PREV INDEX=1 UNREADABLE LOAD_ERROR=%u WORD=%u", Q1N1_PAYLOAD_LOAD_E_FAULT, word);
        CHECK(line_has(want) > 0 && line_has("PREV INDEX=0 WHOLE COUNTER=2") > 0 && line_has("PREV INDEX=2 WHOLE COUNTER=2") > 0);
        CHECK(line_has("COUNTER THIS=3 PREVIOUS=2") > 0 && loads == 2048 + word + 1);
        unsigned seen[3] = {S_WHOLE, S_UNREADABLE, S_WHOLE};
        CHECK(all_truth_pages_are(3, 2, seen));
    }
    /* A full read is 3072 loads: the runner allows 4096 in a call. And the page that was read is rewritten in the same boot. */
    fresh(0, 8); previous_whole(11, 11, 11);
    CHECK(run(NULL) == RET_OK && loads == 3072);
    unsigned whole[3] = {S_WHOLE, S_WHOLE, S_WHOLE};
    expected_stamp(&s, 12, 11, whole);
    CHECK(all_truth_pages_are(12, 11, whole));
    return 0;
}

/* ---- What is written -------------------------------------------------------------------------------------------------------- */

static int suite_write(void)
{
    unsigned none[3] = {S_NONE, S_NONE, S_NONE}, whole[3] = {S_WHOLE, S_WHOLE, S_WHOLE};
    int reset;
    /* A first boot, each path, two line sizes: the pages are the oracle's, in the cache view and in DRAM, and nothing else changed. */
    for (uint32_t path = 0; path < 3; path++)
        for (unsigned dmin = 2; dmin <= 9; dmin += 7) {
            fresh(path, 3);
            w.reset_returns = 1;
            w.reset_ret = ~UINT64_C(0);
            w.feat[1] = path == 2 ? 0 : ~UINT64_C(0);
            set_cache_line(dmin);
            CHECK(run(NULL) == (path ? RET_RETURNED : RET_OK));
            CHECK(all_truth_pages_are(1, 0, none) && arena_outside_pages_unchanged() && no_stray_calls());
            CHECK(loads == 3072 && smc_n() == (path ? 3u : 2u));
        }
    /* A second boot after a first: the pages carry the previous run's counter and states. */
    fresh(0, 8);
    CHECK(run(NULL) == RET_OK);
    memcpy(pristine, truth, (size_t)ARENA_PAGES * PAGE);
    memcpy(arena, truth, (size_t)ARENA_PAGES * PAGE);
    CHECK(run(NULL) == RET_OK && line_has("COUNTER THIS=2 PREVIOUS=1") > 0 && all_truth_pages_are(2, 1, whole));
    /* The header's descriptor fields follow the map; what PSCI answered is in the header, raw. */
    fresh(0, 8);
    w.feat[0] = 0x00000001; w.feat[1] = 0xFFFFFFFFFFFFFFFEull;
    CHECK(run(NULL) == RET_OK);
    {
        const uint8_t *p = truth + (size_t)slot_page[2] * PAGE;
        CHECK(get32(p + 60) == 7 && get64(p + 64) == (uint64_t)(uintptr_t)arena && get64(p + 72) == (uint64_t)ARENA_PAGES * PAGE);
        CHECK(get32(p + 44) == 1 && get32(p + 48) == 0xFFFFFFFEu && get32(p + 28) == 0 && p[57] == 1 && p[58] == 0 && p[59] == 0);
    }
    /* A page that does not verify: the clean never reaches DRAM, the re-read after the invalidate shows it, nothing is reset. A lost
     * first line leaves the CRC word (in the second) right, so only the CRC of the whole page can tell. */
    for (unsigned slot = 0; slot < 3; slot++)
        for (int line = -1; line < 1; line++) {
            fresh(1, 8);
            w.lossy_slot = (int)slot;
            w.lossy_line = line;
            CHECK(run(&reset) == RET_VERIFY && !reset && resets_called == 0);
            CHECK(line_has("VERIFY FAILED PAGES=1") > 0 && smc_n() == 2 && line_contains("NEXT RESET") < 0);
        }
    return 0;
}

/* ---- Cache maintenance ------------------------------------------------------------------------------------------------------- */

static int suite_cache(void)
{
    unsigned none[3] = {S_NONE, S_NONE, S_NONE};
    for (unsigned dmin = 2; dmin <= 9; dmin++) {
        unsigned line = 4u << dmin, per_page = PAGE / line, last_cvac = 0, first_civac = ~0u, dsb1 = 0, dsb2 = 0, seen_dsb = 0;
        fresh(0, 8);
        set_cache_line(dmin);
        CHECK(run(NULL) == RET_OK);
        CHECK(cache_n("cvac") == 3 * per_page && cache_n("civac") == 3 * per_page && cache_n("dsb") == 2);
        for (unsigned i = 0; i < nev; i++) {
            if (ev[i].kind != EV_CACHE) continue;
            if (!strcmp(ev[i].text, "cvac")) last_cvac = i;
            if (!strcmp(ev[i].text, "civac") && first_civac == ~0u) first_civac = i;
            if (!strcmp(ev[i].text, "dsb")) { if (!seen_dsb++) dsb1 = i; else dsb2 = i; }
        }
        CHECK(last_cvac < dsb1 && dsb1 < first_civac && first_civac < dsb2);       /* all CVAC, DSB, all CIVAC, DSB */
        for (unsigned k = 0; k < 3; k++)
            for (unsigned offset = 0; offset < PAGE; offset += line) {
                unsigned cvac = 0, civac = 0;
                for (unsigned i = 0; i < nev; i++) {
                    if (ev[i].kind != EV_CACHE || ev[i].id != slot_addr[k] + offset) continue;
                    cvac += !strcmp(ev[i].text, "cvac");
                    civac += !strcmp(ev[i].text, "civac");
                }
                CHECK(cvac == 1 && civac == 1);
            }
        CHECK(no_stray_calls() && all_truth_pages_are(1, 0, none));
    }
    fresh(0, 8);
    w.at_write[1] = par_fault(0xd);
    CHECK(run(NULL) == RET_PAGE && cache_n("cvac") == 0 && cache_n("civac") == 0 && cache_n("dsb") == 0);
    return 0;
}

/* ---- The reset -------------------------------------------------------------------------------------------------------------------- */

static int suite_reset(void)
{
    unsigned none[3] = {S_NONE, S_NONE, S_NONE};
    static const uint64_t negative[] = {~UINT64_C(0), 0xffffffffu, 0xfffffffeu, 0xfffffff7u, 0xfffffff6u, 0x80000000u, 0xffffffff80000000ull};
    static const struct { uint64_t freq; uint32_t seconds; } waits[] = {{19200000, 1}, {19200000, 7}, {19200000, 60}, {1000000, 3}, {1000000000, 2}};
    int reset = 0;
    /* Path none: no reset call, no wait, the canaries stay. */
    fresh(0, 8);
    CHECK(run(&reset) == RET_OK && !reset && smc_n() == 2 && counter_calls == 1);
    CHECK(line_has("PATH REQUESTED=NONE USED=NONE") > 0 && line_has("RESET NONE CANARIES STAY FOR A MANUAL RESET") > 0 && line_contains("NEXT RESET") < 0);
    /* SYSTEM_RESET implemented (0 and flags): pages, clean, verify, countdown, then one SYSTEM_RESET that does not return. */
    for (unsigned flags = 0; flags < 2; flags++) {
        fresh(1, 8);
        w.feat[0] = flags;
        run(&reset);
        CHECK(reset == 1 && resets_called == 1 && smc_with(ID_RESET) == 1 && smc_with(ID_RESET2) == 0 && smc_n() == 3);
        int call = smc_index(ID_RESET), countdown = line_has("NEXT RESET AFTER 8 S"), callline = line_has("RESET CALL SYSTEM_RESET");
        CHECK(call == (int)nev - 1 && ev[call].x1 == 0 && ev[call].x2 == 0 && ev[call].x3 == 0);     /* the last thing it did */
        CHECK(countdown > 0 && callline > countdown && callline < call);
        CHECK(ev[call].now - ev[countdown].now >= 8u * w.cntfrq && ev[call].now - ev[countdown].now < 9u * w.cntfrq);
        CHECK(line_has("VERIFY OK") > 0 && line_has("VERIFY OK") < countdown && line_has("CLEAN DC_CVAC_DSB LINE=64 LINES=192") > 0);
        CHECK(line_has("PATH REQUESTED=PSCI_RESET USED=PSCI_RESET") > 0);
        CHECK(all_truth_pages_are(1, 0, none) && arena_outside_pages_unchanged() && no_stray_calls());     /* what a reset keeps */
        unsigned last_cache = 0;
        for (unsigned i = 0; i < nev; i++) if (ev[i].kind == EV_CACHE) last_cache = i;
        CHECK(last_cache < (unsigned)countdown);                                  /* no store after the clean: nothing follows it */
    }
    /* SYSTEM_RESET2: the SMC64 function with reset type 0 and cookie 0. */
    fresh(2, 5);
    w.feat[1] = 0;
    run(&reset);
    CHECK(reset == 1 && smc_with(ID_RESET2) == 1 && smc_with(ID_RESET) == 0 && smc_n() == 3 && no_stray_calls());
    int announced = line_has("NEXT RESET AFTER 5 S");
    CHECK(announced > 0 && line_has("RESET CALL SYSTEM_RESET2 TYPE=ARCH_WARM") > announced);
    CHECK(ev[smc_index(ID_RESET2)].x1 == 0 && ev[smc_index(ID_RESET2)].x2 == 0 && ev[smc_index(ID_RESET2)].now - ev[announced].now >= 5u * w.cntfrq);
    CHECK(all_truth_pages_are(1, 0, none));
    /* Not implemented (any negative answer): refused before the first store, no wait, no reset call, whatever the other function says. */
    for (unsigned i = 0; i < sizeof negative / sizeof negative[0]; i++)
        for (uint32_t path = 1; path <= 2; path++) {
            fresh(path, 8);
            w.feat[path - 1] = negative[i];
            w.feat[2 - path] = 0;
            CHECK(run(&reset) == RET_NOT_IMPL && !reset);
            CHECK(line_has(path == 1 ? "REFUSED RESET_NOT_IMPLEMENTED SYSTEM_RESET" : "REFUSED RESET_NOT_IMPLEMENTED SYSTEM_RESET2") > 0);
            CHECK(loads == 0 && counter_calls == 0 && left_alone());
        }
    /* A reset that returns: the value is printed, the run ends, nothing is called again. */
    for (uint32_t path = 1; path <= 2; path++) {
        fresh(path, 2);
        w.feat[0] = w.feat[1] = 0;
        w.reset_returns = 1;
        w.reset_ret = ~UINT64_C(1);
        CHECK(run(&reset) == RET_RETURNED && !reset && resets_called == 1 && smc_n() == 3);
        CHECK(line_contains("RESET RETURNED=0XFFFFFFFFFFFFFFFE:INVALID_PARAMETERS(-2)") > 0 && ev[nev - 1].kind == EV_LINE);
    }
    /* A counter that does not advance, that runs backwards, or a frequency that cannot be right: announced, not made. The pages were written
     * first. A counter that ran backwards would, with an unsigned difference, read as an endless wait and the reset would be called at once. */
    for (unsigned variant = 0; variant < 7; variant++) {
        fresh(1, 8);
        if (variant == 0) w.step = 0;
        if (variant == 1) w.cntfrq = 0;
        if (variant == 2) w.cntfrq = 999999;
        if (variant == 3) w.cntfrq = 1000000001u;
        if (variant == 4) w.stuck_after = 100;
        if (variant == 5) { w.back_after = 2; w.back_by = 400000; }         /* the first read of the wait is already below its start */
        if (variant == 6) { w.back_after = 200; w.back_by = 4000000; }      /* it ran backwards after a while: below its start again */
        CHECK(run(&reset) == RET_COUNTER && !reset && resets_called == 0 && line_has("REFUSED COUNTER_NOT_ADVANCING") > 0);
        CHECK(smc_n() == 2 && cache_n("dsb") == 2);
        if (variant >= 5) CHECK(counter_calls > (variant == 5 ? 2u : 200u) && line_contains("NEXT RESET AFTER 8 S") > 0);
    }
    /* The countdown is the configured number of seconds of the counter, at the frequencies the guard allows. */
    for (unsigned i = 0; i < sizeof waits / sizeof waits[0]; i++) {
        char want[40];
        fresh(1, waits[i].seconds);
        w.cntfrq = waits[i].freq;
        w.step = waits[i].freq / 1000;
        snprintf(want, sizeof want, "NEXT RESET AFTER %u S", waits[i].seconds);
        run(&reset);
        announced = line_has(want);
        CHECK(reset == 1 && announced > 0);
        uint64_t waited = ev[smc_index(ID_RESET)].now - ev[announced].now;
        CHECK(waited >= (uint64_t)waits[i].seconds * waits[i].freq && waited < (uint64_t)waits[i].seconds * waits[i].freq + 8 * w.step);
    }
    return 0;
}

/* ---- The page, line by line ------------------------------------------------------------------------------------------------------ */

static int suite_lines(void)
{
    static const char *const head[] = {
        PFX "CONFIG OK PATH=PSCI_RESET COUNTDOWN=8 PAGES=3", PFX "NEXT FEATURES", PFX "FEATURES SYSTEM_RESET=0X0:IMPLEMENTED",
        PFX "FEATURES SYSTEM_RESET2=0XFFFFFFFFFFFFFFFF:NOT_SUPPORTED(-1)", PFX "WARM_TYPE ARCH=0X0 QUERY=NONE SYSTEM_RESET2=NO",
    };
    static const char *const order[] = {
        "PAGE INDEX=2 BASE=0X", "NEXT READ PREVIOUS PAGES", "PREV INDEX=0 WHOLE COUNTER=3", "COUNTER THIS=4 PREVIOUS=3",
        "NEXT WRITE PAGES", "WROTE PAGE=0 CRC=0X", "CLEAN DC_CVAC_DSB LINE=64 LINES=192", "VERIFY OK",
        "PATH REQUESTED=PSCI_RESET USED=PSCI_RESET", "NEXT RESET AFTER 8 S", "RESET CALL SYSTEM_RESET",
    };
    unsigned seen = 0, at = 0;
    char text[100];
    int reset = 0;
    fresh(1, 8);
    previous_whole(3, 3, 3);
    run(&reset);
    CHECK(reset == 1);
    for (unsigned i = 0; i < nev && seen < sizeof head / sizeof head[0]; i++)
        if (ev[i].kind == EV_LINE) CHECK(!strcmp(ev[i].text, head[seen++]));
    CHECK(seen == 5);
    for (unsigned i = 0; i < sizeof order / sizeof order[0]; i++) {
        int found = line_has(order[i]);
        CHECK(found > (int)at);                                  /* each line comes after the one before it */
        at = (unsigned)found;
    }
    CHECK(lines_n() <= 40 && bad_lines == 0 && line_has("PAGE INDEX=0 BASE=0X") > 0);
    /* The CRC of each page is on a WROTE line. */
    for (unsigned k = 0; k < 3; k++) {
        snprintf(text, sizeof text, "PAGE=%u CRC=0X%X", k, (unsigned)get32(truth + (size_t)slot_page[k] * PAGE + 124));
        CHECK(line_contains(text) > 0);
    }
    return 0;
}

/* ---- Random worlds ------------------------------------------------------------------------------------------------------------- */

static void random_page(unsigned slot, unsigned kind)
{
    uint8_t page[PAGE];
    struct stamp s;
    unsigned prev[3] = {(unsigned)(next_random() % 4), (unsigned)(next_random() % 4), (unsigned)(next_random() % 4)};
    expected_stamp(&s, 1 + next_random() % 40, next_random() % 40, prev);
    s.timestamp = next_random();
    oracle_page(page, slot, kind == 6 ? slot_addr[(slot + 1) % 3] : slot_addr[slot], &s);
    switch (kind) {
    case 1: for (unsigned n = 1 + next_random() % 8; n; n--) page[next_random() % PAGE] ^= (uint8_t)(1u << (next_random() % 8)); break;
    case 2: { unsigned at = (unsigned)(next_random() % PAGE), n = 1 + (unsigned)(next_random() % 512); memset(page + at, 0, at + n < PAGE ? n : PAGE - at); break; }
    case 3: for (unsigned i = 0; i < PAGE; i++) page[i] = (uint8_t)next_random(); break;
    case 4: memset(page, (int)(next_random() & 1 ? 0 : 0xff), PAGE); break;
    case 5: for (unsigned i = 128; i < PAGE; i += 4) if (next_random() % 3) put32(page + i, (uint32_t)next_random()); break;
    case 7: for (unsigned i = 0; i < 128; i++) if (next_random() % 2) page[i] = (uint8_t)next_random(); break;
    default: break;
    }
    put_page_bytes(slot, page);
}

static int suite_fuzz(void)
{
    for (unsigned round = 0; round < 700; round++) {
        struct verdict v[3];
        unsigned highest = 0, states[3];
        int reset = 0;
        char want[100];
        fresh((uint32_t)(next_random() % 3), (uint32_t)(1 + next_random() % 60));
        w.feat[0] = next_random() % 3 == 0 ? ~UINT64_C(0) : next_random() % 4;
        w.feat[1] = next_random() % 3 == 0 ? ~UINT64_C(0) : next_random() % 4;
        w.reset_returns = (int)(next_random() & 1);
        w.reset_ret = next_random() % 2 ? ~UINT64_C(0) : (uint64_t)(next_random() % 5) - 6;
        w.step = 1 + next_random() % 40000;
        set_cache_line((unsigned)(2 + next_random() % 8));
        for (unsigned k = 0; k < 3; k++) {
            random_page(k, (unsigned)(next_random() % 8));
            v[k] = oracle_classify(arena + (size_t)slot_page[k] * PAGE, k, slot_addr[k]);
            states[k] = v[k].state;
        }
        uint64_t value = run(&reset);
        CHECK(no_stray_calls() && arena_outside_pages_unchanged() && lines_n() <= 40 && value <= RET_CACHE);
        if (w.path && (int32_t)(uint32_t)w.feat[w.path - 1] < 0) {            /* the reset is not implemented: nothing else happened */
            CHECK(value == RET_NOT_IMPL && loads == 0 && left_alone());
            continue;
        }
        for (unsigned k = 0; k < 3; k++) {
            if (v[k].state == S_WHOLE) {
                snprintf(want, sizeof want, "PREV INDEX=%u WHOLE COUNTER=%u", k, v[k].counter);
                if (v[k].counter > highest) highest = v[k].counter;
            } else {
                snprintf(want, sizeof want, "PREV INDEX=%u %s", k, state_names[v[k].state]);
            }
            CHECK(line_has(want) > 0);
        }
        CHECK(smc_with(ID_RESET) + smc_with(ID_RESET2) <= 1);
        if (resets_called) {      /* a reset call comes only for the configured function, after the pages are in DRAM */
            CHECK(w.path != 0 && smc_with(w.path == 1 ? ID_RESET : ID_RESET2) == 1 && all_truth_pages_are(highest + 1, highest, states));
        } else if (value == RET_OK) {
            CHECK(w.path == 0 && all_truth_pages_are(highest + 1, highest, states));
        }
    }
    return 0;
}

/* ---- The corpus: the payload's reader against the host tool ------------------------------------------------------------------------ */

/* The corpus file holds three 4096-byte pages a case. The model's pages have addresses of its own, which the file cannot know, so a page that
 * names the nominal address of its slot (CORPUS_ADDRESS) is rewritten to name the model's, and its CRC is recomputed only when it was valid for
 * the nominal one: a page the file damages stays damaged in exactly that way. A page that names any other address is left as it is. */
#define CORPUS_ADDRESS(k) (UINT64_C(0xFEED00001000) + (k) * UINT64_C(0x1000))

static void corpus_fixup(uint8_t *page, unsigned k)
{
    uint8_t copy[PAGE];
    int was_valid;
    if (get64(page + 16) != CORPUS_ADDRESS(k)) return;
    memcpy(copy, page, PAGE);
    put32(copy + 124, 0);
    was_valid = crc32_ref(copy, PAGE) == get32(page + 124);
    put64(page + 16, slot_addr[k]);
    if (!was_valid) return;
    memcpy(copy, page, PAGE);
    put32(copy + 124, 0);
    put32(page + 124, crc32_ref(copy, PAGE));
}

static int run_corpus(const char *file)
{
    FILE *f = fopen(file, "rb");
    uint8_t buffer[3 * PAGE];
    unsigned cases = 0;
    if (!f) { fprintf(stderr, "cannot open %s\n", file); return 2; }
    while (fread(buffer, 1, sizeof buffer, f) == sizeof buffer) {
        fresh(0, 8);
        for (unsigned k = 0; k < 3; k++) {
            corpus_fixup(buffer + (size_t)k * PAGE, k);
            put_page_bytes(k, buffer + (size_t)k * PAGE);
        }
        run(NULL);
        printf("CASE %u", cases++);
        for (unsigned k = 0; k < 3; k++) {
            const char *found = "?";
            unsigned counter = 0, bad = 0;
            char crc = '-';
            for (unsigned s = 0; s < 4; s++) {
                char key[64];
                snprintf(key, sizeof key, "PREV INDEX=%u %s", k, state_names[s]);
                int at = line_has(key);
                if (at < 0) continue;
                found = state_names[s];
                if (strstr(ev[at].text, "COUNTER=")) counter = (unsigned)strtoul(strstr(ev[at].text, "COUNTER=") + 8, NULL, 10);
                if (strstr(ev[at].text, "BAD_WORDS=")) bad = (unsigned)strtoul(strstr(ev[at].text, "BAD_WORDS=") + 10, NULL, 10);
                if (strstr(ev[at].text, "CRC=OK")) crc = 'O';
                if (strstr(ev[at].text, "CRC=BAD")) crc = 'B';
            }
            printf(" %s:%u:%u:%c", found, counter, bad, crc);
        }
        int c = line_contains("COUNTER THIS=");
        printf(" THIS=%u\n", c >= 0 ? (unsigned)strtoul(strstr(ev[c].text, "THIS=") + 5, NULL, 10) : 0);
    }
    fclose(f);
    return 0;
}

/* The number docs/SP11-PAYLOAD-RETPROBE.md plans a chain's page with: the most lines over every path, answer and previous state. */
static int report_lines(void)
{
    unsigned most = 0;
    for (unsigned round = 0; round < 3000; round++) {
        fresh((uint32_t)(next_random() % 3), (uint32_t)(1 + next_random() % 60));
        w.feat[0] = next_random() % 2 ? 0 : ~UINT64_C(0);
        w.feat[1] = next_random() % 2 ? 0 : ~UINT64_C(0);
        w.reset_returns = (int)(next_random() & 1);
        w.reset_ret = ~UINT64_C(0);
        w.step = 1 + next_random() % 40000;
        for (unsigned k = 0; k < 3; k++) random_page(k, (unsigned)(next_random() % 8));
        if (next_random() % 4 == 0) { w.fault_slot = (int)(next_random() % 3); w.fault_word = (unsigned)(next_random() % 1024); }
        run(NULL);
        if (lines_n() > most) most = lines_n();
    }
    printf("LINES_MAX=%u\n", most);
    return 0;
}

/* The page of a run on a fresh arena, a line each, for the examples of docs/SP11-PAYLOAD-RETPROBE.md: the reset path (0 to 2) and, when
 * "returns" follows, a reset call that comes back with NOT_SUPPORTED instead of taking the machine. The addresses are the model's. */
static int report_page(const char *path, int returns)
{
    int reset = 0;
    fresh((uint32_t)strtoul(path, NULL, 10), 8);
    w.reset_returns = returns;
    w.reset_ret = ~UINT64_C(0);
    run(&reset);
    for (unsigned i = 0; i < nev; i++)
        if (ev[i].kind == EV_LINE) printf("%s\n", ev[i].text);
    return 0;
}

int main(int argc, char **argv)
{
    static const struct { const char *name; int (*run)(void); } suites[] = {
        {"args", suite_args}, {"phase1", suite_phase1}, {"config", suite_config}, {"pages", suite_pages}, {"previous", suite_previous},
        {"write", suite_write}, {"cache", suite_cache}, {"reset", suite_reset}, {"lines", suite_lines}, {"fuzz", suite_fuzz},
    };
    unsigned ran = 0;
    alloc_world();
    if (argc > 2 && !strcmp(argv[1], "corpus")) return run_corpus(argv[2]);
    if (argc > 1 && !strcmp(argv[1], "lines-report")) return report_lines();
    if (argc > 2 && !strcmp(argv[1], "page-report")) return report_page(argv[2], argc > 3 && !strcmp(argv[3], "returns"));
    for (unsigned i = 0; i < sizeof suites / sizeof suites[0]; i++) {
        if (argc > 1 && strcmp(argv[1], "all") && strcmp(argv[1], suites[i].name)) continue;
        if (suites[i].run()) { fprintf(stderr, "FAIL: suite %s\n", suites[i].name); return 1; }
        ran++;
    }
    printf("PASS: %u payload retprobe suites, %u checks\n", ran, checks);
    return 0;
}
