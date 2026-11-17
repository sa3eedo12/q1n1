/* SPDX-License-Identifier: MIT */
/* Payload "retprobe": the DRAM retention probe M10 of the Surface Pro 11 (docs/SP11-PAYLOAD-RETPROBE.md; the design, the operator's
 * runbook and the host tools are in Snapintosh docs/SP11-RETENTION-PROBE.md). EXPERIMENTAL; hardware NOT RUN.
 *
 * Question. Does a page of DRAM keep its bytes across a reset of this board, and across which reset path? Today every EL2 result
 * reaches the operator as a photograph of the panel, and a reset takes the panel with it. If a page survives a reset, a later boot can
 * read the earlier boot's report from it and put it on the stick as a file (the design document). Nothing is assumed: UNKNOWN until a
 * boot on the unit says WHOLE, PARTIAL or NONE for each page.
 *
 * PHASE 1, always, read only in the machine's sense. PSCI_FEATURES (function 0x8400000A) is asked about SYSTEM_RESET (0x84000009) and
 * SYSTEM_RESET2 (0xC4000012) and the answers are printed. PSCI_FEATURES takes function ids and has no reset-type argument, so the
 * architectural warm reset type (0) cannot be queried: it is reported as implied by SYSTEM_RESET2 (INFERRED: the PSCI specification
 * was not re-read; Linux treats it so) and the call itself is what would say INVALID_PARAMETERS.
 *
 * PHASE 2, only with a configuration file. The runner's manifest may list one data file of exactly 64 bytes that starts with the
 * magic RETCFG01 (layout below). Without it nothing is written and nothing is reset: a manifest that lists this payload alone is a
 * PHASE 1 run and needs no authorisation beyond the one `psci` has. With it the payload
 *   1. checks the whole configuration and every page, and refuses all of PHASE 2 before touching memory when any check fails: each of
 *      the three 4 KiB pages must be inside ONE descriptor of the final memory map, of type 7 (conventional: free memory, in no
 *      range the runner or a payload owns), overlap no descriptor of another type and none of the payload, its stack, the preload
 *      table or the map buffer, and EL2's stage 1 must translate it for a read and for a write to itself (identity) as Normal
 *      write-back (AT S1E2R and AT S1E2W: they make no access and cannot abort);
 *   2. asks, when the configuration names a reset, whether that function is implemented, and refuses before any store when it is not;
 *   3. READS the previous boot's three pages FIRST, through the runner's guarded load32 (a second reader, independent of the one in the
 *      Shell and the one on the Mac): WHOLE (header, CRC and body), PARTIAL or NONE; the new boot counter is the highest WHOLE
 *      counter plus one, or 1;
 *   4. writes the three new pages (the only stores of this payload outside its own stack), cleans each cache line with DC CVAC, DSB SY;
 *   5. verifies them: DC CIVAC over every line, DSB SY, then it recomputes the CRC of every page from memory;
 *   6. prints a countdown line and waits N seconds of the counter, so that the page can be seen and the operator can hold the key
 *      that starts the stick again (the runbook), then calls the reset the configuration names, once. It is never called when the
 *      stores or their verification failed, when the counter does not advance or runs backwards, or when PSCI_FEATURES did not report
 *      it implemented. If the call returns, the line says what it returned and nothing else is done.
 *
 * What it can call, with SMC at EL2, each through its own helper with a fixed function id and no other id expressible: PSCI_FEATURES
 * (the two arguments above), SYSTEM_RESET and SYSTEM_RESET2 (reset type 0, architectural warm reset, cookie 0). It never calls
 * CPU_ON, CPU_OFF, SYSTEM_OFF, SYSTEM_SUSPEND or any vendor id. It writes no system register but PAR_EL1, which its two translation
 * requests (AT S1E2R and AT S1E2W) write as their answer. SYSTEM_RESET is the architectural cold-reset call and the warm reset is
 * SYSTEM_RESET2 (NOT_SUPPORTED on the unit, OBSERVED once; the PSCI text was not re-read: INFERRED), so a NONE after SYSTEM_RESET is a
 * likely outcome and says nothing is wrong.
 *
 * Page record, layout version 1, little endian, 4096 bytes: a 128-byte header of 32 words, then 992 body words.
 *   w0 w1   magic "RETCAN01"              w2  layout version (1)           w3  page index (0 to 2)
 *   w4 w5   physical address of the page   w6  boot counter (this boot)     w7  previous counter (highest WHOLE page, else 0)
 *   w8 w9   CNTPCT_EL0 when written        w10 CNTFRQ_EL0 (low 32 bits)     w11 raw w0 of PSCI_FEATURES(SYSTEM_RESET)
 *   w12     raw w0 of PSCI_FEATURES(SYSTEM_RESET2)
 *   w13     bytes: reset path requested, reset path used (0 none, 1 SYSTEM_RESET, 2 SYSTEM_RESET2 warm), the previous state of
 *           page 0 and of page 1 (0 NONE, 1 PARTIAL, 2 WHOLE, 3 UNREADABLE)
 *   w14     bytes: the previous state of page 2, flush method (1: DC CVAC by line, DSB SY), two zero bytes
 *   w15     type of the memory-map descriptor that holds the page (7)    w16 w17 its start    w18 w19 its size in bytes
 *   w20-w30 zero                           w31 CRC-32 (IEEE, as zlib.crc32) of the page with this word taken as zero
 *   body word i (0 to 991) = boot counter << 12 | page index << 10 | i, so that no word of a decayed page (all zero, all ones) can be
 *   mistaken for one, and a damaged page can say which words are intact even when its header is not.
 * Configuration (64 bytes): w0 w1 "RETCFG01", w2 version (1), w3 reset path, w4 countdown in seconds (1 to 60), w5 page count (3),
 * w6 to w11 the three page addresses (64-bit each), w12 to w14 zero, w15 CRC-32 of w0 to w14.
 *
 * Loads: the stack, the arguments, the memory map and the preload table in place; every word of the previous pages through
 * ops.load32 (4096 loads at most per call, and three pages read are 3072); the configuration file in place; the written pages after
 * the verification's cache maintenance. Stores: the payload's own stack and exactly the three pages.
 *
 * Returns: 0 done (PHASE 1 only, or PHASE 2 with no reset requested), 1 bad arguments, 2 not at EL2, 3 memory map refused, 4 configuration
 * refused, 5 a page refused, 6 a written page did not verify, 7 the reset is not implemented, 8 the reset call returned, 9 the counter does
 * not advance, 10 the boot counter would overflow, 11 CTR_EL0 gives no usable line size. */
#define PL_PAGE_PREFIX "PAYLOAD RETPROBE "
#ifndef PL_PAGE_LINES
#define PL_PAGE_LINES 40u
#endif
#include "payload-page.h"
#include "payload-mmu.h"
#include "preload.h"

#ifdef Q1N1_PAYLOAD_HOST_TEST
/* The host test replaces what a build machine cannot run: MRS, SMC, the second translation instruction and cache maintenance. */
uint64_t pl_host_sysreg(const char *name);
void pl_host_smc(uint64_t regs[4]);
uint64_t pl_host_at_s1e2w(uint64_t va);
void pl_host_cache(const char *operation, uint64_t address);
#define SYSREG(name) pl_host_sysreg(#name)
#else
#define SYSREG(name) ({ uint64_t value_; __asm__ volatile("mrs %0, " #name : "=r"(value_)); value_; })
#endif

#define OUT_OF_LINE static __attribute__((noinline))

#define PAGES 3u
#define PAGE_WORDS 1024u
#define HEADER_WORDS 32u
#define BODY_WORDS (PAGE_WORDS - HEADER_WORDS)
#define CRC_WORD 31u
#define MAGIC_LO 0x43544552u            /* "RETC", the first half of both magics */
#define PAGE_MAGIC_HI 0x31304e41u       /* "AN01" */
#define CONFIG_MAGIC_HI 0x31304746u     /* "FG01" */
#define LAYOUT_VERSION 1u
#define CONFIG_BYTES 64u
#define CONFIG_WORDS 16u
#define COUNTER_MAX 0xfffffu            /* the body word keeps the counter in bits 31:12 */
#define MIN_BODY_MATCHES 16u
#define COUNTDOWN_MAX_S 60u
#define COUNTER_HZ_MIN 1000000u
#define COUNTER_HZ_MAX 1000000000u
#define STUCK_READS 1000000u
#define ESSENTIAL_LINES 8u

#define FUNCTION_PSCI_FEATURES 0x8400000Au
#define FUNCTION_SYSTEM_RESET 0x84000009u
#define FUNCTION_SYSTEM_RESET2 0xC4000012u
#define RESET_TYPE_ARCH_WARM 0u
#define COOKIE_UNUSED 0u
/* What a helper returns when it was asked for something it may not issue: no SMC was made. "NOT_ISSE" in ASCII. */
#define NOT_ISSUED UINT64_C(0x4e4f545f49535345)

enum { PATH_NONE = 0, PATH_PSCI_RESET = 1, PATH_PSCI_RESET2 = 2, PATH_COUNT = 3 };
enum { STATE_NONE = 0, STATE_PARTIAL = 1, STATE_WHOLE = 2, STATE_UNREADABLE = 3 };
enum {
    RET_OK = 0, RET_NOT_EL2 = 2, RET_MAP = 3, RET_CONFIG = 4, RET_PAGE = 5, RET_VERIFY = 6, RET_NOT_IMPLEMENTED = 7,
    RET_RETURNED = 8, RET_COUNTER = 9, RET_OVERFLOW = 10, RET_CACHE = 11,
};
enum { CONFIG_NONE, CONFIG_FOUND, CONFIG_TWO, CONFIG_NO_TABLE };
enum {
    CFG_OK, CFG_BAD_CRC, CFG_BAD_VERSION, CFG_BAD_PATH, CFG_BAD_COUNTDOWN, CFG_BAD_PAGE_COUNT, CFG_RESERVED, CFG_PAGE_UNALIGNED,
    CFG_PAGE_RANGE, CFG_PAGES_NOT_DISTINCT,
};
enum {
    PAGE_OK, PAGE_NOT_IN_MAP, PAGE_OVERLAPS_OTHER, PAGE_PROTECTED, PAGE_NOT_MAPPED, PAGE_NOT_WRITABLE, PAGE_NOT_WRITE_BACK,
    PAGE_NOT_IDENTITY, PAGE_READ_WRITE_DIFFER,
};

/* Arrays of characters, not of pointers: an absolute pointer table would depend on the load address. */
static const char path_name[PATH_COUNT][13] = {"NONE", "PSCI_RESET", "PSCI_RESET2"};
static const char state_name[4][11] = {"NONE", "PARTIAL", "WHOLE", "UNREADABLE"};
static const char config_reason[10][20] = {"OK", "BAD_CRC", "BAD_VERSION", "BAD_PATH", "BAD_COUNTDOWN", "BAD_PAGE_COUNT",
                                          "RESERVED_NOT_ZERO", "PAGE_UNALIGNED", "PAGE_RANGE", "PAGES_NOT_DISTINCT"};
static const char page_reason[9][20] = {"OK", "NOT_IN_MAP", "OVERLAPS_OTHER", "PROTECTED", "NOT_MAPPED", "NOT_WRITABLE", "NOT_WRITE_BACK",
                                        "NOT_IDENTITY", "READ_WRITE_DIFFER"};
static const char error_name[9][19] = {"NOT_SUPPORTED", "INVALID_PARAMETERS", "DENIED", "ALREADY_ON", "ON_PENDING",
                                       "INTERNAL_FAILURE", "NOT_PRESENT", "DISABLED", "INVALID_ADDRESS"};
/* The two functions PSCI_FEATURES is asked about; only ever the argument of that query. */
static const uint32_t feature_asked[2] = {FUNCTION_SYSTEM_RESET, FUNCTION_SYSTEM_RESET2};

struct extent {
    uint64_t start, bytes;
    uint32_t type;
};
struct config {
    uint32_t path, countdown;
    uint64_t page[PAGES];
};
struct previous {
    unsigned state;
    uint32_t counter, bad_words, crc_ok, load_error, load_word;
};
struct stamp {
    uint32_t counter, previous_counter, frequency, feature_reset, feature_reset2, path_requested, path_used;
    uint32_t previous_state[PAGES];
    uint64_t timestamp;
};

/* ---- The only SMCs. Each helper holds one function id and nothing else can be put in x0. ------------------------------------- */

OUT_OF_LINE uint64_t smc_features(unsigned which)
{
    if (which >= 2u) return NOT_ISSUED;
#ifdef Q1N1_PAYLOAD_HOST_TEST
    uint64_t regs[4] = {FUNCTION_PSCI_FEATURES, feature_asked[which], 0, 0};
    pl_host_smc(regs);
    return regs[0];
#else
    register uint64_t x0 __asm__("x0") = FUNCTION_PSCI_FEATURES;
    register uint64_t x1 __asm__("x1") = feature_asked[which];
    register uint64_t x2 __asm__("x2") = 0;
    register uint64_t x3 __asm__("x3") = 0;
    __asm__ volatile("smc #0" : "+r"(x0), "+r"(x1), "+r"(x2), "+r"(x3)
                     :
                     : "x4", "x5", "x6", "x7", "x8", "x9", "x10", "x11", "x12", "x13", "x14", "x15", "x16", "x17", "memory");
    return x0;
#endif
}

/* SYSTEM_RESET: no argument, does not return when it works. */
OUT_OF_LINE uint64_t smc_system_reset(void)
{
#ifdef Q1N1_PAYLOAD_HOST_TEST
    uint64_t regs[4] = {FUNCTION_SYSTEM_RESET, 0, 0, 0};
    pl_host_smc(regs);
    return regs[0];
#else
    register uint64_t x0 __asm__("x0") = FUNCTION_SYSTEM_RESET;
    register uint64_t x1 __asm__("x1") = 0;
    register uint64_t x2 __asm__("x2") = 0;
    register uint64_t x3 __asm__("x3") = 0;
    __asm__ volatile("smc #0" : "+r"(x0), "+r"(x1), "+r"(x2), "+r"(x3)
                     :
                     : "x4", "x5", "x6", "x7", "x8", "x9", "x10", "x11", "x12", "x13", "x14", "x15", "x16", "x17", "memory");
    return x0;
#endif
}

/* SYSTEM_RESET2 (SMC64): x1 is the reset type, the architectural warm reset, and x2 the cookie, which that type ignores. */
OUT_OF_LINE uint64_t smc_system_reset2(void)
{
#ifdef Q1N1_PAYLOAD_HOST_TEST
    uint64_t regs[4] = {FUNCTION_SYSTEM_RESET2, RESET_TYPE_ARCH_WARM, COOKIE_UNUSED, 0};
    pl_host_smc(regs);
    return regs[0];
#else
    register uint64_t x0 __asm__("x0") = FUNCTION_SYSTEM_RESET2;
    register uint64_t x1 __asm__("x1") = RESET_TYPE_ARCH_WARM;
    register uint64_t x2 __asm__("x2") = COOKIE_UNUSED;
    register uint64_t x3 __asm__("x3") = 0;
    __asm__ volatile("smc #0" : "+r"(x0), "+r"(x1), "+r"(x2), "+r"(x3)
                     :
                     : "x4", "x5", "x6", "x7", "x8", "x9", "x10", "x11", "x12", "x13", "x14", "x15", "x16", "x17", "memory");
    return x0;
#endif
}

/* ---- Translation, cache maintenance and barriers: one helper per instruction kind ---------------------------------------------- */

/* AT S1E2W, then the ISB that must precede the read of PAR_EL1 (payload-mmu.h says why). It makes no access at the address. */
OUT_OF_LINE uint64_t at_s1e2w(uint64_t va)
{
#ifdef Q1N1_PAYLOAD_HOST_TEST
    return pl_host_at_s1e2w(va);
#else
    uint64_t par;
    __asm__ volatile("at s1e2w, %1\n\tisb\n\tmrs %0, par_el1" : "=r"(par) : "r"(va) : "memory");
    return par;
#endif
}

OUT_OF_LINE void dc_cvac(uint64_t address)
{
#ifdef Q1N1_PAYLOAD_HOST_TEST
    pl_host_cache("cvac", address);
#else
    __asm__ volatile("dc cvac, %0" : : "r"(address) : "memory");
#endif
}

OUT_OF_LINE void dc_civac(uint64_t address)
{
#ifdef Q1N1_PAYLOAD_HOST_TEST
    pl_host_cache("civac", address);
#else
    __asm__ volatile("dc civac, %0" : : "r"(address) : "memory");
#endif
}

OUT_OF_LINE void dsb_sy(void)
{
#ifdef Q1N1_PAYLOAD_HOST_TEST
    pl_host_cache("dsb", 0);
#else
    __asm__ volatile("dsb sy" : : : "memory");
#endif
}

/* ---- CRC-32 and the page pattern -------------------------------------------------------------------------------------------- */

/* One 32-bit little-endian word of a reflected CRC-32 (polynomial 0xEDB88320): the word goes into the register and 32 steps
 * follow, which is the same as four bytes one after the other. */
OUT_OF_LINE uint32_t crc32_word(uint32_t crc, uint32_t word)
{
    crc ^= word;
    for (unsigned i = 0; i < 32u; i++) crc = (crc >> 1) ^ (UINT32_C(0xEDB88320) & (UINT32_C(0) - (crc & 1u)));
    return crc;
}

static inline uint32_t body_word(uint32_t counter, uint32_t slot, uint32_t i)
{
    return counter << 12 | slot << 10 | i;
}

/* The CRC of a page as stored: the header's CRC word counts as zero. */
OUT_OF_LINE uint32_t page_crc(const volatile uint32_t *words)
{
    uint32_t crc = ~UINT32_C(0);
    for (unsigned i = 0; i < PAGE_WORDS; i++) crc = crc32_word(crc, i == CRC_WORD ? 0u : words[i]);
    return ~crc;
}

/* The CRC of the page the header and the pattern describe, before the page exists in memory. */
OUT_OF_LINE uint32_t new_page_crc(const uint32_t *header, uint32_t counter, uint32_t slot)
{
    uint32_t crc = ~UINT32_C(0);
    for (unsigned i = 0; i < HEADER_WORDS; i++) crc = crc32_word(crc, i == CRC_WORD ? 0u : header[i]);
    for (unsigned i = 0; i < BODY_WORDS; i++) crc = crc32_word(crc, body_word(counter, slot, i));
    return ~crc;
}

/* The state a page of words is in, as the three readers of it (this one, the Shell's dump on the Mac, the host tool) are specified to
 * decide it. WHOLE needs the header to name this very page (magic, version, index, address, a counter in range), a CRC that holds and
 * a body without one wrong word. A header that does not name this page leaves the body to speak. Of the words whose low ten bits equal
 * their own index, the epoch (counter and index: the bits above) that most of them agree on is found, ties to the smallest epoch, and
 * at least MIN_BODY_MATCHES words of exactly that epoch and index make the page PARTIAL. Anything less is NONE: an all-zero page, an
 * all-ones page and noise land here. */
OUT_OF_LINE void classify(const uint32_t *page, uint32_t slot, uint64_t address, struct previous *r)
{
    uint32_t counter = page[6], bad = 0;
    r->crc_ok = page_crc(page) == page[CRC_WORD];
    r->counter = 0;
    r->bad_words = 0;
    if (page[0] == MAGIC_LO && page[1] == PAGE_MAGIC_HI && page[2] == LAYOUT_VERSION && page[3] == slot &&
        page[4] == (uint32_t)address && page[5] == (uint32_t)(address >> 32) && counter >= 1u && counter <= COUNTER_MAX) {
        for (unsigned i = 0; i < BODY_WORDS; i++) bad += page[HEADER_WORDS + i] != body_word(counter, slot, i);
        r->bad_words = bad;
        r->counter = counter;
        r->state = r->crc_ok && !bad ? STATE_WHOLE : STATE_PARTIAL;
        return;
    }
    uint32_t epoch = 0, agreed = 0, matches = 0;
    for (unsigned i = 0; i < BODY_WORDS; i++) {
        uint32_t key = page[HEADER_WORDS + i] >> 10, same = 0;
        if ((page[HEADER_WORDS + i] & 0x3ffu) != i) continue;
        for (unsigned j = 0; j < BODY_WORDS; j++) same += (page[HEADER_WORDS + j] & 0x3ffu) == j && page[HEADER_WORDS + j] >> 10 == key;
        if (same > agreed || (same == agreed && key < epoch)) {
            agreed = same;
            epoch = key;
        }
    }
    for (unsigned i = 0; i < BODY_WORDS; i++) matches += page[HEADER_WORDS + i] == (epoch << 10 | i);
    r->bad_words = BODY_WORDS - matches;
    r->state = matches >= MIN_BODY_MATCHES ? STATE_PARTIAL : STATE_NONE;
}

/* Reads one page through the guarded load (the memory may never have been written since power-on: an abort must not take the board)
 * and classifies it. `page` is a buffer on the payload's stack, which is where load32 may store. */
OUT_OF_LINE void read_previous(const struct q1n1_payload_args *a, uint64_t address, uint32_t slot, uint32_t *page, struct previous *r)
{
    pl_zero(r, sizeof *r);
    for (unsigned i = 0; i < PAGE_WORDS; i++) {
        int32_t error = a->ops.load32(address + 4u * i, &page[i]);
        if (error) {
            r->state = STATE_UNREADABLE;
            r->load_error = (uint32_t)error;
            r->load_word = i;
            return;
        }
    }
    classify(page, slot, address, r);
}

/* ---- Printing ---------------------------------------------------------------------------------------------------------------- */

OUT_OF_LINE void add_text(const struct q1n1_payload_args *a, struct pl_page *p, const char *key, const char *text)
{
    struct pl_line item;
    pl_begin(&item);
    pl_text(&item, key);
    pl_text(&item, "=");
    pl_text(&item, text);
    pl_page_add(a, p, item.buf);
}

/* A PSCI answer: KEY=RAW and the name of an error code, IMPLEMENTED for a non-negative 32-bit result, NEGATIVE for any other. */
OUT_OF_LINE void add_answer(const struct q1n1_payload_args *a, struct pl_page *p, const char *key, uint64_t x0, int wide)
{
    struct pl_line item;
    uint64_t negated = wide ? UINT64_C(0) - x0 : (uint32_t)(UINT32_C(0) - (uint32_t)x0);
    pl_begin(&item);
    pl_text(&item, key);
    pl_text(&item, "=");
    pl_hex(a, &item, x0);
    if (negated - 1u < 9u) {
        pl_text(&item, ":");
        pl_text(&item, error_name[negated - 1u]);
        pl_text(&item, "(-");
        pl_dec(&item, negated);
        pl_text(&item, ")");
    } else {
        pl_text(&item, (int32_t)(uint32_t)x0 >= 0 ? ":IMPLEMENTED" : ":NEGATIVE");
    }
    pl_page_add(a, p, item.buf);
}

OUT_OF_LINE void add_walk(const struct q1n1_payload_args *a, struct pl_page *p, const char *key, const struct pl_walk *w)
{
    struct pl_line item;
    pl_begin(&item);
    pl_text(&item, key);
    pl_text(&item, "=");
    pl_put_walk(a, &item, w);
    pl_page_add(a, p, item.buf);
}

/* ---- The configuration ---------------------------------------------------------------------------------------------------------- */

/* The one data file of exactly CONFIG_BYTES that starts with the magic, found in the preload table the runner built (it is the entry
 * of the manifest after the payload; this payload's own entry is skipped by its base). The table is checked before it is read. */
OUT_OF_LINE unsigned find_config(const struct q1n1_payload_args *a, uint64_t *base)
{
    const struct q1n1_preload_cache *t = (const struct q1n1_preload_cache *)(uintptr_t)a->preload_table;
    unsigned found = 0;
    if (!a->preload_table || (a->preload_table & 7u) || a->preload_table >= PL_ADDRESS_LIMIT || a->preload_size < 32u ||
        a->preload_size > PL_ADDRESS_LIMIT - a->preload_table)
        return CONFIG_NO_TABLE;
    if (t->magic != Q1N1_CACHE_MAGIC || t->version != 1 || t->entry_size != sizeof(struct q1n1_cached_file)) return CONFIG_NO_TABLE;
    if (t->count > Q1N1_PRELOAD_MAX || 32u + t->count * sizeof(struct q1n1_cached_file) > a->preload_size) return CONFIG_NO_TABLE;
    for (uint64_t i = 0; i < t->count; i++) {
        const struct q1n1_cached_file *e = &t->files[i];
        const volatile uint32_t *w = (const volatile uint32_t *)(uintptr_t)e->base;
        if (e->base == a->payload_base || e->file.size != CONFIG_BYTES || !e->base || (e->base & 7u) || e->base >= PL_ADDRESS_LIMIT ||
            e->base > PL_ADDRESS_LIMIT - CONFIG_BYTES)
            continue;
        if (w[0] != MAGIC_LO || w[1] != CONFIG_MAGIC_HI) continue;
        if (found++) return CONFIG_TWO;
        *base = e->base;
    }
    return found ? CONFIG_FOUND : CONFIG_NONE;
}

/* CFG_OK and the parsed configuration, or the first reason it is refused. The CRC comes first: with a bad CRC no field is believed. */
OUT_OF_LINE unsigned config_parse(uint64_t base, struct config *c)
{
    const volatile uint32_t *w = (const volatile uint32_t *)(uintptr_t)base;
    uint32_t v[CONFIG_WORDS], crc = ~UINT32_C(0);
    for (unsigned i = 0; i < CONFIG_WORDS; i++) v[i] = w[i];
    for (unsigned i = 0; i < CONFIG_WORDS - 1u; i++) crc = crc32_word(crc, v[i]);
    if (~crc != v[CONFIG_WORDS - 1u]) return CFG_BAD_CRC;
    if (v[2] != LAYOUT_VERSION) return CFG_BAD_VERSION;
    if (v[3] >= PATH_COUNT) return CFG_BAD_PATH;
    if (v[4] < 1u || v[4] > COUNTDOWN_MAX_S) return CFG_BAD_COUNTDOWN;
    if (v[5] != PAGES) return CFG_BAD_PAGE_COUNT;
    if (v[12] | v[13] | v[14]) return CFG_RESERVED;
    c->path = v[3];
    c->countdown = v[4];
    for (unsigned k = 0; k < PAGES; k++) {
        c->page[k] = (uint64_t)v[6 + 2u * k + 1u] << 32 | v[6 + 2u * k];
        if (c->page[k] & (PL_PAGE_BYTES - 1u)) return CFG_PAGE_UNALIGNED;
        if (!c->page[k] || c->page[k] > PL_ADDRESS_LIMIT - PL_PAGE_BYTES) return CFG_PAGE_RANGE;
    }
    if (c->page[0] == c->page[1] || c->page[0] == c->page[2] || c->page[1] == c->page[2]) return CFG_PAGES_NOT_DISTINCT;
    return CFG_OK;
}

/* ---- The pages -------------------------------------------------------------------------------------------------------------- */

static inline int overlaps(uint64_t start, uint64_t bytes, uint64_t other, uint64_t other_bytes)
{
    return other_bytes && start < other + other_bytes && other < start + bytes;
}

/* PAGE_OK, the descriptor that holds the page and how EL2's stage 1 maps it; or why not. Reads the map and asks the MMU; stores nothing. */
OUT_OF_LINE unsigned page_check(const struct q1n1_payload_args *a, uint64_t address, struct extent *x, struct pl_walk *w)
{
    struct pl_desc d;
    struct pl_walk written;
    uint64_t count = a->map_size / a->map_stride;
    unsigned inside = 0;
    for (uint64_t i = 0; i < count; i++) {
        if (!pl_desc_read(a, i, &d) || !overlaps(address, PL_PAGE_BYTES, d.start, d.end - d.start)) continue;
        if (d.type != PL_EFI_CONVENTIONAL || d.start > address || d.end < address + PL_PAGE_BYTES) return PAGE_OVERLAPS_OTHER;
        x->start = d.start;
        x->bytes = d.end - d.start;
        x->type = d.type;
        inside = 1;
    }
    if (!inside) return PAGE_NOT_IN_MAP;
    if (overlaps(address, PL_PAGE_BYTES, a->payload_base, a->payload_size) || overlaps(address, PL_PAGE_BYTES, a->stack_base, a->stack_size) ||
        overlaps(address, PL_PAGE_BYTES, a->preload_table, a->preload_size) || overlaps(address, PL_PAGE_BYTES, a->map_base, a->map_size))
        return PAGE_PROTECTED;
    pl_walk_page(address, w);
    pl_walk_decode(at_s1e2w(address), address, &written);
    if (!w->mapped) return PAGE_NOT_MAPPED;
    if (!written.mapped) return PAGE_NOT_WRITABLE;
    if (w->pa != written.pa || w->attr != written.attr || w->sh != written.sh) return PAGE_READ_WRITE_DIFFER;
    if (pl_attr_class(w->attr) != PL_ATTR_WB) return PAGE_NOT_WRITE_BACK;
    if (!w->ident) return PAGE_NOT_IDENTITY;
    return PAGE_OK;
}

/* The header on the stack: every word of it but the CRC. */
OUT_OF_LINE void header_build(uint32_t *header, uint32_t slot, uint64_t address, const struct stamp *s, const struct extent *x)
{
    pl_zero(header, HEADER_WORDS * 4u);
    header[0] = MAGIC_LO;
    header[1] = PAGE_MAGIC_HI;
    header[2] = LAYOUT_VERSION;
    header[3] = slot;
    header[4] = (uint32_t)address;
    header[5] = (uint32_t)(address >> 32);
    header[6] = s->counter;
    header[7] = s->previous_counter;
    header[8] = (uint32_t)s->timestamp;
    header[9] = (uint32_t)(s->timestamp >> 32);
    header[10] = s->frequency;
    header[11] = s->feature_reset;
    header[12] = s->feature_reset2;
    header[13] = s->path_requested | s->path_used << 8 | s->previous_state[0] << 16 | s->previous_state[1] << 24;
    header[14] = s->previous_state[2] | 1u << 8;
    header[15] = x->type;
    header[16] = (uint32_t)x->start;
    header[17] = (uint32_t)(x->start >> 32);
    header[18] = (uint32_t)x->bytes;
    header[19] = (uint32_t)(x->bytes >> 32);
}

/* The page's stores, in memory order. They are the only stores to memory outside the payload's stack. */
OUT_OF_LINE void page_store(uint64_t address, const uint32_t *header, uint32_t counter, uint32_t slot)
{
    volatile uint32_t *p = (volatile uint32_t *)(uintptr_t)address;
    for (unsigned i = 0; i < HEADER_WORDS; i++) p[i] = header[i];
    for (unsigned i = 0; i < BODY_WORDS; i++) p[HEADER_WORDS + i] = body_word(counter, slot, i);
}

/* The lines of every page are cleaned to the point of coherency and then fenced: a reset takes the caches with it, so a line that is
 * only dirty is gone. Whether the point of coherency is DRAM or a system cache in front of it is UNKNOWN (the design document). */
OUT_OF_LINE void clean_pages(const uint64_t *pages, uint32_t line)
{
    for (unsigned k = 0; k < PAGES; k++)
        for (uint32_t offset = 0; offset < PL_PAGE_BYTES; offset += line) dc_cvac(pages[k] + offset);
    dsb_sy();
}

/* Cleans and invalidates every line, fences, and recomputes the CRC of each page from memory: the check that a store reached the point
 * of coherency and that what is read back is the page that was meant. */
OUT_OF_LINE unsigned verify_pages(const uint64_t *pages, const uint32_t *crc, uint32_t line)
{
    unsigned bad = 0;
    for (unsigned k = 0; k < PAGES; k++)
        for (uint32_t offset = 0; offset < PL_PAGE_BYTES; offset += line) dc_civac(pages[k] + offset);
    dsb_sy();
    for (unsigned k = 0; k < PAGES; k++) {
        const volatile uint32_t *p = (const volatile uint32_t *)(uintptr_t)pages[k];
        bad += page_crc(p) != crc[k] || p[CRC_WORD] != crc[k];
    }
    return bad;
}

/* ---- The wait and the reset ---------------------------------------------------------------------------------------------------- */

/* 1 when `seconds` of the counter went by, 0 when the counter does not advance, runs backwards (the unsigned `now - start` would wrap
 * and read as a long wait) or CNTFRQ_EL0 is not a plausible frequency: a reset that was announced for a time that cannot be measured is
 * not made. */
OUT_OF_LINE int wait_seconds(const struct q1n1_payload_args *a, uint32_t seconds)
{
    uint64_t frequency = SYSREG(cntfrq_el0) & 0xffffffffu, start = a->ops.counter(), last = start, now;
    uint32_t stuck = 0;
    if (frequency < COUNTER_HZ_MIN || frequency > COUNTER_HZ_MAX) return 0;
    for (;;) {
        now = a->ops.counter();
        if (now < start) return 0;
        if (now - start >= frequency * seconds) return 1;
        if (now == last) {
            if (++stuck >= STUCK_READS) return 0;
        } else {
            stuck = 0;
            last = now;
        }
    }
}

OUT_OF_LINE void refuse(const struct q1n1_payload_args *a, struct pl_page *p, const char *text)
{
    pl_say(a, p, "REFUSED", text, 1);
}

uint64_t payload_entry(const struct q1n1_payload_args *a);
uint64_t payload_entry(const struct q1n1_payload_args *a)
{
    struct pl_page p;
    struct config cfg;
    struct stamp stamp;
    struct extent extent[PAGES];
    struct previous previous[PAGES];
    struct pl_walk walk[PAGES];
    uint32_t header[HEADER_WORDS], crc[PAGES], page[PAGE_WORDS];
    uint64_t config_base = 0, answer[2];
    unsigned found, state, highest = 0;

    if (!pl_args_ok(a) || !a->ops.load32 || !a->ops.counter) return Q1N1_PAYLOAD_RET_BAD_ARGS;
    pl_page_init(&p, ESSENTIAL_LINES);
    if ((SYSREG(CurrentEL) >> 2 & 3) != 2) {
        pl_say(a, &p, "SKIPPED", "NOT_AT_EL2", 1);
        return RET_NOT_EL2;
    }

    /* The configuration is looked for and checked first, and what it says is only used after PHASE 1. */
    found = find_config(a, &config_base);
    pl_zero(&cfg, sizeof cfg);
    state = found == CONFIG_FOUND ? config_parse(config_base, &cfg) : CFG_OK;
    pl_page_open(&p, "CONFIG", 1);
    if (found == CONFIG_FOUND && state == CFG_OK) {
        pl_page_add(a, &p, "OK");
        add_text(a, &p, "PATH", path_name[cfg.path]);
        pl_add_dec(a, &p, "COUNTDOWN", cfg.countdown);
        pl_add_dec(a, &p, "PAGES", PAGES);
    } else if (found == CONFIG_FOUND) {
        add_text(a, &p, "REFUSED", config_reason[state]);
    } else {
        add_text(a, &p, "NONE", found == CONFIG_TWO ? "TWO_FILES" : found == CONFIG_NO_TABLE ? "NO_TABLE" : "NO_FILE");
    }
    pl_page_flush(a, &p);

    /* PHASE 1. */
    pl_say(a, &p, "NEXT", "FEATURES", 1);
    answer[0] = smc_features(0);
    answer[1] = smc_features(1);
    pl_page_open(&p, "FEATURES", 0);
    add_answer(a, &p, "SYSTEM_RESET", answer[0], 0);
    add_answer(a, &p, "SYSTEM_RESET2", answer[1], 0);
    pl_page_flush(a, &p);
    pl_page_open(&p, "WARM_TYPE", 0);
    pl_add_hex(a, &p, "ARCH", RESET_TYPE_ARCH_WARM);
    pl_page_add(a, &p, "QUERY=NONE");
    pl_page_add(a, &p, (int32_t)(uint32_t)answer[1] >= 0 ? "SYSTEM_RESET2=YES" : "SYSTEM_RESET2=NO");
    pl_page_flush(a, &p);
    if (found != CONFIG_FOUND || state != CFG_OK) {
        if (found == CONFIG_FOUND) {
            refuse(a, &p, "CONFIG");
            return RET_CONFIG;
        }
        pl_say(a, &p, "SKIPPED", "PHASE2=NO_CONFIG", 0);
        return RET_OK;
    }

    /* PHASE 2, checks only: nothing is stored until every one of them has passed. */
    state = pl_map_check(a);
    if (state != PL_MAP_OK) {
        refuse(a, &p, "MAP");
        return RET_MAP;
    }
    for (unsigned k = 0; k < PAGES; k++) {
        state = page_check(a, cfg.page[k], &extent[k], &walk[k]);
        if (state != PAGE_OK) {
            pl_page_open(&p, "REFUSED", 1);
            add_text(a, &p, "PAGE", page_reason[state]);
            pl_add_dec(a, &p, "INDEX", k);
            pl_add_hex(a, &p, "BASE", cfg.page[k]);
            pl_page_flush(a, &p);
            return RET_PAGE;
        }
        pl_page_open(&p, "PAGE", 0);
        pl_add_dec(a, &p, "INDEX", k);
        pl_add_hex(a, &p, "BASE", cfg.page[k]);
        pl_add_hex(a, &p, "EXTENT", extent[k].start);
        pl_add_hex(a, &p, "BYTES", extent[k].bytes);
        add_walk(a, &p, "MAP", &walk[k]);
        pl_page_flush(a, &p);
    }
    uint32_t cache_type = (uint32_t)SYSREG(ctr_el0);
    uint32_t line = 4u << (cache_type >> 16 & 15u);
    if ((cache_type >> 16 & 15u) < 2u || (cache_type >> 16 & 15u) > 9u) {
        refuse(a, &p, "CACHE_LINE_SIZE");
        return RET_CACHE;
    }
    if (cfg.path == PATH_PSCI_RESET && (int32_t)(uint32_t)answer[0] < 0) {
        refuse(a, &p, "RESET_NOT_IMPLEMENTED SYSTEM_RESET");
        return RET_NOT_IMPLEMENTED;
    }
    if (cfg.path == PATH_PSCI_RESET2 && (int32_t)(uint32_t)answer[1] < 0) {
        refuse(a, &p, "RESET_NOT_IMPLEMENTED SYSTEM_RESET2");
        return RET_NOT_IMPLEMENTED;
    }

    /* The previous boot's pages are read before anything is written, and the boot counter comes from what they say. */
    pl_say(a, &p, "NEXT", "READ PREVIOUS PAGES", 1);
    for (unsigned k = 0; k < PAGES; k++) {
        read_previous(a, cfg.page[k], k, page, &previous[k]);
        stamp.previous_state[k] = previous[k].state;
        pl_page_open(&p, "PREV", 0);
        pl_add_dec(a, &p, "INDEX", k);
        pl_page_add(a, &p, state_name[previous[k].state]);
        if (previous[k].state == STATE_WHOLE) {
            pl_add_dec(a, &p, "COUNTER", previous[k].counter);
            if (previous[k].counter > highest) highest = previous[k].counter;
        } else if (previous[k].state == STATE_UNREADABLE) {
            pl_add_dec(a, &p, "LOAD_ERROR", previous[k].load_error);
            pl_add_dec(a, &p, "WORD", previous[k].load_word);
        } else if (previous[k].state == STATE_PARTIAL) {
            pl_add_dec(a, &p, "BAD_WORDS", previous[k].bad_words);
            pl_page_add(a, &p, previous[k].crc_ok ? "CRC=OK" : "CRC=BAD");
        }
        pl_page_flush(a, &p);
    }
    if (highest >= COUNTER_MAX) {
        refuse(a, &p, "COUNTER_OVERFLOW");
        return RET_OVERFLOW;
    }
    pl_page_open(&p, "COUNTER", 0);
    pl_add_dec(a, &p, "THIS", highest + 1u);
    pl_add_dec(a, &p, "PREVIOUS", highest);
    pl_page_flush(a, &p);

    /* The stores. */
    pl_say(a, &p, "NEXT", "WRITE PAGES", 1);
    stamp.counter = highest + 1u;
    stamp.previous_counter = highest;
    stamp.frequency = (uint32_t)SYSREG(cntfrq_el0);
    stamp.feature_reset = (uint32_t)answer[0];
    stamp.feature_reset2 = (uint32_t)answer[1];
    stamp.path_requested = cfg.path;
    stamp.path_used = cfg.path;
    stamp.timestamp = a->ops.counter();
    for (unsigned k = 0; k < PAGES; k++) {
        header_build(header, k, cfg.page[k], &stamp, &extent[k]);
        crc[k] = new_page_crc(header, stamp.counter, k);
        header[CRC_WORD] = crc[k];
        page_store(cfg.page[k], header, stamp.counter, k);
    }
    pl_page_open(&p, "WROTE", 0);
    for (unsigned k = 0; k < PAGES; k++) {
        pl_add_dec(a, &p, "PAGE", k);
        pl_add_hex(a, &p, "CRC", crc[k]);
    }
    pl_page_flush(a, &p);
    clean_pages(cfg.page, line);
    pl_page_open(&p, "CLEAN", 0);
    pl_page_add(a, &p, "DC_CVAC_DSB");
    pl_add_dec(a, &p, "LINE", line);
    pl_add_dec(a, &p, "LINES", PAGES * (PL_PAGE_BYTES / line));
    pl_page_flush(a, &p);
    state = verify_pages(cfg.page, crc, line);
    if (state) {
        pl_page_open(&p, "VERIFY", 1);
        pl_page_add(a, &p, "FAILED");
        pl_add_dec(a, &p, "PAGES", state);
        pl_page_flush(a, &p);
        return RET_VERIFY;
    }
    pl_say(a, &p, "VERIFY", "OK", 0);

    /* The reset the configuration names, if any: announced, waited for, and called once. */
    pl_page_open(&p, "PATH", 0);
    add_text(a, &p, "REQUESTED", path_name[cfg.path]);
    add_text(a, &p, "USED", path_name[stamp.path_used]);
    pl_page_flush(a, &p);
    if (cfg.path == PATH_NONE) {
        pl_say(a, &p, "RESET", "NONE CANARIES STAY FOR A MANUAL RESET", 1);
        return RET_OK;
    }
    /* The line the stages before the writes printed, with the configured number: "NEXT RESET AFTER 8 S". */
    struct pl_line seconds;
    pl_begin(&seconds);
    pl_dec(&seconds, cfg.countdown);
    pl_page_open(&p, "NEXT", 1);
    pl_page_add(a, &p, "RESET AFTER");
    pl_page_add(a, &p, seconds.buf);
    pl_page_add(a, &p, "S");
    pl_page_flush(a, &p);
    if (!wait_seconds(a, cfg.countdown)) {
        refuse(a, &p, "COUNTER_NOT_ADVANCING");
        return RET_COUNTER;
    }
    if (cfg.path == PATH_PSCI_RESET) {
        pl_say(a, &p, "RESET", "CALL SYSTEM_RESET", 1);
        answer[0] = smc_system_reset();
        pl_page_open(&p, "RESET", 1);
        add_answer(a, &p, "RETURNED", answer[0], 0);
    } else {
        pl_say(a, &p, "RESET", "CALL SYSTEM_RESET2 TYPE=ARCH_WARM", 1);
        answer[0] = smc_system_reset2();
        pl_page_open(&p, "RESET", 1);
        add_answer(a, &p, "RETURNED", answer[0], 1);
    }
    pl_page_flush(a, &p);
    return RET_RETURNED;
}
