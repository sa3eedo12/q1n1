/* SPDX-License-Identifier: MIT */
/* The runner's EL2 half (sp11-payload.h): for each payload of the chain in manifest order, verify it where
 * it now is, make it executable, call it, and offer it the four ops of the payload ABI
 * (sp11-payload-abi.h). Everything the hardware does goes through q1n1_payload_env, so the native tests
 * run this against a fake platform.
 *
 * The payload gets exactly what the ABI says and the ops are the only way it calls q1n1: puts, hex,
 * load32 and counter. They are not a sandbox: hex writes into the buffer the payload names and puts reads
 * the string it names. load32 reads through the platform's guarded copy and refuses every request whose
 * destination is not the payload's own stack, so it cannot be turned into a store to a device register
 * either; in a runner built with the opt-in write-table gate hex and puts refuse a pointer outside the
 * stack (outside the stack and the payload's image, for puts) in the same way, and say so on the page.
 * That does not sandbox the payload (it is code at EL2): it keeps the ops
 * honest, and the review of the payload and its pinned SHA-256 carry the rest. The same goes for the chain:
 * the hash taken again before each call catches a payload that was damaged (by an earlier payload that
 * scribbled on it, or by memory the bounce did not preserve), not one that was written to lie. */
#include "sp11-payload.h"
#include "sha256.h"
#if Q1N1_SP11_SMMUMAP
#include "sp11-smmumap.h"
#endif
#if Q1N1_SP11_WTAB
#include "sp11-payload-wtab.h"
#endif

#if Q1N1_SP11_PAYLOAD

/* One payload runs at a time, so the ops (plain function pointers with no context argument, because the
 * payload is a separate binary) find their platform here. The counters are the budgets of the call in
 * progress and start again for the next payload. */
static struct {
    const struct q1n1_payload_env *env;
    uint64_t stack_base, stack_size;
    unsigned lines, dropped, loads, faults, refused;
#if Q1N1_SP11_WTAB
    uint64_t image_base, image_size;        /* the payload's own image: where ops.puts may also read a string */
    unsigned op_lines;                      /* which ops have printed their first refusal line (bit 0 hex, bit 1 puts) */
#endif
} session;

/* The physical address space the unit's tables can map: 48 bits. A load beyond it is a translation
 * fault at best, so it is refused before it is tried. */
#define ADDRESS_LIMIT (UINT64_C(1) << 48)

int q1n1_payload_load32_check(uint64_t addr, const uint32_t *out, uint64_t stack_base, uint64_t stack_size,
                              unsigned loads_done)
{
    uint64_t where = (uint64_t)(uintptr_t)out;
    if (!out) return Q1N1_PAYLOAD_LOAD_E_PARAM;
    if ((addr & 3) || (where & 3)) return Q1N1_PAYLOAD_LOAD_E_ALIGN;
    if (addr > ADDRESS_LIMIT - 4) return Q1N1_PAYLOAD_LOAD_E_RANGE;
    /* The guarded copy stores to `out`. Anywhere but the payload's own stack that would be a store a
     * payload chose, so the whole word must be inside the stack. */
    if (stack_size < 4 || where < stack_base || where - stack_base > stack_size - 4) return Q1N1_PAYLOAD_LOAD_E_OUT;
    if (loads_done >= Q1N1_PAYLOAD_LOADS_MAX) return Q1N1_PAYLOAD_LOAD_E_BUDGET;
    return Q1N1_PAYLOAD_LOAD_OK;
}

#if Q1N1_SP11_WTAB
/* An op that acts on a pointer of the payload was given one outside what the table's run allows (the stack for hex; the stack and the payload's image for puts). Nothing was
 * read or written. The refusal is counted (REFUSED in the DONE line, which is never dropped) and the first one of each op is a line of the page, inside the payload's line budget:
 * a payload that tries again does not flood the page, and a refusal is never silent. */
static void refuse_pointer_op(unsigned bit, const char *op, const void *where, uint64_t cap)
{
    struct q1n1_payload_line line;
    session.refused++;
    if (session.op_lines & bit) return;
    session.op_lines |= bit;
    if (Q1N1_PAYLOAD_LINES_MAX <= session.lines) {
        session.dropped++;
        return;
    }
    q1n1_payload_line_begin(&line, "PAYLOAD OP REFUSED");
    q1n1_payload_line_word(&line, op);
    q1n1_payload_line_hex(&line, "A", (uint64_t)(uintptr_t)where);
    if (cap) q1n1_payload_line_hex(&line, "CAP", cap);
    session.lines++;
    session.env->emit(line.buf);
}
#endif

static void op_puts(const char *line)
{
    char text[Q1N1_PAYLOAD_LINE_MAX + 1];
    unsigned n = 0;
    if (!line) return;
#if Q1N1_SP11_WTAB
    if (!q1n1_wtab_puts_ok(line, session.stack_base, session.stack_size, session.image_base, session.image_size)) {
        refuse_pointer_op(2u, "PUTS", line, 0);
        return;
    }
#endif
    while (line[n] && n < Q1N1_PAYLOAD_LINE_MAX) {
        text[n] = line[n];
        n++;
    }
    text[n] = 0;
    q1n1_payload_sanitize(text);
    if (session.lines >= Q1N1_PAYLOAD_LINES_MAX) {
        session.dropped++;
        return;
    }
    session.lines++;
    session.env->emit(text);
}

static uint32_t op_hex(char *dst, uint32_t cap, uint64_t value)
{
#if Q1N1_SP11_WTAB
    if (!q1n1_wtab_hex_ok(dst, cap, session.stack_base, session.stack_size)) {
        refuse_pointer_op(1u, "HEX", dst, cap);
        return 0;
    }
#endif
    return (uint32_t)q1n1_payload_fmt_hex(dst, cap, value);
}

static int32_t op_load32(uint64_t addr, uint32_t *out)
{
    int refusal = q1n1_payload_load32_check(addr, out, session.stack_base, session.stack_size, session.loads);
    if (refusal) {
        session.refused++;
        return refusal;
    }
    uint32_t value = 0;
#if Q1N1_SP11_WTAB
    /* A word in a window the table has not opened (or has closed: the run stopped, or was undone) is not read: the block behind it may be
     * unpowered or unclocked, and a read of that can hang the bus, which no guard recovers. */
    if (q1n1_wtab_load_check(addr)) {
        session.refused++;
        return Q1N1_WTAB_LOAD_E_GATED;
    }
#endif
    session.loads++;
    /* Only ever a load: COPY32 reads `addr` into the runner's own variable. The payload's word is
     * written by an ordinary store after the guarded read succeeded. */
    if (session.env->guarded(Q1N1_PAYLOAD_G_COPY32, (uint64_t)(uintptr_t)&value, addr, 4)) {
        session.faults++;
        return Q1N1_PAYLOAD_LOAD_E_FAULT;
    }
#if Q1N1_SP11_WTAB
    /* A read of a gated block that raised an error response ends the run: the table undoes what it switched on. */
    if (q1n1_wtab_load_done(addr)) {
        session.faults++;
        return Q1N1_WTAB_LOAD_E_GATED;
    }
#endif
    *out = value;
    return Q1N1_PAYLOAD_LOAD_OK;
}

static uint64_t op_counter(void)
{
    return session.env->counter();
}

int q1n1_payload_verify_in_place(const struct q1n1_payload_loaded *loaded, uint32_t index)
{
    if (!loaded->count || loaded->count > Q1N1_PAYLOAD_MAX_FILES || !loaded->table_base || index >= loaded->count)
        return 0;
    /* Only a payload is hashed here, and only a payload is ever called. */
    if (!q1n1_payload_file_is_code(&loaded->file[index])) return 0;
    const struct q1n1_preload_cache *table = (const void *)(uintptr_t)loaded->table_base;
    /* The table describes exactly what the runner loaded: a payload finds its files through it, so a
     * count or an entry that changed after the bounce is as much a refusal as a payload that did. Every
     * entry is compared, data files included, though only the payload's bytes are hashed. */
    if (table->count != loaded->count) return 0;
    for (uint32_t i = 0; i < loaded->count; i++) {
        const struct q1n1_cached_file *entry = &table->files[i];
        const struct q1n1_payload_file *own = &loaded->file[i];
        if (entry->base != own->base || entry->file.size != own->bytes || entry->allocation != own->alloc) return 0;
        uint8_t different = 0;
        for (unsigned k = 0; k < 32; k++) different |= (uint8_t)(entry->file.sha256[k] ^ own->sha256[k]);
        if (different) return 0;
    }
    /* Then the payload itself: hashed where it now is, against the digest in the table, which the loop
     * above has shown is the one measured before the bounce. */
    return q1n1_preload_verify(table, index);
}

/* Two words at the low end of the stack, written before every call and checked when the payload returns:
 * a payload that ran past its stack has overwritten them. */
#define GUARD_WORDS 2u
#define GUARD_PATTERN UINT64_C(0x5afe5afe5afe5afe)

static void emit_line(const struct q1n1_payload_env *env, const struct q1n1_payload_line *line)
{
    env->emit(line->buf);
}

static void emit_chain_stopped(const struct q1n1_payload_env *env, uint32_t index, const char *reason)
{
    struct q1n1_payload_line line;
    q1n1_payload_line_begin(&line, "PAYLOAD CHAIN STOPPED");
    q1n1_payload_line_dec(&line, "INDEX", index);
    q1n1_payload_line_raw(&line, " REASON=");
    q1n1_payload_line_raw(&line, reason);
    emit_line(env, &line);
}

#if Q1N1_SP11_SMMUMAP
/* A payload that does not verify where it now is: the lines and the status of the loop's own refusal, for one checked before the
 * step that writes a page table rather than before its call. */
static void refuse_hash(const struct q1n1_payload_env *env, const struct q1n1_payload_loaded *loaded, uint32_t index,
                        struct q1n1_payload_result *result)
{
    const struct q1n1_payload_file *file = &loaded->file[index];
    struct q1n1_payload_line line;
    uint8_t now[32];
    q1n1_sha256((const void *)(uintptr_t)file->base, (size_t)file->bytes, now);
    q1n1_payload_line_begin(&line, "PAYLOAD REFUSED=HASH_AT_EL2");
    q1n1_payload_line_dec(&line, "INDEX", index);
    q1n1_payload_line_digest(&line, "WANT", file->sha256);
    q1n1_payload_line_digest(&line, "HAVE", now);
    emit_line(env, &line);
    result->status = Q1N1_PAYLOAD_RUN_HASH;
    result->stopped = index;
    emit_chain_stopped(env, index, "HASH_AT_EL2");
}
#endif

int q1n1_payload_run(const struct q1n1_payload_env *env, const struct q1n1_payload_loaded *loaded,
                     const struct q1n1_payload_platform *platform, struct q1n1_payload_result *result)
{
    struct q1n1_payload_line line;
    uint8_t *clear = (uint8_t *)result;
    for (size_t i = 0; i < sizeof *result; i++) clear[i] = 0;
    result->status = Q1N1_PAYLOAD_RUN_OK;
    session.env = env;

    for (uint32_t i = 0; i < loaded->notes && i < Q1N1_PAYLOAD_NOTES; i++) env->emit(loaded->note[i]);
    unsigned code = 0;
    for (uint32_t i = 0; i < loaded->count && i < Q1N1_PAYLOAD_MAX_FILES; i++)
        code += q1n1_payload_file_is_code(&loaded->file[i]);
    if (!loaded->count || !loaded->stack_base || !code) {
        q1n1_payload_line_begin(&line, "PAYLOAD REFUSED=NO_PAYLOAD");
        emit_line(env, &line);
        result->status = Q1N1_PAYLOAD_RUN_NO_PAYLOAD;
        return result->status;
    }

    volatile uint64_t *guard = (volatile uint64_t *)(uintptr_t)loaded->stack_base;
#if Q1N1_SP11_SMMUMAP
    int smmumap_done = 0;
#endif
    for (uint32_t index = 0; index < loaded->count && index < Q1N1_PAYLOAD_MAX_FILES; index++) {
        const struct q1n1_payload_file *file = &loaded->file[index];
        struct q1n1_payload_call_result *done = &result->call[result->called];
        if (!q1n1_payload_file_is_code(file)) continue;     /* data is found through the table, never called */

        /* The second hash, here, where this payload now is, and again before every later one rather than
         * once for the chain: an earlier payload is code at EL2 and may have damaged it. The first hash was
         * taken before the bounce; memory the bounce did not preserve shows up as a difference too. A
         * payload that does not verify is not called and the chain ends here. */
        if (!q1n1_payload_verify_in_place(loaded, index)) {
            uint8_t now[32];
            q1n1_sha256((const void *)(uintptr_t)file->base, (size_t)file->bytes, now);
            q1n1_payload_line_begin(&line, "PAYLOAD REFUSED=HASH_AT_EL2");
            q1n1_payload_line_dec(&line, "INDEX", index);
            q1n1_payload_line_digest(&line, "WANT", file->sha256);
            q1n1_payload_line_digest(&line, "HAVE", now);
            emit_line(env, &line);
            result->status = Q1N1_PAYLOAD_RUN_HASH;
            result->stopped = index;
            emit_chain_stopped(env, index, "HASH_AT_EL2");
            return result->status;
        }
        q1n1_payload_line_begin(&line, "PAYLOAD VERIFY=OK");
        emit_line(env, &line);
#if Q1N1_SP11_SMMUMAP
        /* Once, after the first payload's own hash check and before its call: the one descriptor that maps the PCIe SMMU's register
         * page (sp11-smmumap.h). Nothing is written unless every payload of the chain verifies where it now is, so a payload that
         * does not verify can no longer follow a descriptor: the others are checked first, without a line, and one that fails gives
         * the refusal the loop would give it later. A refusal of the step wrote nothing and the chain goes on; only a descriptor
         * that could be neither checked nor removed ends it. */
        if (!smmumap_done && env->smmumap) {
            smmumap_done = 1;
            for (uint32_t other = index + 1; other < loaded->count && other < Q1N1_PAYLOAD_MAX_FILES; other++) {
                if (q1n1_payload_file_is_code(&loaded->file[other]) && !q1n1_payload_verify_in_place(loaded, other)) {
                    refuse_hash(env, loaded, other, result);
                    return result->status;
                }
            }
            if (env->smmumap() == Q1N1_SMMUMAP_UNSAFE) {
                result->status = Q1N1_PAYLOAD_RUN_SMMUMAP;
                result->stopped = index;
                emit_chain_stopped(env, index, "SMMUMAP");
                return result->status;
            }
        }
#endif

        /* Rebuilt for every payload from nothing: what an earlier payload did to its copy is not seen. */
        struct q1n1_payload_args args;
        uint8_t *raw = (uint8_t *)&args;
        for (size_t i = 0; i < sizeof args; i++) raw[i] = 0;
        args.magic = Q1N1_PAYLOAD_ABI_MAGIC;
        args.version = Q1N1_PAYLOAD_ABI_VERSION;
        args.size = sizeof args;
        args.payload_base = file->base;
        args.payload_size = file->bytes;
        args.fb_base = platform->fb_base;
        args.fb_bytes = platform->fb_bytes;
        args.fb_width = platform->fb_width;
        args.fb_height = platform->fb_height;
        args.fb_stride = platform->fb_stride;
        args.fb_format = platform->fb_format;
        args.map_base = platform->map_base;
        args.map_size = platform->map_size;
        args.map_stride = platform->map_stride;
        args.preload_table = loaded->table_base;
        args.preload_size = sizeof(struct q1n1_preload_cache);
        args.stack_base = loaded->stack_base;
        args.stack_size = loaded->stack_alloc;
        args.ops.puts = op_puts;
        args.ops.hex = op_hex;
        args.ops.load32 = op_load32;
        args.ops.counter = op_counter;
#if Q1N1_SP11_WTAB
        /* The table's ops go to this payload alone, in the one field of ABI v1 that is zero by definition; its run, journal and gates start from
         * nothing for every payload of the chain. */
        if (q1n1_wtab_attached()) {
            struct q1n1_wtab_machine machine = {file->base, file->bytes, platform->map_base, platform->map_size, platform->map_stride};
            q1n1_wtab_begin(q1n1_wtab_attached(), &machine);
            args.reserved[0] = (uint64_t)(uintptr_t)q1n1_wtab_ops();
        }
#endif
        session.stack_base = args.stack_base;
        session.stack_size = args.stack_size;
        session.lines = session.dropped = session.loads = session.faults = session.refused = 0;
#if Q1N1_SP11_WTAB
        session.image_base = file->base;
        session.image_size = file->bytes;
        session.op_lines = 0;
#endif

        for (unsigned i = 0; i < GUARD_WORDS; i++) guard[i] = GUARD_PATTERN;
        env->sync_code(file->base, file->alloc);

        /* Named before the call, so that a payload that never returns is named by this line. */
        char text[24];
        q1n1_payload_fmt_dec(text, sizeof text, index);
        q1n1_payload_line_begin(&line, "PAYLOAD CALL");
        q1n1_payload_line_word(&line, text);
        q1n1_payload_line_digest(&line, 0, file->sha256);
        emit_line(env, &line);
        uint64_t value = env->call(file->base, &args, args.stack_base + args.stack_size);
#if Q1N1_SP11_WTAB
        /* Before the DONE line: what is still in force is undone (when the table says so) and the run's END is printed even if the payload
         * returned in the middle of it. */
        if (q1n1_wtab_attached()) q1n1_wtab_finish(0);
#endif

        int intact = 1;
        for (unsigned i = 0; i < GUARD_WORDS; i++) intact &= guard[i] == GUARD_PATTERN;
        q1n1_payload_line_begin(&line, "PAYLOAD DONE");
        q1n1_payload_line_dec(&line, "INDEX", index);
        q1n1_payload_line_hex(&line, "RETURN", value);
        q1n1_payload_line_word(&line, intact ? "STACK=OK" : "STACK=OVERFLOW");
        q1n1_payload_line_dec(&line, "LOADS", session.loads);
        q1n1_payload_line_dec(&line, "FAULTS", session.faults);
        q1n1_payload_line_dec(&line, "REFUSED", session.refused);
        q1n1_payload_line_dec(&line, "LINES", session.lines);
        q1n1_payload_line_dec(&line, "DROPPED", session.dropped);
        emit_line(env, &line);

        done->index = index;
        done->retval = value;
        done->stack_ok = intact;
        done->lines = session.lines;
        done->dropped = session.dropped;
        done->loads = session.loads;
        done->faults = session.faults;
        done->refused = session.refused;
        result->called++;
        /* What a payload returns never stops the chain; a payload that ran past its stack does, because
         * nothing says what else it overwrote. */
        if (!intact) {
            result->status = Q1N1_PAYLOAD_RUN_STACK;
            result->stopped = index;
            emit_chain_stopped(env, index, "STACK_OVERFLOW");
            return result->status;
        }
    }
    return result->status;
}

#endif /* Q1N1_SP11_PAYLOAD */
