/* SPDX-License-Identifier: MIT */
/* The runner's EL2 half (sp11-payload.h): verify the payload where it now is, make it executable, call
 * it, and offer it the four ops of the payload ABI (sp11-payload-abi.h). Everything the hardware does
 * goes through q1n1_payload_env, so the native tests run this against a fake platform.
 *
 * The payload gets exactly what the ABI says and the ops are the only way it calls q1n1: puts, hex,
 * load32 and counter. There is no store. load32 reads through the platform's guarded copy and refuses
 * every request whose destination is not the payload's own stack, so it cannot be turned into a store to
 * a device register either. That does not sandbox the payload (it is code at EL2): it keeps the ops
 * honest, and the review of the payload and its pinned SHA-256 carry the rest. */
#include "sp11-payload.h"
#include "sha256.h"

#if Q1N1_SP11_PAYLOAD

/* One payload runs once, so the ops (plain function pointers with no context argument, because the
 * payload is a separate binary) find their platform here. */
static struct {
    const struct q1n1_payload_env *env;
    uint64_t stack_base, stack_size;
    unsigned lines, dropped, loads, faults, refused;
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

static void op_puts(const char *line)
{
    char text[Q1N1_PAYLOAD_LINE_MAX + 1];
    unsigned n = 0;
    if (!line) return;
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
    session.loads++;
    /* Only ever a load: COPY32 reads `addr` into the runner's own variable. The payload's word is
     * written by an ordinary store after the guarded read succeeded. */
    if (session.env->guarded(Q1N1_PAYLOAD_G_COPY32, (uint64_t)(uintptr_t)&value, addr, 4)) {
        session.faults++;
        return Q1N1_PAYLOAD_LOAD_E_FAULT;
    }
    *out = value;
    return Q1N1_PAYLOAD_LOAD_OK;
}

static uint64_t op_counter(void)
{
    return session.env->counter();
}

int q1n1_payload_verify_in_place(const struct q1n1_payload_loaded *loaded)
{
    if (!loaded->count || !loaded->table_base) return 0;
    const struct q1n1_preload_cache *table = (const void *)(uintptr_t)loaded->table_base;
    /* The table describes exactly what the runner loaded: a payload finds its files through it, so a
     * count or an entry that changed after the bounce is as much a refusal as a payload that did. */
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
     * above has shown is the one measured before the bounce. Only the payload is hashed; a data file can
     * be gigabytes and nothing calls it. */
    return q1n1_preload_verify(table, 0);
}

/* Two words at the low end of the stack, written after the bounce and checked when the payload returns:
 * a payload that ran past its stack has overwritten them. */
#define GUARD_WORDS 2u
#define GUARD_PATTERN UINT64_C(0x5afe5afe5afe5afe)

static void emit_line(const struct q1n1_payload_env *env, const struct q1n1_payload_line *line)
{
    env->emit(line->buf);
}

int q1n1_payload_run(const struct q1n1_payload_env *env, const struct q1n1_payload_loaded *loaded,
                     const struct q1n1_payload_platform *platform, struct q1n1_payload_result *result)
{
    struct q1n1_payload_line line;
    result->status = Q1N1_PAYLOAD_RUN_OK;
    result->retval = 0;
    result->stack_ok = 0;
    result->lines = result->dropped = result->loads = result->faults = result->refused = 0;
    session.env = env;
    session.lines = session.dropped = session.loads = session.faults = session.refused = 0;

    for (uint32_t i = 0; i < loaded->notes && i < Q1N1_PAYLOAD_NOTES; i++) env->emit(loaded->note[i]);
    if (!loaded->count || !loaded->stack_base) {
        q1n1_payload_line_begin(&line, "PAYLOAD REFUSED=NO_PAYLOAD");
        emit_line(env, &line);
        result->status = Q1N1_PAYLOAD_RUN_NO_PAYLOAD;
        return result->status;
    }
    /* The second hash, here, where the payload now is. The first was taken before the bounce; a line
     * the bounce lost, or memory it did not preserve, shows up as a difference and the payload is not
     * called. */
    if (!q1n1_payload_verify_in_place(loaded)) {
        uint8_t now[32];
        q1n1_sha256((const void *)(uintptr_t)loaded->file[0].base, (size_t)loaded->file[0].bytes, now);
        q1n1_payload_line_begin(&line, "PAYLOAD REFUSED=HASH_AT_EL2 INDEX=0");
        q1n1_payload_line_digest(&line, "WANT", loaded->file[0].sha256);
        q1n1_payload_line_digest(&line, "HAVE", now);
        emit_line(env, &line);
        result->status = Q1N1_PAYLOAD_RUN_HASH;
        return result->status;
    }
    q1n1_payload_line_begin(&line, "PAYLOAD VERIFY=OK");
    emit_line(env, &line);

    struct q1n1_payload_args args;
    uint8_t *raw = (uint8_t *)&args;
    for (size_t i = 0; i < sizeof args; i++) raw[i] = 0;
    args.magic = Q1N1_PAYLOAD_ABI_MAGIC;
    args.version = Q1N1_PAYLOAD_ABI_VERSION;
    args.size = sizeof args;
    args.payload_base = loaded->file[0].base;
    args.payload_size = loaded->file[0].bytes;
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
    session.stack_base = args.stack_base;
    session.stack_size = args.stack_size;

    volatile uint64_t *guard = (volatile uint64_t *)(uintptr_t)loaded->stack_base;
    for (unsigned i = 0; i < GUARD_WORDS; i++) guard[i] = GUARD_PATTERN;
    env->sync_code(loaded->file[0].base, loaded->file[0].alloc);

    /* Named before the call, so that a payload that never returns is named by this line. */
    q1n1_payload_line_begin(&line, "PAYLOAD CALL");
    q1n1_payload_line_digest(&line, 0, loaded->file[0].sha256);
    emit_line(env, &line);
    uint64_t value = env->call(loaded->file[0].base, &args, args.stack_base + args.stack_size);

    char text[24];
    q1n1_payload_fmt_hex(text, sizeof text, value);
    q1n1_payload_line_begin(&line, "PAYLOAD RETURN=");
    q1n1_payload_line_raw(&line, text);
    emit_line(env, &line);
    int intact = 1;
    for (unsigned i = 0; i < GUARD_WORDS; i++) intact &= guard[i] == GUARD_PATTERN;
    q1n1_payload_line_begin(&line, intact ? "PAYLOAD STACK=OK" : "PAYLOAD STACK=OVERFLOW");
    emit_line(env, &line);
    q1n1_payload_line_begin(&line, "PAYLOAD OPS");
    q1n1_payload_line_dec(&line, "LOADS", session.loads);
    q1n1_payload_line_dec(&line, "FAULTS", session.faults);
    q1n1_payload_line_dec(&line, "REFUSED", session.refused);
    q1n1_payload_line_dec(&line, "LINES", session.lines);
    q1n1_payload_line_dec(&line, "DROPPED", session.dropped);
    emit_line(env, &line);

    result->retval = value;
    result->stack_ok = intact;
    result->lines = session.lines;
    result->dropped = session.dropped;
    result->loads = session.loads;
    result->faults = session.faults;
    result->refused = session.refused;
    return result->status;
}

#endif /* Q1N1_SP11_PAYLOAD */
