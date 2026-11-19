# SPDX-License-Identifier: MIT
"""The seeded bugs in the big-file code of the payload runner (docs/SP11-PAYLOAD-BIGFILE.md) that tools/test-q1n1-sp11-payload.py (Mutants) applies to a copy
of the sources, each of which the gate-on programs ('load-big' at the default 8 MiB chunk cap, 'load-small' at 64 KiB, 'plan-big', 'plan-small') must reject. Data
only: it is a module of its own because the main test is close to the size limit every test file keeps. Hardware: NOT RUN."""

LOAD = 'uefi/sp11-payload-load.c'
PLAN = 'uefi/sp11-payload-plan.c'
HDR = 'uefi/sp11-payload.h'
LOADERS = ['load-big', 'load-small']
PLANS = ['plan-big', 'plan-small']

TOP_OK = ('    return address && !(address & (PAGE_BYTES - 1)) && bytes && address <= Q1N1_PAYLOAD_TOP_ADDRESS &&\n'
          '           bytes - 1 <= Q1N1_PAYLOAD_TOP_ADDRESS - address;')
NO_MEMORY_RETURN = ('    if (status) {\n        diag->efi = status;\n        diag->expected = bytes;\n        diag->got = 0;\n'
                    '        return Q1N1_PAYLOAD_E_FILE_NO_MEMORY;\n    }')


def bigfile_mutants():
    """(name, file below the copy's root, [(text that occurs exactly once, what replaces it)], programs that must reject it, build error that counts)."""
    return [
        # -- the limit: derived from the cap, 256 ops, at most 2 GiB, in 64 bits
        ('big-limit-is-not-derived-from-the-cap', HDR, [(
            '#define Q1N1_PAYLOAD_MAX_FILE_BYTES ((uint64_t)Q1N1_PAYLOAD_SWEEP_MAX_OPS * Q1N1_PAYLOAD_CHUNK_BYTES)',
            '#define Q1N1_PAYLOAD_MAX_FILE_BYTES ((uint64_t)Q1N1_PAYLOAD_SWEEP_MAX_OPS << 20)')], LOADERS, None),
        ('big-limit-counts-512-ops', HDR, [(
            '#define Q1N1_PAYLOAD_SWEEP_MAX_OPS 256u', '#define Q1N1_PAYLOAD_SWEEP_MAX_OPS 512u')], ['load-big'], 'no file is over 2 GiB'),
        ('big-limit-counts-512-ops-at-a-small-cap', HDR, [(
            '#define Q1N1_PAYLOAD_SWEEP_MAX_OPS 256u', '#define Q1N1_PAYLOAD_SWEEP_MAX_OPS 512u')], ['load-small', 'plan-small'], None),
        ('big-cap-of-16-mib', HDR, [('#define Q1N1_SP11_BIGFILE_CHUNK_KIB 8192u', '#define Q1N1_SP11_BIGFILE_CHUNK_KIB 16384u')],
         ['load-big'], 'the chunk cap is a power of two from 64 KiB to 8 MiB'),
        ('big-ceiling-lets-4-gib-through', HDR, [
            ('#define Q1N1_SP11_BIGFILE_CHUNK_KIB 8192u', '#define Q1N1_SP11_BIGFILE_CHUNK_KIB 16384u'),
            ('Q1N1_SP11_BIGFILE_CHUNK_KIB <= 8192u', 'Q1N1_SP11_BIGFILE_CHUNK_KIB <= 16384u')], ['load-big'], 'no file is over 2 GiB'),
        ('big-limit-truncated-to-32-bits', LOAD, [(
            '        if (f->size > Q1N1_PAYLOAD_MAX_FILE_BYTES) {', '        if ((uint32_t)f->size > Q1N1_PAYLOAD_MAX_FILE_BYTES) {')],
         LOADERS, None),
        ('big-limit-is-exclusive', LOAD, [(
            '        if (f->size > Q1N1_PAYLOAD_MAX_FILE_BYTES) {', '        if (f->size >= Q1N1_PAYLOAD_MAX_FILE_BYTES) {')], LOADERS, None),
        # -- allocation: the top of RAM for data, no fallback, a named refusal, the answer checked
        ('big-data-is-asked-of-anypages', LOAD, [(
            'bs->allocate_pages(Q1N1_PAYLOAD_ALLOCATE_MAX_ADDRESS, type, bytes / PAGE_BYTES, &address);',
            'bs->allocate_pages(Q1N1_PAYLOAD_ALLOCATE_ANY_PAGES, type, bytes / PAGE_BYTES, &address);')], LOADERS, None),
        ('big-data-falls-back-to-anypages', LOAD, [(
            NO_MEMORY_RETURN, '    if (status) {\n        return allocate(bs, type, bytes, base, diag);\n    }')], LOADERS, None),
        ('big-allocation-failure-is-not-refused', LOAD, [(
            '        return Q1N1_PAYLOAD_E_FILE_NO_MEMORY;\n', '        status = 0;\n')], LOADERS, None),
        ('big-refusal-does-not-name-the-file', LOAD, [(
            '    if (err == Q1N1_PAYLOAD_E_FILE_NO_MEMORY) return 1;\n', '')], LOADERS, None),
        ('big-payload-is-asked-of-the-top-too', LOAD, [(
            'int err = entry->memory_type == Q1N1_PAYLOAD_TYPE_DATA ? allocate_top(', 'int err = 1 ? allocate_top(')], LOADERS, None),
        ('big-top-answer-is-trusted', LOAD, [(TOP_OK, '    return address && !(address & (PAGE_BYTES - 1)) && bytes;')], LOADERS, None),
        ('big-top-bound-is-exclusive', LOAD, [(
            'bytes - 1 <= Q1N1_PAYLOAD_TOP_ADDRESS - address;', 'bytes - 1 < Q1N1_PAYLOAD_TOP_ADDRESS - address;')], LOADERS, None),
        ('big-top-bound-ignores-the-end', LOAD, [(
            'bytes - 1 <= Q1N1_PAYLOAD_TOP_ADDRESS - address;', 'bytes - 1 <= Q1N1_PAYLOAD_TOP_ADDRESS;')], LOADERS, None),
        # -- hashing in slices, reading in 1 MiB requests, the progress lines
        ('big-hash-skips-the-last-slice', LOAD, [(
            '    while (done < entry->bytes) {', '    while (done + Q1N1_PAYLOAD_PROGRESS_BYTES <= entry->bytes) {')], LOADERS, None),
        ('big-hash-rereads-the-first-slice', LOAD, [(
            '        q1n1_sha256_update(&state, p + done, (size_t)take);', '        q1n1_sha256_update(&state, p, (size_t)take);')], LOADERS, None),
        ('big-hash-length-is-narrowed', LOAD, [(
            '        q1n1_sha256_update(&state, p + done, (size_t)take);', '        q1n1_sha256_update(&state, p + done, (size_t)(take & 0x3FFFFFF) - (take == 1));')],
         LOADERS, None),
        ('big-read-request-grows-to-8-mib', LOAD, [('#define READ_CHUNK UINT64_C(1048576)', '#define READ_CHUNK UINT64_C(8388608)')], ['load-big'], None),
        ('big-progress-is-printed-per-request', LOAD, [(
            '        if (progress_reading && (*got / Q1N1_PAYLOAD_PROGRESS_BYTES) != ((*got - n) / Q1N1_PAYLOAD_PROGRESS_BYTES))',
            '        if (progress_reading)')], ['load-big'], None),
        ('big-hash-progress-is-not-printed', LOAD, [(
            '        if (take == Q1N1_PAYLOAD_PROGRESS_BYTES) progress_line("PAYLOAD HASH", done, 0);', '')], ['load-big'], None),
        ('big-progress-line-changes-its-shape', LOAD, [('"PAYLOAD READ"', '"PAYLOAD LOAD"')], ['load-big'], None),
        # -- the plan: 64-bit sizes and the op count
        ('big-plan-size-truncated-to-32-bits', PLAN, [(
            'static uint64_t chunks_for(uint64_t size, uint32_t chunk_cap)', 'static uint64_t chunks_for(uint32_t size, uint32_t chunk_cap)')],
         PLANS, None),
        ('big-max-ops-rounds-down', PLAN, [(
            '        uint64_t ops = chunks_for(t->range[i].size, t->chunk_cap);', '        uint64_t ops = t->range[i].size / t->chunk_cap;')],
         PLANS, None),
        ('big-max-ops-is-the-first-ranges', PLAN, [('        if (ops > most) most = ops;', '        if (!most) most = ops;')], PLANS, None),
    ]
