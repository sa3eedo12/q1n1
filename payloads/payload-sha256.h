/* SPDX-License-Identifier: MIT */
/* SHA-256 (FIPS 180-4) for the hashbig payload (docs/SP11-PAYLOAD-HASHBIG.md), plain integer C: general registers only, no libc, no
 * table that needs a relocation. The 64 round constants are a constant array of integers in .rodata, reached with ADRP and ADD like
 * every other constant of a payload; the linker script puts .rodata in the flat binary and the ELF check refuses an absolute address.
 * The host test links this very header (tools/test-q1n1-sp11-payload-hashbig.c) and compares its digests with the FIPS vectors, with
 * the runner's own sha256.c and, through hashbig, with Python's hashlib.
 *
 * The compression function is the only code of a payload that reads a loaded file in place, so it is a function of its own, out of
 * line: the binary check (policy key `bulk_reads`) names it as the place where loads may use any base. Hardware: NOT RUN. */
#pragma once
#include "payload-util.h"

typedef uint32_t __attribute__((may_alias)) pl_sha256_word;

struct pl_sha256 {
    uint32_t h[8];
};

static const uint32_t pl_sha256_k[64] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
    0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u, 0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
    0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu, 0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
    0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u, 0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
    0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u, 0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
    0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u, 0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
    0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
    0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u, 0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u,
};

static inline void pl_sha256_init(struct pl_sha256 *s)
{
    s->h[0] = 0x6a09e667u;
    s->h[1] = 0xbb67ae85u;
    s->h[2] = 0x3c6ef372u;
    s->h[3] = 0xa54ff53au;
    s->h[4] = 0x510e527fu;
    s->h[5] = 0x9b05688cu;
    s->h[6] = 0x1f83d9abu;
    s->h[7] = 0x5be0cd19u;
}

static inline uint32_t pl_sha256_ror(uint32_t x, unsigned n)
{
    return x >> n | x << (32 - n);
}

/* `blocks` whole 64-byte blocks at `p`, which must be 4-byte aligned. The message schedule is kept in a 16-word ring on the stack. */
static __attribute__((noinline)) void pl_sha256_blocks(struct pl_sha256 *s, const uint8_t *p, uint64_t blocks)
{
    uint32_t w[16];
    while (blocks--) {
        uint32_t a = s->h[0], b = s->h[1], c = s->h[2], d = s->h[3], e = s->h[4], f = s->h[5], g = s->h[6], h = s->h[7];
        for (unsigned i = 0; i < 64; i++) {
            uint32_t wi;
            if (i < 16) {
                wi = __builtin_bswap32(((const pl_sha256_word *)p)[i]);
            } else {
                uint32_t x = w[(i + 1) & 15], y = w[(i + 14) & 15];
                wi = w[i & 15] + (pl_sha256_ror(x, 7) ^ pl_sha256_ror(x, 18) ^ x >> 3) + w[(i + 9) & 15] +
                     (pl_sha256_ror(y, 17) ^ pl_sha256_ror(y, 19) ^ y >> 10);
            }
            w[i & 15] = wi;
            uint32_t t1 = h + (pl_sha256_ror(e, 6) ^ pl_sha256_ror(e, 11) ^ pl_sha256_ror(e, 25)) + ((e & f) ^ (~e & g)) +
                          pl_sha256_k[i] + wi;
            uint32_t t2 = (pl_sha256_ror(a, 2) ^ pl_sha256_ror(a, 13) ^ pl_sha256_ror(a, 22)) + ((a & b) ^ (a & c) ^ (b & c));
            h = g;
            g = f;
            f = e;
            e = d + t1;
            d = c;
            c = b;
            b = a;
            a = t1 + t2;
        }
        s->h[0] += a;
        s->h[1] += b;
        s->h[2] += c;
        s->h[3] += d;
        s->h[4] += e;
        s->h[5] += f;
        s->h[6] += g;
        s->h[7] += h;
        p += 64;
    }
}

/* Pads and finishes. `block` is 128 bytes of the caller's stack whose first `tail_len` (below 64) bytes are the last bytes of the
 * message and whose other bytes are zero; `total` is the message length in bytes. The digest is written big-endian to `out`. */
static inline void pl_sha256_finish(struct pl_sha256 *s, uint8_t *block, uint32_t tail_len, uint64_t total, uint8_t *out)
{
    unsigned used = tail_len < 56 ? 64 : 128;
    uint64_t bits = total << 3;
    block[tail_len] = 0x80;
    for (unsigned i = 0; i < 8; i++) block[used - 1 - i] = (uint8_t)(bits >> (8 * i));
    pl_sha256_blocks(s, block, used / 64);
    for (unsigned i = 0; i < 8; i++) {
        out[4 * i] = (uint8_t)(s->h[i] >> 24);
        out[4 * i + 1] = (uint8_t)(s->h[i] >> 16);
        out[4 * i + 2] = (uint8_t)(s->h[i] >> 8);
        out[4 * i + 3] = (uint8_t)s->h[i];
    }
}
