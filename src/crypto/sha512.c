/*
 * MIT License
 *
 * Copyright (c) 2026 ActivationSystem Contributors
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

/**
 * @file  sha512.c
 * @brief SHA-512 (FIPS 180-4) implementation. See sha512.h for the API docs.
 */

#include "activation/sha512.h"

#include <string.h>

/* Internal helpers                                                    */

/** Rotate right for 64-bit values (well-defined, no UB on edge shifts). */
static uint64_t rotr64(uint64_t x, unsigned n)
{
    return (x >> n) | (x << (64U - n));
}

/** Big-endian load / store of 64-bit words (portable, alignment-safe). */
static uint64_t load_be64(const uint8_t *p)
{
    uint64_t v = 0;
    int i;
    for (i = 0; i < 8; i++) {
        v = (v << 8) | (uint64_t)p[i];
    }
    return v;
}

static void store_be64(uint8_t *p, uint64_t v)
{
    int i;
    for (i = 7; i >= 0; i--) {
        p[i] = (uint8_t)(v & 0xFFu);
        v >>= 8;
    }
}

/* Round constants -- first 64 bits of the fractional parts of the     */
/* square roots of the first 80 primes (FIPS 180-4, section 4.2.3).    */

static const uint64_t K[80] = {
    0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL,
    0xe9b5dba58189dbbcULL, 0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL,
    0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL, 0xd807aa98a3030242ULL,
    0x12835b0145706fbeULL, 0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
    0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL,
    0xc19bf174cf692694ULL, 0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL,
    0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL, 0x2de92c6f592b0275ULL,
    0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
    0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL, 0xb00327c898fb213fULL,
    0xbf597fc7beef0ee4ULL, 0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL,
    0x06ca6351e003826fULL, 0x142929670a0e6e70ULL, 0x27b70a8546d22ffcULL,
    0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
    0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL,
    0x92722c851482353bULL, 0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL,
    0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL, 0xd192e819d6ef5218ULL,
    0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
    0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL, 0x2748774cdf8eeb99ULL,
    0x34b0bcb5e19b48a8ULL, 0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL,
    0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL, 0x748f82ee5defb2fcULL,
    0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
    0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL,
    0xc67178f2e372532bULL, 0xca273eceea26619cULL, 0xd186b8c721c0c207ULL,
    0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL, 0x06f067aa72176fbaULL,
    0x0a637dc5a2c898a6ULL, 0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
    0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL,
    0x431d67c49c100d4cULL, 0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL,
    0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL
};

/* Core compression function                                            */

/**
 * @brief Process one 128-byte block through the 80-round SHA-512 compression.
 * @param state current 8-word chaining state (updated in place).
 * @param block pointer to exactly 128 bytes of input.
 */
static void sha512_compress(uint64_t state[8], const uint8_t block[ACT_SHA512_BLOCK_SIZE])
{
    uint64_t w[80];
    uint64_t a, b, c, d, e, f, g, h;
    uint64_t t1, t2;
    int i;

    /* Message schedule: first 16 words from the block, then expansion. */
    for (i = 0; i < 16; i++) {
        w[i] = load_be64(block + 8 * i);
    }
    for (i = 16; i < 80; i++) {
        const uint64_t s0 = rotr64(w[i - 15], 1) ^ rotr64(w[i - 15], 8) ^ (w[i - 15] >> 7);
        const uint64_t s1 = rotr64(w[i - 2], 19) ^ rotr64(w[i - 2], 61) ^ (w[i - 2] >> 6);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }

    a = state[0]; b = state[1]; c = state[2]; d = state[3];
    e = state[4]; f = state[5]; g = state[6]; h = state[7];

    for (i = 0; i < 80; i++) {
        const uint64_t s1 = rotr64(e, 14) ^ rotr64(e, 18) ^ rotr64(e, 41);
        const uint64_t ch = (e & f) ^ ((~e) & g);
        t1 = h + s1 + ch + K[i] + w[i];
        const uint64_t s0 = rotr64(a, 28) ^ rotr64(a, 34) ^ rotr64(a, 39);
        const uint64_t maj = (a & b) ^ (a & c) ^ (b & c);
        t2 = s0 + maj;

        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }

    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
    state[4] += e; state[5] += f; state[6] += g; state[7] += h;
}

/* Public API                                                           */

void act_sha512_init(act_sha512_ctx *ctx)
{
    /* FIPS 180-4, section 5.3.3 -- initial hash values. */
    ctx->state[0] = 0x6a09e667f3bcc908ULL;
    ctx->state[1] = 0xbb67ae8584caa73bULL;
    ctx->state[2] = 0x3c6ef372fe94f82bULL;
    ctx->state[3] = 0xa54ff53a5f1d36f1ULL;
    ctx->state[4] = 0x510e527fade682d1ULL;
    ctx->state[5] = 0x9b05688c2b3e6c1fULL;
    ctx->state[6] = 0x1f83d9abfb41bd6bULL;
    ctx->state[7] = 0x5be0cd19137e2179ULL;
    ctx->bitlen_total = 0;
    ctx->buffer_len = 0;
    memset(ctx->buffer, 0, sizeof(ctx->buffer));
}

void act_sha512_update(act_sha512_ctx *ctx, const void *data, size_t len)
{
    const uint8_t *p = (const uint8_t *)data;

    if (data == NULL || len == 0) {
        return;
    }

    ctx->bitlen_total += (uint64_t)len * 8ULL;

    /* Fill a partially buffered block first, if present. */
    if (ctx->buffer_len > 0) {
        const size_t need = ACT_SHA512_BLOCK_SIZE - ctx->buffer_len;
        const size_t take = (len < need) ? len : need;
        memcpy(ctx->buffer + ctx->buffer_len, p, take);
        ctx->buffer_len += take;
        p += take;
        len -= take;
        if (ctx->buffer_len == ACT_SHA512_BLOCK_SIZE) {
            sha512_compress(ctx->state, ctx->buffer);
            ctx->buffer_len = 0;
        }
    }

    /* Compress whole blocks directly from the input. */
    while (len >= ACT_SHA512_BLOCK_SIZE) {
        sha512_compress(ctx->state, p);
        p += ACT_SHA512_BLOCK_SIZE;
        len -= ACT_SHA512_BLOCK_SIZE;
    }

    /* Buffer the tail. */
    if (len > 0) {
        memcpy(ctx->buffer, p, len);
        ctx->buffer_len = len;
    }
}

void act_sha512_final(act_sha512_ctx *ctx, uint8_t digest[ACT_SHA512_DIGEST_SIZE])
{
    uint64_t bitlen = ctx->bitlen_total;
    uint8_t pad[ACT_SHA512_BLOCK_SIZE];
    uint8_t lenbuf[16];
    size_t padlen;
    int i;

    /* 0x80 terminator, then zeros, then 128-bit big-endian bit length. */
    pad[0] = 0x80;
    memset(pad + 1, 0, sizeof(pad) - 1);

    /* (128-bit length: we use 64-bit counting; messages < 2 Exabytes are fine,
     * which is more than enough for an activation system.) */
    memset(lenbuf, 0, 8);
    store_be64(lenbuf + 8, bitlen);

    padlen = (ctx->buffer_len < 112) ? (112 - ctx->buffer_len)
                                     : (240 - ctx->buffer_len); /* wraps into next block */
    padlen %= ACT_SHA512_BLOCK_SIZE;
    if (padlen == 0) {
        padlen = ACT_SHA512_BLOCK_SIZE;
    }

    act_sha512_update(ctx, pad, padlen);
    act_sha512_update(ctx, lenbuf, sizeof(lenbuf));
    /* After feeding the length the context buffer holds exactly nothing. */

    for (i = 0; i < 8; i++) {
        store_be64(digest + 8 * i, ctx->state[i]);
    }

    act_sha512_init(ctx); /* reset so ctx is reusable */
}

void act_sha512(const void *data, size_t len, uint8_t digest[ACT_SHA512_DIGEST_SIZE])
{
    act_sha512_ctx ctx;
    act_sha512_init(&ctx);
    act_sha512_update(&ctx, data, len);
    act_sha512_final(&ctx, digest);
}

int act_secure_memcmp(const void *a, const void *b, size_t len)
{
    const uint8_t *pa = (const uint8_t *)a;
    const uint8_t *pb = (const uint8_t *)b;
    uint8_t diff = 0;
    size_t i;

    for (i = 0; i < len; i++) {
        diff |= (uint8_t)(pa[i] ^ pb[i]);
    }
    /* OR-accumulated difference is 0 iff the buffers match; returning it
     * directly keeps the memcmp() "0 == equal" convention while the loop
     * timing stays independent of where a mismatch occurs. */
    return (int)diff;
}

void act_secure_wipe(void *dst, size_t len)
{
    volatile uint8_t *p = (volatile uint8_t *)dst;
    while (len--) {
        *p++ = 0;
    }
}
