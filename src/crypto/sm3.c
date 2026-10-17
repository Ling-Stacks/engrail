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
 * @file  sm3.c
 * @brief SM3 hash (GB/T 32905-2016). See sm3.h.
 */

#include "activation/sm3.h"

#include <string.h>

#define ROTL(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

/* P0 / P1 permutations (GB/T 32905-2016 section 4.2). */
#define P0(x) ((x) ^ ROTL(x, 9) ^ ROTL(x, 17))
#define P1(x) ((x) ^ ROTL(x, 15) ^ ROTL(x, 23))

static uint32_t load_be32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static void store_be32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)(v);
}

/** One 512-bit block compression over 8-word state. */
static void sm3_compress(uint32_t v[8], const uint8_t block[64])
{
    uint32_t w[68], w1[64];
    int j;

    for (j = 0; j < 16; j++) {
        w[j] = load_be32(block + 4 * j);
    }
    for (j = 16; j < 68; j++) {
        const uint32_t x = w[j - 16] ^ w[j - 9] ^ ROTL(w[j - 3], 15);
        w[j] = P1(x) ^ ROTL(w[j - 13], 7) ^ w[j - 6];
    }
    for (j = 0; j < 64; j++) {
        w1[j] = w[j] ^ w[j + 4];
    }

    uint32_t a = v[0], b = v[1], c = v[2], d = v[3];
    uint32_t e = v[4], f = v[5], g = v[6], h = v[7];

    for (j = 0; j < 64; j++) {
        const uint32_t t = (j < 16) ? 0x79cc4519u : 0x7a879d8au;
        const uint32_t tt1_rot = ROTL(a, 12) + e + ROTL(t, (uint32_t)(j % 32));
        const uint32_t ss1 = ROTL(tt1_rot, 7);
        const uint32_t ss2 = ss1 ^ ROTL(a, 12);
        uint32_t ff, gg;
        if (j < 16) {
            ff = a ^ b ^ c;
            gg = e ^ f ^ g;
        } else {
            ff = (a & b) | (a & c) | (b & c);
            gg = (e & f) | ((~e) & g);
        }
        const uint32_t tt1 = ff + d + ss2 + w1[j];
        const uint32_t tt2 = gg + h + ss1 + w[j];
        d = c;
        c = ROTL(b, 9);
        b = a;
        a = tt1;
        h = g;
        g = ROTL(f, 19);
        f = e;
        e = P0(tt2);
    }

    v[0] ^= a; v[1] ^= b; v[2] ^= c; v[3] ^= d;
    v[4] ^= e; v[5] ^= f; v[6] ^= g; v[7] ^= h;
}

void act_sm3_init(act_sm3_ctx *ctx)
{
    /* GB/T 32905-2016 section 5.3.2 initial value. */
    ctx->state[0] = 0x7380166fu;
    ctx->state[1] = 0x4914b2b9u;
    ctx->state[2] = 0x172442d7u;
    ctx->state[3] = 0xda8a0600u;
    ctx->state[4] = 0xa96f30bcu;
    ctx->state[5] = 0x163138aau;
    ctx->state[6] = 0xe38dee4du;
    ctx->state[7] = 0xb0fb0e4eu;
    ctx->bitlen_total = 0;
    ctx->buffer_len = 0;
    memset(ctx->buffer, 0, sizeof(ctx->buffer));
}

void act_sm3_update(act_sm3_ctx *ctx, const void *data, size_t len)
{
    const uint8_t *p = (const uint8_t *)data;
    if (data == NULL || len == 0) {
        return;
    }
    ctx->bitlen_total += (uint64_t)len * 8ULL;

    if (ctx->buffer_len > 0) {
        const size_t need = ACT_SM3_BLOCK_SIZE - ctx->buffer_len;
        const size_t take = (len < need) ? len : need;
        memcpy(ctx->buffer + ctx->buffer_len, p, take);
        ctx->buffer_len += take;
        p += take;
        len -= take;
        if (ctx->buffer_len == ACT_SM3_BLOCK_SIZE) {
            sm3_compress(ctx->state, ctx->buffer);
            ctx->buffer_len = 0;
        }
    }
    while (len >= ACT_SM3_BLOCK_SIZE) {
        sm3_compress(ctx->state, p);
        p += ACT_SM3_BLOCK_SIZE;
        len -= ACT_SM3_BLOCK_SIZE;
    }
    if (len > 0) {
        memcpy(ctx->buffer, p, len);
        ctx->buffer_len = len;
    }
}

void act_sm3_final(act_sm3_ctx *ctx, uint8_t digest[ACT_SM3_DIGEST_SIZE])
{
    const uint64_t bitlen = ctx->bitlen_total;
    uint8_t pad[ACT_SM3_BLOCK_SIZE];
    uint8_t lenbuf[8];
    size_t padlen;
    int i;

    pad[0] = 0x80;
    memset(pad + 1, 0, sizeof(pad) - 1);
    for (i = 0; i < 8; i++) {
        lenbuf[i] = (uint8_t)(bitlen >> (56 - 8 * i));
    }

    /* length field is 8 bytes (64 bits): leave 64..size-8 for it */
    padlen = (ctx->buffer_len < 56) ? (56 - ctx->buffer_len)
                                    : (120 - ctx->buffer_len);

    act_sm3_update(ctx, pad, padlen);
    act_sm3_update(ctx, lenbuf, 8);

    for (i = 0; i < 8; i++) {
        store_be32(digest + 4 * i, ctx->state[i]);
    }
    act_sm3_init(ctx);
}

void act_sm3(const void *data, size_t len, uint8_t digest[ACT_SM3_DIGEST_SIZE])
{
    act_sm3_ctx ctx;
    act_sm3_init(&ctx);
    act_sm3_update(&ctx, data, len);
    act_sm3_final(&ctx, digest);
}
