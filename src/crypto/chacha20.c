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
 * @file  chacha20.c
 * @brief ChaCha20 (RFC 8439) -- ARX core, little-endian state, portable C99.
 */

#include "activation/chacha20.h"

#include <string.h>

/** Quarter round: a += b; d ^= a; d <<<= 16; (and rotations 12, 8). */
#define QR(a, b, c, d)                                    \
    do {                                                  \
        a += b; d ^= a; d = (d << 16) | (d >> 16);        \
        c += d; b ^= c; b = (b << 12) | (b >> 20);        \
        a += b; d ^= a; d = (d << 8) | (d >> 24);         \
        c += d; b ^= c; b = (b << 7) | (b >> 25);         \
    } while (0)

static uint32_t load32_le(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

/** Generate one 64-byte keystream block for (key, nonce, counter). */
static void chacha20_block(const uint8_t key[32],
                           const uint8_t nonce[12],
                           uint32_t counter,
                           uint8_t out[64])
{
    /* "expand 32-byte k" */
    uint32_t st[16] = {
        0x61707865u, 0x3320646eu, 0x79622d32u, 0x6b206574u,
        load32_le(key + 0),  load32_le(key + 4),
        load32_le(key + 8),  load32_le(key + 12),
        load32_le(key + 16), load32_le(key + 20),
        load32_le(key + 24), load32_le(key + 28),
        counter,
        load32_le(nonce + 0), load32_le(nonce + 4), load32_le(nonce + 8)
    };
    uint32_t w[16];
    memcpy(w, st, sizeof(w));

    for (int i = 0; i < 10; i++) { /* 20 rounds = 10 double rounds */
        QR(w[0], w[4], w[8],  w[12]);
        QR(w[1], w[5], w[9],  w[13]);
        QR(w[2], w[6], w[10], w[14]);
        QR(w[3], w[7], w[11], w[15]);
        QR(w[0], w[5], w[10], w[15]);
        QR(w[1], w[6], w[11], w[12]);
        QR(w[2], w[7], w[8],  w[13]);
        QR(w[3], w[4], w[9],  w[14]);
    }

    for (int i = 0; i < 16; i++) {
        const uint32_t v = w[i] + st[i];
        out[4 * i + 0] = (uint8_t)(v);
        out[4 * i + 1] = (uint8_t)(v >> 8);
        out[4 * i + 2] = (uint8_t)(v >> 16);
        out[4 * i + 3] = (uint8_t)(v >> 24);
    }
    memset(w, 0, sizeof(w));
    memset(st, 0, sizeof(st));
}

void act_chacha20_xor(const uint8_t key[ACT_CHACHA20_KEY_SIZE],
                      const uint8_t nonce[ACT_CHACHA20_NONCE_SIZE],
                      uint32_t counter,
                      uint8_t *data, size_t len)
{
    uint8_t ks[64];
    size_t off = 0;
    while (off < len) {
        chacha20_block(key, nonce, counter++, ks);
        const size_t take = (len - off < 64) ? (len - off) : 64;
        for (size_t i = 0; i < take; i++) {
            data[off + i] ^= ks[i];
        }
        off += take;
    }
    memset(ks, 0, sizeof(ks));
}
