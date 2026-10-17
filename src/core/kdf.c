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
 * @file  kdf.c
 * @brief HKDF-SHA512 (RFC 5869) and PBKDF2-HMAC-SHA512 (RFC 8018).
 */

#include "activation/kdf.h"
#include "activation/hmac.h"
#include "activation/sha512.h"

#include <string.h>

void act_hkdf_extract(const uint8_t *salt, size_t salt_len,
                      const uint8_t *ikm, size_t ikm_len,
                      uint8_t prk[64])
{
    uint8_t zeros[ACT_HMAC_SHA512_SIZE] = { 0 };
    if (salt == NULL || salt_len == 0) {
        /* RFC 5869: absent salt => hashlen zeros. */
        act_hmac_sha512(zeros, sizeof(zeros), ikm, ikm_len, prk);
    } else {
        act_hmac_sha512(salt, salt_len, ikm, ikm_len, prk);
    }
}

int act_hkdf_expand(const uint8_t prk[64],
                    const uint8_t *info, size_t info_len,
                    uint8_t *out, size_t out_len)
{
    if (out_len > 255ULL * ACT_HMAC_SHA512_SIZE) {
        return -1;
    }

    uint8_t t[ACT_HMAC_SHA512_SIZE];
    size_t t_len = 0;
    size_t done = 0;
    uint32_t counter = 1;

    while (done < out_len) {
        /* T(i) = HMAC-SHA512(PRK, T(i-1) || info || i)  (three-input HMAC,
         * streamed manually since our helper only takes two chunks). */
        uint8_t ctr = (uint8_t)counter;
        {
            act_sha512_ctx ctx;
            uint8_t k[ACT_SHA512_BLOCK_SIZE];
            uint8_t pad[ACT_SHA512_BLOCK_SIZE];
            size_t i;
            memset(k, 0, sizeof(k));
            memcpy(k, prk, 64);
            for (i = 0; i < ACT_SHA512_BLOCK_SIZE; i++) {
                pad[i] = (uint8_t)(k[i] ^ 0x36);
            }
            act_sha512_init(&ctx);
            act_sha512_update(&ctx, pad, ACT_SHA512_BLOCK_SIZE);
            act_sha512_update(&ctx, t, t_len);
            if (info != NULL && info_len > 0) {
                act_sha512_update(&ctx, info, info_len);
            }
            act_sha512_update(&ctx, &ctr, 1);
            act_sha512_final(&ctx, t);
            for (i = 0; i < ACT_SHA512_BLOCK_SIZE; i++) {
                pad[i] = (uint8_t)(k[i] ^ 0x5c);
            }
            act_sha512_init(&ctx);
            act_sha512_update(&ctx, pad, ACT_SHA512_BLOCK_SIZE);
            act_sha512_update(&ctx, t, ACT_SHA512_DIGEST_SIZE);
            act_sha512_final(&ctx, t);
            act_secure_wipe(k, sizeof(k));
            act_secure_wipe(pad, sizeof(pad));
        }

        t_len = ACT_HMAC_SHA512_SIZE;
        const size_t take = (out_len - done < t_len) ? (out_len - done) : t_len;
        memcpy(out + done, t, take);
        done += take;
        counter++;
    }

    act_secure_wipe(t, sizeof(t));
    return 0;
}

int act_hkdf_sha512(const uint8_t *salt, size_t salt_len,
                    const uint8_t *ikm, size_t ikm_len,
                    const uint8_t *info, size_t info_len,
                    uint8_t *out, size_t out_len)
{
    uint8_t prk[ACT_HMAC_SHA512_SIZE];
    act_hkdf_extract(salt, salt_len, ikm, ikm_len, prk);
    const int rc = act_hkdf_expand(prk, info, info_len, out, out_len);
    act_secure_wipe(prk, sizeof(prk));
    return rc;
}

void act_pbkdf2_hmac_sha512(const uint8_t *pass, size_t pass_len,
                            const uint8_t *salt, size_t salt_len,
                            uint32_t iterations,
                            uint8_t *out, size_t out_len)
{
    if (iterations == 0) {
        iterations = 1;
    }

    uint32_t block = 1;
    size_t done = 0;
    while (done < out_len) {
        /* U1 = HMAC(pass, salt || INT_32_BE(block)) */
        uint8_t sblock[256];
        size_t sl = salt_len;
        if (sl > sizeof(sblock) - 4) {
            sl = sizeof(sblock) - 4; /* sane cap; salts are 16-32 bytes */
        }
        memcpy(sblock, salt, sl);
        sblock[sl + 0] = (uint8_t)(block >> 24);
        sblock[sl + 1] = (uint8_t)(block >> 16);
        sblock[sl + 2] = (uint8_t)(block >> 8);
        sblock[sl + 3] = (uint8_t)(block);

        uint8_t u[ACT_HMAC_SHA512_SIZE];
        uint8_t acc[ACT_HMAC_SHA512_SIZE];
        act_hmac_sha512(pass, pass_len, sblock, sl + 4, u);
        memcpy(acc, u, sizeof(acc));

        for (uint32_t i = 1; i < iterations; i++) {
            act_hmac_sha512(pass, pass_len, u, sizeof(u), u);
            for (int j = 0; j < ACT_HMAC_SHA512_SIZE; j++) {
                acc[j] ^= u[j];
            }
        }

        const size_t take = (out_len - done < sizeof(acc))
                                ? (out_len - done)
                                : sizeof(acc);
        memcpy(out + done, acc, take);
        done += take;
        block++;

        act_secure_wipe(u, sizeof(u));
        act_secure_wipe(acc, sizeof(acc));
    }
}
