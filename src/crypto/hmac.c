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
 * @file  hmac.c
 * @brief HMAC-SHA512. See hmac.h for documentation.
 */

#include "activation/hmac.h"
#include "activation/sha512.h"

#include <string.h>

void act_hmac_sha512(const uint8_t *key, size_t keylen,
                     const void *data, size_t len,
                     uint8_t mac[ACT_HMAC_SHA512_SIZE])
{
    act_sha512_ctx ctx;
    uint8_t k[ACT_SHA512_BLOCK_SIZE]; /* padded key */
    uint8_t pad[ACT_SHA512_BLOCK_SIZE];
    uint8_t khash[ACT_SHA512_DIGEST_SIZE];
    size_t i;

    /* Keys longer than the block size are replaced by H(key). */
    memset(k, 0, sizeof(k));
    if (keylen > ACT_SHA512_BLOCK_SIZE) {
        act_sha512(key, keylen, khash);
        memcpy(k, khash, ACT_SHA512_DIGEST_SIZE);
    } else if (keylen > 0) {
        memcpy(k, key, keylen);
    }

    /* ipad / opad construction (RFC 2104):
     *   inner = H(K xor ipad || data)      ipad = 0x36...
     *   mac   = H(K xor opad || inner)     opad = 0x5c... */
    for (i = 0; i < ACT_SHA512_BLOCK_SIZE; i++) {
        pad[i] = (uint8_t)(k[i] ^ 0x36); /* ipad for the inner hash */
    }

    act_sha512_init(&ctx);
    act_sha512_update(&ctx, pad, ACT_SHA512_BLOCK_SIZE);
    act_sha512_update(&ctx, data, len);
    act_sha512_final(&ctx, mac);

    for (i = 0; i < ACT_SHA512_BLOCK_SIZE; i++) {
        pad[i] = (uint8_t)(k[i] ^ 0x5c); /* opad for the outer hash */
    }

    act_sha512_init(&ctx);
    act_sha512_update(&ctx, pad, ACT_SHA512_BLOCK_SIZE);
    act_sha512_update(&ctx, mac, ACT_SHA512_DIGEST_SIZE);
    act_sha512_final(&ctx, mac);

    act_secure_wipe(k, sizeof(k));
    act_secure_wipe(pad, sizeof(pad));
    act_secure_wipe(khash, sizeof(khash));
}

void act_hmac_sha512_2(const uint8_t *key, size_t keylen,
                       const void *data1, size_t len1,
                       const void *data2, size_t len2,
                       uint8_t mac[ACT_HMAC_SHA512_SIZE])
{
    act_sha512_ctx ctx;
    uint8_t k[ACT_SHA512_BLOCK_SIZE];
    uint8_t pad[ACT_SHA512_BLOCK_SIZE];
    uint8_t khash[ACT_SHA512_DIGEST_SIZE];
    uint8_t inner[ACT_SHA512_DIGEST_SIZE];
    size_t i;

    memset(k, 0, sizeof(k));
    if (keylen > ACT_SHA512_BLOCK_SIZE) {
        act_sha512(key, keylen, khash);
        memcpy(k, khash, ACT_SHA512_DIGEST_SIZE);
    } else if (keylen > 0) {
        memcpy(k, key, keylen);
    }

    for (i = 0; i < ACT_SHA512_BLOCK_SIZE; i++) {
        pad[i] = (uint8_t)(k[i] ^ 0x36); /* ipad for the inner hash */
    }

    act_sha512_init(&ctx);
    act_sha512_update(&ctx, pad, ACT_SHA512_BLOCK_SIZE);
    act_sha512_update(&ctx, data1, len1);
    act_sha512_update(&ctx, data2, len2);
    act_sha512_final(&ctx, inner);

    for (i = 0; i < ACT_SHA512_BLOCK_SIZE; i++) {
        pad[i] = (uint8_t)(k[i] ^ 0x5c); /* opad for the outer hash */
    }

    act_sha512_init(&ctx);
    act_sha512_update(&ctx, pad, ACT_SHA512_BLOCK_SIZE);
    act_sha512_update(&ctx, inner, ACT_SHA512_DIGEST_SIZE);
    act_sha512_final(&ctx, mac);

    act_secure_wipe(k, sizeof(k));
    act_secure_wipe(pad, sizeof(pad));
    act_secure_wipe(khash, sizeof(khash));
    act_secure_wipe(inner, sizeof(inner));
}
