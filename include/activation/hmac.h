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
 * @file  hmac.h
 * @brief HMAC-SHA512 (RFC 2104 / FIPS 198-1) keyed message authentication.
 *
 * Used for domain-separated derivation of machine fingerprints: the product
 * public key serves as the MAC key, so fingerprints are product-specific and
 * cannot be precomputed for other products or replayed between vendors.
 */

#ifndef ACTIVATION_HMAC_H
#define ACTIVATION_HMAC_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** HMAC-SHA512 output length in bytes (same as SHA-512). */
#define ACT_HMAC_SHA512_SIZE 64

/**
 * @brief One-shot HMAC-SHA512.
 *
 * @param key    MAC key (recommended >= 32 bytes of entropy).
 * @param keylen key length in bytes (any, incl. 0).
 * @param data   message to authenticate.
 * @param len    message length in bytes.
 * @param mac    output buffer, #ACT_HMAC_SHA512_SIZE bytes.
 */
void act_hmac_sha512(const uint8_t *key, size_t keylen,
                     const void *data, size_t len,
                     uint8_t mac[ACT_HMAC_SHA512_SIZE]);

/**
 * @brief Streaming variant: authenticate two message chunks in sequence.
 *
 * Computes HMAC over (data1 || data2) without materialising the
 * concatenation -- handy for header/body-style inputs.
 */
void act_hmac_sha512_2(const uint8_t *key, size_t keylen,
                       const void *data1, size_t len1,
                       const void *data2, size_t len2,
                       uint8_t mac[ACT_HMAC_SHA512_SIZE]);

#ifdef __cplusplus
}
#endif

#endif /* ACTIVATION_HMAC_H */
