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
 * @file  kdf.h
 * @brief Key-derivation primitives: HKDF-SHA512 (RFC 5869) and
 *        PBKDF2-HMAC-SHA512 (RFC 8018).
 *
 * Role in the security model ("no constants can replicate keys")
 * Every derived key used at runtime (fingerprint binding, state-file
 * binding, token authentication, key-file encryption) is expanded from
 * (vendor public key, per-deployment random salt, purpose string) via
 * HKDF. The *source code contains zero secret material*: all of its
 * constants are public domain separators. Two deployments built from the
 * identical source produce disjoint key spaces, and knowing every
 * constant still leaves an attacker with exactly the Ed25519
 * discrete-log problem.
 */

#ifndef ACTIVATION_KDF_H
#define ACTIVATION_KDF_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief HKDF-SHA512 extract step: PRK = HMAC-SHA512(salt, IKM).
 *
 * A salt of NULL/0 is treated as the RFC-recommended hashlen zeros.
 *
 * @param salt      optional salt.
 * @param salt_len  salt length.
 * @param ikm       input key material.
 * @param ikm_len   input key material length.
 * @param prk       output pseudo-random key (64 bytes).
 */
void act_hkdf_extract(const uint8_t *salt, size_t salt_len,
                      const uint8_t *ikm, size_t ikm_len,
                      uint8_t prk[64]);

/**
 * @brief HKDF-SHA512 expand step: derive @p out_len bytes from @p prk.
 *
 * @param prk       pseudo-random key (64 bytes, from act_hkdf_extract).
 * @param info      optional context/purpose string (may be NULL).
 * @param info_len  length of @p info.
 * @param out       output key material.
 * @param out_len   desired length (<= 255 * 64 bytes).
 * @return 0 on success, -1 when out_len exceeds the HKDF maximum.
 */
int act_hkdf_expand(const uint8_t prk[64],
                    const uint8_t *info, size_t info_len,
                    uint8_t *out, size_t out_len);

/**
 * @brief One-shot HKDF-SHA512 (extract + expand).
 */
int act_hkdf_sha512(const uint8_t *salt, size_t salt_len,
                    const uint8_t *ikm, size_t ikm_len,
                    const uint8_t *info, size_t info_len,
                    uint8_t *out, size_t out_len);

/**
 * @brief PBKDF2-HMAC-SHA512 (RFC 8018) for passphrase-based keys.
 *
 * @param pass       passphrase bytes (may be NULL when pass_len == 0).
 * @param pass_len   passphrase length.
 * @param salt       salt (draw from act_random_bytes, >= 16 bytes).
 * @param salt_len   salt length.
 * @param iterations work factor (>= 100000 recommended for offline keys).
 * @param out        output key buffer.
 * @param out_len    desired key length.
 */
void act_pbkdf2_hmac_sha512(const uint8_t *pass, size_t pass_len,
                            const uint8_t *salt, size_t salt_len,
                            uint32_t iterations,
                            uint8_t *out, size_t out_len);

#ifdef __cplusplus
}
#endif

#endif /* ACTIVATION_KDF_H */
