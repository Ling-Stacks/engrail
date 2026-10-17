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
 * @file  sha512.h
 * @brief SHA-512 message digest (FIPS 180-4) -- dependency-free C implementation.
 *
 * Used as the core one-way primitive of the activation system:
 *   - machine fingerprint derivation (multi-round cascaded hashing)
 *   - HMAC-SHA512 key derivation
 *   - Ed25519 internal hashing
 *
 * The implementation is conservative C99, has no external dependencies and
 * works on both 32-bit and 64-bit platforms (all arithmetic is done on
 * uint64_t, no native word-size assumptions).
 */

#ifndef ACTIVATION_SHA512_H
#define ACTIVATION_SHA512_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Size (in bytes) of a SHA-512 digest. */
#define ACT_SHA512_DIGEST_SIZE 64
/** Size (in bytes) of a SHA-512 input block. */
#define ACT_SHA512_BLOCK_SIZE  128

/** Incremental SHA-512 hashing context. */
typedef struct act_sha512_ctx {
    uint64_t state[8];                  /**< intermediate hash state (8 x 64-bit words) */
    uint64_t bitlen_total;              /**< total number of processed bits (low 64) */
    uint8_t  buffer[ACT_SHA512_BLOCK_SIZE]; /**< pending input bytes */
    size_t   buffer_len;                /**< number of valid bytes in @p buffer */
} act_sha512_ctx;

/**
 * @brief Initialize a SHA-512 context.
 * @param ctx context to initialize (must not be NULL).
 */
void act_sha512_init(act_sha512_ctx *ctx);

/**
 * @brief Feed data into the running hash.
 * @param ctx  initialized context.
 * @param data input bytes (may be NULL iff @p len == 0).
 * @param len  number of bytes to process.
 */
void act_sha512_update(act_sha512_ctx *ctx, const void *data, size_t len);

/**
 * @brief Finalize the hash and write the 64-byte digest.
 *
 * The context is reset to the initial state afterwards, so the same ctx
 * can be safely reused for a new message.
 *
 * @param ctx    context.
 * @param digest output buffer, at least #ACT_SHA512_DIGEST_SIZE bytes.
 */
void act_sha512_final(act_sha512_ctx *ctx, uint8_t digest[ACT_SHA512_DIGEST_SIZE]);

/**
 * @brief One-shot SHA-512 helper.
 * @param data   input bytes.
 * @param len    input length in bytes.
 * @param digest output buffer, at least #ACT_SHA512_DIGEST_SIZE bytes.
 */
void act_sha512(const void *data, size_t len, uint8_t digest[ACT_SHA512_DIGEST_SIZE]);

/**
 * @brief Constant-time memory comparison (length-limited memcmp).
 *
 * Returns 0 only when the two buffers are equal. Timing does not depend on
 * where the first difference occurs -- important when comparing signatures.
 *
 * @param a   first buffer.
 * @param b   second buffer.
 * @param len number of bytes to compare.
 * @return 0 if equal, non-zero otherwise.
 */
int act_secure_memcmp(const void *a, const void *b, size_t len);

/**
 * @brief Overwrite a memory region with zeros in a way the optimizer
 *        cannot remove (defense against key material lingering in RAM).
 * @param dst target buffer.
 * @param len number of bytes to wipe.
 */
void act_secure_wipe(void *dst, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* ACTIVATION_SHA512_H */
