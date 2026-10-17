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
 * @file  fingerprint.h
 * @brief Stable, privacy-preserving machine fingerprint.
 *
 * The fingerprint is a 16-byte value derived from a set of platform
 * hardware/OS identifiers through a three-round keyed cascade:
 *
 *   H1 = SHA512  ( domain || pubkey || product || sources )
 *   H2 = HMAC512 ( key = H1[0:32],  data = H1[32:64] || domain2 || sources )
 *   H3 = HMAC512 ( key = pubkey,    data = H2 || domain3 || H1[0:16] )
 *   machine_code = H3[0:16]
 *
 * Properties:
 *   - One-way: platform identifiers cannot be recovered from the code.
 *   - Product-bound: the product public key is mixed into every round, so
 *     codes are not comparable across vendors/products.
 *   - Stable on the same machine, different across machines -- which is
 *     what makes activation codes non-transferable.
 *
 * Platforms: Windows / Linux / macOS / Android / Termux / *BSD.
 */

#ifndef ACTIVATION_FINGERPRINT_H
#define ACTIVATION_FINGERPRINT_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Length of the resulting machine code in bytes. */
#define ACT_MACHINE_CODE_SIZE 16

/** Deployment salt size: a random, PUBLIC value generated once per
 * deployment and embedded next to the public key. It feeds every
 * runtime key derivation, so identical source code deployed twice still
 * yields disjoint key spaces ("templates cannot replicate keys"). */
#define ACT_DSALT_SIZE 32

/** Buffer size for act_fp_to_string() (32 hex + dash + NUL = 34). */
#define ACT_MACHINE_CODE_STR_SIZE 34

/**
 * @brief Maximum number of collected source strings.
 * @internal
 */
#define ACT_FP_MAX_SOURCES 16

/**
 * @brief Collected platform identifier strings.
 *
 * `sources` is a NULL-terminated array of NUL-terminated UTF-8 strings;
 * ordering is fixed by the collector, never by the environment.
 */
typedef struct act_fp_sources {
    const char *sources[ACT_FP_MAX_SOURCES];
    int count;
} act_fp_sources;

/**
 * @brief Collect platform identifiers for the current machine.
 *
 * Everything is best-effort: a missing source is simply skipped. The
 * remaining sources are still sufficient in practice (hostname, OS,
 * machine-id/GUID, CPU info, user name...).
 *
 * @param out populated with collected sources (not allocated; the strings
 *            point either to static storage or to buffers owned by @p out).
 * @param scratch caller-provided scratch buffer used for dynamic values.
 * @param scratch_len size of @p scratch (>= 2048 bytes recommended).
 */
void act_fp_collect(act_fp_sources *out, char *scratch, size_t scratch_len);

/**
 * @brief Derive the per-purpose runtime keys for a deployment.
 *
 * HKDF-SHA512 over (ikm = pubkey, salt = dsalt, info = purpose). This is
 * the ONLY place secret structure exists at runtime, and its inputs are
 * per-deployment values -- the code itself carries no secrets.
 *
 * @param pubkey     vendor public key (32 bytes).
 * @param dsalt      deployment salt (32 bytes).
 * @param fp_key     output: fingerprint-cascade key (32 bytes).
 * @param token_key  output: offline-token binding key (32 bytes).
 * @param session_key output: session/auxiliary key (32 bytes).
 */
void act_deployment_keys(const uint8_t pubkey[32],
                         const uint8_t dsalt[ACT_DSALT_SIZE],
                         uint8_t fp_key[32],
                         uint8_t token_key[32],
                         uint8_t session_key[32]);

/**
 * @brief Compute the 16-byte machine code from explicit sources.
 *
 * @param fp_key     fingerprint key from act_deployment_keys().
 * @param product_id 32-bit product identifier.
 * @param salt       optional extra device entropy provided by the
 *                   application (e.g. an ANDROID_ID); may be NULL.
 * @param salt_len   length of @p salt.
 * @param src        sources as returned by act_fp_collect().
 * @param out16      output machine code, #ACT_MACHINE_CODE_SIZE bytes.
 */
void act_fp_compute(const uint8_t fp_key[32], uint32_t product_id,
                    const uint8_t *salt, size_t salt_len,
                    const act_fp_sources *src,
                    uint8_t out16[ACT_MACHINE_CODE_SIZE]);

/**
 * @brief Convenience wrapper: derive keys + collect + compute in one call.
 *
 * @param pubkey     vendor public key.
 * @param dsalt      deployment salt.
 * @param product_id product identifier.
 * @param salt       optional app-provided entropy (may be NULL).
 * @param salt_len   length of @p salt.
 * @param out16      output machine code.
 */
void act_fingerprint(const uint8_t pubkey[32],
                     const uint8_t dsalt[ACT_DSALT_SIZE],
                     uint32_t product_id,
                     const uint8_t *salt, size_t salt_len,
                     uint8_t out16[ACT_MACHINE_CODE_SIZE]);

/**
 * @brief Render a machine code as "XXXXXXXXXXXXXXXX-XXXXXXXXXXXXXXXX".
 * @param code16 16-byte machine code.
 * @param buf    output buffer, at least #ACT_MACHINE_CODE_STR_SIZE bytes.
 */
void act_fp_to_string(const uint8_t code16[ACT_MACHINE_CODE_SIZE],
                      char buf[ACT_MACHINE_CODE_STR_SIZE]);

#ifdef __cplusplus
}
#endif

#endif /* ACTIVATION_FINGERPRINT_H */
