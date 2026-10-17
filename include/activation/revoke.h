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
 * @file  revoke.h
 * @brief Vendor-signed license revocation lists.
 *
 * Every activation code carries an 8-byte random serial. A vendor can
 * later invalidate specific serials (refund, chargeback, leaked key...)
 * by shipping a revocation file:
 *
 *   offset        size        field
 *   0             4           magic "ACTR"
 *   4             1           format version (0x01)
 *   5             4           entry count (big-endian uint32)
 *   9             8*count     serials, insertion order
 *   9+8*count     64          Ed25519 signature over bytes [0, 9+8*count)
 *
 * The client verifies the signature against the product public key, so
 * users cannot delete their serial from the list. Distribute updated
 * revocation files together with application updates -- verification is
 * fully offline.
 *
 * Community: https://t.me/Stack_Traces
 */

#ifndef ACTIVATION_REVOKE_H
#define ACTIVATION_REVOKE_H

#include "activation/license.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Atomically write a signed revocation list.
 *
 * @param path        destination file.
 * @param sk          vendor private key (#ACT_ED25519_PRIVKEY_SIZE).
 * @param serials     flat array of count*8 bytes (concatenated serials).
 * @param count       number of serials.
 * @return #ACT_OK or #ACT_ERR_ARG / #ACT_ERR_STATE_IO.
 */
act_status act_revoke_save(const char *path, const uint8_t sk[64],
                           const uint8_t *serials_flat, uint32_t count);

/**
 * @brief Load + verify a revocation list.
 *
 * @param path        revocation file path.
 * @param pk          vendor public key.
 * @param out_flat    output buffer for count*8 serial bytes (may be NULL
 *                    to just validate and query the count).
 * @param cap         capacity of @p out_flat in serials.
 * @param count_out   receives the verified entry count (may be NULL).
 * @return #ACT_OK, #ACT_ERR_SIGNATURE (bad list signature),
 *         #ACT_ERR_STATE_MISSING / _IO / _CORRUPT, or #ACT_ERR_ARG
 *         when the list does not fit into @p out_flat.
 */
act_status act_revoke_load(const char *path, const uint8_t pk[32],
                           uint8_t *out_flat, uint32_t cap,
                           uint32_t *count_out);

/**
 * @brief Append one serial to an existing signed list (load-merge-save).
 *
 * If the file does not exist yet, a fresh list is created.
 *
 * @param path    revocation file.
 * @param sk      vendor private key.
 * @param serial  8-byte serial to add.
 */
act_status act_revoke_add(const char *path, const uint8_t sk[64],
                          const uint8_t serial[ACT_SERIAL_SIZE]);

/** Constant-time containment test over a flat serial array. */
int act_revoke_contains(const uint8_t *serials_flat, uint32_t count,
                        const uint8_t serial[ACT_SERIAL_SIZE]);

/**
 * @brief Convenience: check whether the license identified by @p info
 *        is on a (verified) revocation list.
 * @return 1 if revoked, 0 if clean, negative #act_status on load failure.
 */
int act_revoke_check(const char *path, const uint8_t pk[32],
                     const act_license_info *info);

#ifdef __cplusplus
}
#endif

#endif /* ACTIVATION_REVOKE_H */
