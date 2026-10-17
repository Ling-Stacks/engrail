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
 * @file  keyfile.h
 * @brief Passphrase-encrypted storage for the vendor signing seed.
 *
 * Format "ACTKEY2" (112 bytes):
 *
 *   offset  size  field
 *   0       7     magic "ACTKEY2"
 *   7       1     format version (0x02)
 *   8       16    PBKDF2 salt (random)
 *   24      4     PBKDF2 iterations, big-endian
 *   28      32    deployment salt (public, random, unique per deployment)
 *   60      12    ChaCha20 nonce (random)
 *   72      32    ChaCha20(seed)          -- ciphertext
 *   104     8     HMAC-SHA512(mac_key, ...) truncated to 64 bits
 *
 * Keys come from PBKDF2-HMAC-SHA512(passphrase, salt, iters, 64):
 *   enc_key = dk[0:32], mac_key = dk[32:64]
 * Encrypt-then-MAC: the MAC covers the entire header + ciphertext, and a
 * wrong passphrase / tampered file fails *before* decryption.
 *
 * Consequence for the threat model: stealing the key FILE reveals
 * nothing without the passphrase, and the passphrase never exists in
 * source, templates or constants.
 */

#ifndef ACTIVATION_KEYFILE_H
#define ACTIVATION_KEYFILE_H

#include "activation/license.h"

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** On-disk size of an encrypted key file. */
#define ACT_KEYFILE_SIZE 112
/** Deployment salt size (public, per-deployment). */
#define ACT_DSALT_SIZE 32
/** Recommended PBKDF2 iteration count for offline keys. */
#define ACT_KEYFILE_KDF_ITERS 200000u

/**
 * @brief Write an encrypted key file.
 *
 * @param path        destination path.
 * @param seed        32-byte vendor seed.
 * @param dsalt       32-byte deployment salt (public; generate randomly
 *                    once per deployment via act_random_bytes).
 * @param passphrase  NUL-terminated passphrase (NULL = empty).
 * @param iterations  PBKDF2 work factor (0 => #ACT_KEYFILE_KDF_ITERS).
 */
act_status act_keyfile_save(const char *path,
                            const uint8_t seed[32],
                            const uint8_t dsalt[ACT_DSALT_SIZE],
                            const char *passphrase,
                            uint32_t iterations);

/**
 * @brief Read + authenticate + decrypt a key file.
 *
 * @param path        key file path.
 * @param passphrase  passphrase (NULL = empty).
 * @param out_seed    recovered 32-byte seed.
 * @param out_dsalt   recovered deployment salt (may be NULL).
 * @return #ACT_OK; #ACT_ERR_SIGNATURE on wrong passphrase or tampering;
 *         #ACT_ERR_STATE_MISSING / _IO / _CORRUPT / #ACT_ERR_ARG otherwise.
 */
act_status act_keyfile_load(const char *path, const char *passphrase,
                            uint8_t out_seed[32],
                            uint8_t out_dsalt[ACT_DSALT_SIZE]);

#ifdef __cplusplus
}
#endif

#endif /* ACTIVATION_KEYFILE_H */
