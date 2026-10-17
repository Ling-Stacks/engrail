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
 * @file  ed25519.h
 * @brief Ed25519 digital signatures (RFC 8032) -- dependency-free C implementation.
 *
 * This is the anti-forgery foundation of the activation system:
 *   - The vendor signs every activation code with the Ed25519 **private key**.
 *   - Only the 32-byte **public key** is shipped inside the application.
 *   - Producing a code that passes verification is computationally
 *     infeasible without the private key (discrete-log hardness on Curve25519),
 *     and any single-bit modification of a code invalidates its signature.
 *
 * Signatures are deterministic (RFC 8032) and wire-compatible with standard
 * Ed25519 implementations.
 *
 * Arithmetic operates on GF(2^255 - 19) using 16 limbs of 16 bits, which is
 * safe on both 32-bit and 64-bit targets (no 128-bit compiler extension
 * required) -- hence fully cross-platform.
 */

#ifndef ACTIVATION_ED25519_H
#define ACTIVATION_ED25519_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Ed25519 signature length in bytes. */
#define ACT_ED25519_SIG_SIZE    64
/** Ed25519 public key length in bytes. */
#define ACT_ED25519_PUBKEY_SIZE 32
/** Ed25519 private key length in bytes (32-byte seed + 32-byte public key). */
#define ACT_ED25519_PRIVKEY_SIZE 64
/** Ed25519 seed length in bytes. */
#define ACT_ED25519_SEED_SIZE   32

/**
 * @brief Derive an Ed25519 key pair from a 32-byte seed.
 *
 * If @p seed is NULL, the seed is filled from the OS CSPRNG (see
 * random.h). The 32-byte seed is the actual secret; the remaining 32
 * bytes of the private key are just a cached copy of the public key.
 *
 * @param[out] seed optional output buffer for the generated/used seed
 *                  (may be NULL if caller passes its own seed).
 * @param[out] pk   public key, #ACT_ED25519_PUBKEY_SIZE bytes.
 * @param[out] sk   private key, #ACT_ED25519_PRIVKEY_SIZE bytes.
 */
void act_ed25519_keypair(uint8_t seed[ACT_ED25519_SEED_SIZE],
                         uint8_t pk[ACT_ED25519_PUBKEY_SIZE],
                         uint8_t sk[ACT_ED25519_PRIVKEY_SIZE]);

/**
 * @brief Create a deterministic Ed25519 signature over a message.
 *
 * @param[out] sig  output signature, #ACT_ED25519_SIG_SIZE bytes.
 * @param[in]  msg  message to sign.
 * @param[in]  mlen message length in bytes.
 * @param[in]  sk   private key, #ACT_ED25519_PRIVKEY_SIZE bytes.
 */
void act_ed25519_sign(uint8_t sig[ACT_ED25519_SIG_SIZE],
                      const uint8_t *msg, size_t mlen,
                      const uint8_t sk[ACT_ED25519_PRIVKEY_SIZE]);

/**
 * @brief Verify an Ed25519 signature in constant time.
 *
 * Rejects non-canonical signatures (scalar not reduced mod L) and
 * non-canonical / invalid public keys.
 *
 * @param[in] sig  signature, #ACT_ED25519_SIG_SIZE bytes.
 * @param[in] msg  signed message.
 * @param[in] mlen message length in bytes.
 * @param[in] pk   public key, #ACT_ED25519_PUBKEY_SIZE bytes.
 * @return 0 if the signature is valid, -1 otherwise.
 */
int act_ed25519_verify(const uint8_t sig[ACT_ED25519_SIG_SIZE],
                       const uint8_t *msg, size_t mlen,
                       const uint8_t pk[ACT_ED25519_PUBKEY_SIZE]);

#ifdef __cplusplus
}
#endif

#endif /* ACTIVATION_ED25519_H */
