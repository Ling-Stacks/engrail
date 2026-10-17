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
 * @file  sm2.h
 * @brief SM2 public-key cryptography (GB/T 32918) over the standard
 *        sm2p256v1 curve: key pairs, digital signatures (part 2),
 *        public-key encryption / decryption (part 4, C1C3C2 encoding).
 *
 * Security model notes
 * - The only curve material in this file is the *published standard
 *   parameters* (p, a, b, n, G). All Montgomery-domain bookkeeping
 *   constants (R, R^2, -m^-1 mod 2^32, exponent m-2) are derived at
 *   runtime -- zero magic numbers, zero secrets in code.
 * - Scalar multiplication uses a constant-time conditional-swap ladder;
 *   per-iteration work is independent of secret scalar bits.
 * - Signatures and KDFs use SM3 (GB/T 32905).
 * - Encryption is C1C3C2 (G/T 32918.4-2016 order), with ephemeral keys
 *   from the OS CSPRNG.
 *
 * Community: https://t.me/Stack_Traces
 */

#ifndef ACTIVATION_SM2_H
#define ACTIVATION_SM2_H

#include "activation/license.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define ACT_SM2_PRIV_SIZE 32   /**< private key bytes                   */
#define ACT_SM2_PUB_SIZE  64   /**< public key: x||y (uncompressed)     */
#define ACT_SM2_SIG_SIZE  64   /**< signature: r||s                     */
#define ACT_SM2_ID_MAX    32   /**< max signer ID bytes (default 16)    */

/** Default signer ID per GB/T 32918.2 ("1234567812345678"). */
#define ACT_SM2_DEFAULT_ID "1234567812345678"

/**
 * @brief Generate an SM2 key pair.
 *
 * @param seed optional 32-byte seed; when NULL a random one is drawn.
 *             The seed IS the private key (clamped only by range checks).
 * @param pub  output public key (x||y, big-endian, 64 bytes).
 * @param priv output private key (32 bytes, big-endian).
 */
void act_sm2_keypair(uint8_t seed[ACT_SM2_PRIV_SIZE],
                     uint8_t pub[ACT_SM2_PUB_SIZE],
                     uint8_t priv[ACT_SM2_PRIV_SIZE]);

/**
 * @brief Derive an SM2 key pair from an Ed25519 seed (dual-stack keys).
 *
 * One vendor secret -> two stacks:
 *   sm2_priv = SHA512(ed25519_seed || "act-dual/sm2/v1")[0..31] reduced mod n
 * With #ACT_DUAL_INFO you can derive independent key sets per purpose
 * from the same seed. Ed25519 keys come from the seed directly, so a
 * single offline backup covers both algorithms (dual-compliance
 * deployments: SM2 for GB/T markets, Ed25519 everywhere else).
 */
void act_sm2_keypair_from_ed25519_seed(const uint8_t ed_seed[32],
                                       const char *info,
                                       uint8_t pub[ACT_SM2_PUB_SIZE],
                                       uint8_t priv[ACT_SM2_PRIV_SIZE]);

/**
 * @brief SM2 digital signature (GB/T 32918.2-2016).
 *
 * @param sig   output r||s (64 bytes).
 * @param msg   message to sign (hashed internally with Z_A || SM3).
 * @param len   message length.
 * @param priv  private key.
 * @param id    signer ID (NULL => #ACT_SM2_DEFAULT_ID).
 * @return #ACT_OK or #ACT_ERR_ARG.
 */
act_status act_sm2_sign(uint8_t sig[ACT_SM2_SIG_SIZE],
                        const uint8_t *msg, size_t len,
                        const uint8_t priv[ACT_SM2_PRIV_SIZE],
                        const char *id);

/**
 * @brief Verify an SM2 signature (constant-time comparison).
 * @return #ACT_OK when valid; #ACT_ERR_SIGNATURE otherwise.
 */
act_status act_sm2_verify(const uint8_t sig[ACT_SM2_SIG_SIZE],
                          const uint8_t *msg, size_t len,
                          const uint8_t pub[ACT_SM2_PUB_SIZE],
                          const char *id);

/**
 * @brief SM2 public-key encryption (GB/T 32918.4-2016, C1C3C2).
 *
 * Output layout: C1(65, uncompressed point with 0x04 prefix) || C3(32,
 * SM3 tag) || C2(klen, XOR-masked message). Total = 97 + len.
 *
 * @param pub      recipient public key (64 bytes).
 * @param msg      plaintext.
 * @param len      plaintext length.
 * @param out      output buffer.
 * @param out_cap  capacity (>= len + 97).
 * @param out_len  receives the ciphertext length.
 * @return #ACT_OK or #ACT_ERR_ARG / #ACT_ERR_STATE_IO on CSPRNG failure.
 */
act_status act_sm2_encrypt(const uint8_t pub[ACT_SM2_PUB_SIZE],
                           const uint8_t *msg, size_t len,
                           uint8_t *out, size_t out_cap, size_t *out_len);

/**
 * @brief SM2 decryption. Authenticates via the embedded C3 tag.
 *
 * @param in       ciphertext (C1C3C2).
 * @param in_len   ciphertext length (>= 98).
 * @param priv     private key.
 * @param out      output buffer (>= in_len - 97).
 * @param out_cap  capacity.
 * @param out_len  receives plaintext length.
 * @return #ACT_OK; #ACT_ERR_FORMAT on malformed input;
 *         #ACT_ERR_SIGNATURE when the C3 tag mismatches (wrong key or
 *         tampered ciphertext).
 */
act_status act_sm2_decrypt(const uint8_t *in, size_t in_len,
                           const uint8_t priv[ACT_SM2_PRIV_SIZE],
                           uint8_t *out, size_t out_cap, size_t *out_len);

#ifdef __cplusplus
}
#endif

#endif /* ACTIVATION_SM2_H */
