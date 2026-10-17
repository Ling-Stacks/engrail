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
 * @file  chacha20.h
 * @brief ChaCha20 stream cipher (RFC 8439).
 *
 * Used to encrypt the vendor seed at rest (keyfile): PBKDF2-HMAC-SHA512
 * derives the encryption key from a passphrase, ChaCha20 encrypts, and
 * HMAC-SHA512 authenticates (encrypt-then-MAC). See keyfile.h.
 */

#ifndef ACTIVATION_CHACHA20_H
#define ACTIVATION_CHACHA20_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** ChaCha20 key size in bytes. */
#define ACT_CHACHA20_KEY_SIZE 32
/** ChaCha20 nonce size in bytes (RFC 8439). */
#define ACT_CHACHA20_NONCE_SIZE 12

/**
 * @brief Encrypt/decrypt (XOR keystream) in place.
 *
 * @param key        32-byte key.
 * @param nonce      12-byte nonce (unique per message under the same key!).
 * @param counter    initial block counter (0 for fresh messages).
 * @param data       in-place buffer.
 * @param len        data length.
 */
void act_chacha20_xor(const uint8_t key[ACT_CHACHA20_KEY_SIZE],
                      const uint8_t nonce[ACT_CHACHA20_NONCE_SIZE],
                      uint32_t counter,
                      uint8_t *data, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* ACTIVATION_CHACHA20_H */
