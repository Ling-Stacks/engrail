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
 * @file  random.h
 * @brief Cryptographically secure random bytes sourced from the OS.
 *
 * Used only for key generation (never during verification, so the
 * activation path stays fully deterministic).
 */

#ifndef ACTIVATION_RANDOM_H
#define ACTIVATION_RANDOM_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Fill a buffer with cryptographically secure random bytes.
 *
 * Backends, in order of preference:
 *   - Windows:  ProcessPrng / BCryptGenRandom
 *   - POSIX:    getentropy(), else /dev/urandom
 *
 * Aborts the process (fail-closed) if no secure source is available --
 * silently weakened randomness would be catastrophic for key generation.
 *
 * @param buf destination buffer.
 * @param len number of bytes to generate.
 */
void act_random_bytes(uint8_t *buf, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* ACTIVATION_RANDOM_H */
