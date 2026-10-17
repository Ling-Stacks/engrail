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
 * @file  sm3.h
 * @brief SM3 cryptographic hash (GB/T 32905-2016), 256-bit digest.
 *
 * The hash behind SM2 signatures and SM2 key-encryption. Validated
 * against the standard's test vectors and an independent reference
 * implementation. API mirrors sha512.h.
 */

#ifndef ACTIVATION_SM3_H
#define ACTIVATION_SM3_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define ACT_SM3_DIGEST_SIZE 32
#define ACT_SM3_BLOCK_SIZE  64

typedef struct act_sm3_ctx {
    uint32_t state[8];
    uint64_t bitlen_total;
    uint8_t  buffer[ACT_SM3_BLOCK_SIZE];
    size_t   buffer_len;
} act_sm3_ctx;

void act_sm3_init(act_sm3_ctx *ctx);
void act_sm3_update(act_sm3_ctx *ctx, const void *data, size_t len);
void act_sm3_final(act_sm3_ctx *ctx, uint8_t digest[ACT_SM3_DIGEST_SIZE]);
void act_sm3(const void *data, size_t len, uint8_t digest[ACT_SM3_DIGEST_SIZE]);

#ifdef __cplusplus
}
#endif

#endif /* ACTIVATION_SM3_H */
