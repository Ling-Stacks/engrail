/*
 * MIT License
 *
 * Copyright (c) 2026 Engrail Contributors
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
 * @file  bench.c
 * @brief Standalone benchmark for the Engrail Crypto single-file library.
 *
 * Fixed iteration counts (not auto-calibrated) so results are directly
 * comparable across machines and runs. Timing: CLOCK_MONOTONIC where
 * available, clock() fallback elsewhere (CPU time).
 *
 * Usage:  ./bench [--json]
 *
 * Report new numbers via docs/BENCHMARKS.md -- never hand-edit tables
 * from memory; paste actual output.
 */

#include "engrail_crypto.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(_WIN32)
#  include <time.h>
#else
#  include <time.h>
#endif

static double now_ms(void)
{
#if defined(CLOCK_MONOTONIC)
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000.0 + ts.tv_nsec / 1e6;
#else
    return (double)clock() * 1000.0 / CLOCKS_PER_SEC;
#endif
}

static int g_json = 0;

static void report(const char *op, uint32_t iters, double ms)
{
    if (g_json) {
        printf("{\"op\":\"%s\",\"iters\":%u,\"total_ms\":%.3f,"
               "\"us_per_op\":%.3f}\n", op, iters, ms, ms * 1000.0 / iters);
    } else {
        printf("%-28s %10u iters %10.1f ms %10.3f us/op\n",
               op, iters, ms, ms * 1000.0 / iters);
    }
}

#define BENCH(name, iters, setup, body)                                    \
    do {                                                                   \
        setup;                                                             \
        double t0 = now_ms();                                              \
        for (uint32_t i_ = 0; i_ < (iters); i_++) { body; }                \
        report(name, iters, now_ms() - t0);                                \
    } while (0)

int main(int argc, char **argv)
{
    g_json = (argc > 1 && strcmp(argv[1], "--json") == 0);

    static uint8_t buf_1m[1 << 20];
    static uint8_t small[64];
    for (size_t i = 0; i < sizeof(small); i++) small[i] = (uint8_t)(i * 7);
    for (size_t i = 0; i < sizeof(buf_1m); i++) buf_1m[i] = (uint8_t)(i * 13);

    uint8_t ed_seed[32], ed_pk[32], ed_sk[64], ed_sig[64];
    for (int i = 0; i < 32; i++) ed_seed[i] = (uint8_t)(i + 1);
    act_ed25519_keypair(ed_seed, ed_pk, ed_sk);
    act_ed25519_sign(ed_sig, small, sizeof(small), ed_sk);

    uint8_t sm_pub[64], sm_priv[32], sm_sig[64];
    act_sm2_keypair(ed_seed, sm_pub, sm_priv);
    act_sm2_sign(sm_sig, small, sizeof(small), sm_priv, NULL);
    uint8_t sm_ct[161];
    size_t sm_ctlen = 0;
    act_sm2_encrypt(sm_pub, small, 32, sm_ct, sizeof(sm_ct), &sm_ctlen);

    uint8_t out[64];
    uint8_t nonce[12] = { 0, 0, 0, 9, 0, 0, 0, 0x4a, 0, 0, 0, 0 };
    uint8_t key[32];
    for (int i = 0; i < 32; i++) key[i] = (uint8_t)i;
    uint8_t ct1m[1 << 20];

    if (!g_json) {
        printf("%-28s %10s %12s %13s\n", "operation", "iters", "total", "per-op");
        printf("%-28s %10s %12s %13s\n", "------------------------",
               "------", "------", "-------");
    }

    BENCH("sha512/64B", 200000, ,
          act_sha512(small, 64, out));
    BENCH("sha512/1MiB", 200, ,
          act_sha512(buf_1m, sizeof(buf_1m), out));
    BENCH("sm3/64B", 200000, ,
          act_sm3(small, 64, out));
    BENCH("hmac-sha512/64B", 100000, ,
          act_hmac_sha512(key, 32, small, 64, out));
    BENCH("chacha20/1MiB", 200,
          memcpy(ct1m, buf_1m, sizeof(ct1m)),
          act_chacha20_xor(key, nonce, 1, ct1m, sizeof(ct1m)));
    BENCH("hkdf-sha512/32B", 5000, ,
          act_hkdf_sha512(key, 32, small, 64, NULL, 0, out, 32));
    BENCH("pbkdf2/4096iters", 3, ,
          act_pbkdf2_hmac_sha512(small, 8, key, 16, 4096, out, 32));

    BENCH("ed25519/keypair", 200, ,
          act_ed25519_keypair(ed_seed, ed_pk, ed_sk));
    BENCH("ed25519/sign/64B", 200, ,
          act_ed25519_sign(ed_sig, small, 64, ed_sk));
    BENCH("ed25519/verify/64B", 200, ,
          (void)act_ed25519_verify(ed_sig, small, 64, ed_pk));

    BENCH("sm2/keypair", 200, ,
          act_sm2_keypair(ed_seed, sm_pub, sm_priv));
    BENCH("sm2/sign/64B", 200, ,
          act_sm2_sign(sm_sig, small, 64, sm_priv, NULL));
    BENCH("sm2/verify/64B", 200, ,
          (void)act_sm2_verify(sm_sig, small, 64, sm_pub, NULL));
    BENCH("sm2/encrypt/32B", 200, ,
          act_sm2_encrypt(sm_pub, small, 32, sm_ct, sizeof(sm_ct), &sm_ctlen));
    {
        uint8_t pt[64];
        BENCH("sm2/decrypt/64B", 200, ,
              (void)act_sm2_decrypt(sm_ct, sm_ctlen, sm_priv, pt,
                                    sizeof(pt), NULL));
    }

    if (!g_json) {
        printf("\nbench: DONE (fixed iters; compare like-for-like)\n");
    }
    return 0;
}
