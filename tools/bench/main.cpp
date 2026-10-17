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
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

/**
 * @file  main.cpp
 * @brief engrail-bench -- indicative performance reference numbers.
 *
 * Reports wall-clock timings for the primitives applications gate on.
 * Informational only; run on your target hardware for real planning.
 *
 * Community: https://t.me/Stack_Traces
 */

#include "activation/ed25519.h"
#include "activation/hmac.h"
#include "activation/sha512.h"
#include "activation/kdf.h"
#include "activation/sm2.h"
#include "activation/sm3.h"
#include "activation/version.h"

#include <ctime>
#include <cstdio>

namespace {

struct Ctx {
    uint8_t seed[32], pk[32], sk[64];
    uint8_t msg[64];
    uint8_t sig[64];
    uint8_t sm2pub[64], sm2priv[32], sm2sig[64];
    uint8_t ct[97 + 32];
    uint8_t out[128];
};

double now_sec()
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec * 1e-9;
}

void bench(const char *name, int iters, void (*fn)(Ctx *), Ctx *c)
{
    fn(c); /* warm-up */
    const double t0 = now_sec();
    for (int i = 0; i < iters; i++) {
        fn(c);
    }
    const double dt = (now_sec() - t0) / iters;
    std::printf("  %-30s %10.2f us/op\n", name, dt * 1e6);
}

void b_sha512(Ctx *c) { act_sha512(c->msg, 64, c->out); }
void b_sm3(Ctx *c) { act_sm3(c->msg, 64, c->out); }
void b_hmac(Ctx *c) { act_hmac_sha512(c->sk, 32, c->msg, 64, c->out); }
void b_ed_sign(Ctx *c) { act_ed25519_sign(c->sig, c->msg, 64, c->sk); }
void b_ed_verify(Ctx *c) { (void)act_ed25519_verify(c->sig, c->msg, 64, c->pk); }
void b_hkdf(Ctx *c)
{
    act_hkdf_sha512(c->msg, 16, c->msg, 64, c->msg, 8, c->out, 32);
}
void b_sm2_sign(Ctx *c)
{
    act_sm2_sign(c->sm2sig, c->msg, 64, c->sm2priv, nullptr);
}
void b_sm2_verify(Ctx *c)
{
    (void)act_sm2_verify(c->sm2sig, c->msg, 64, c->sm2pub, nullptr);
}
void b_sm2_encrypt(Ctx *c)
{
    size_t n = 0;
    (void)act_sm2_encrypt(c->sm2pub, c->msg, 32, c->ct, sizeof(c->ct), &n);
}

} // namespace

int main()
{
    std::printf("engrail-bench -- %s v%s\n", ACT_PROJECT_NAME, ACT_VERSION);
    std::printf("community: %s\n\n", ACT_TELEGRAM_CHANNEL);
    std::printf("indicative timings (run on your target hardware)\n\n");

    Ctx c;
    for (int i = 0; i < 32; i++) {
        c.seed[i] = (uint8_t)(i * 7 + 1);
    }
    for (int i = 0; i < 64; i++) {
        c.msg[i] = (uint8_t)(i * 3);
    }
    act_ed25519_keypair(c.seed, c.pk, c.sk);
    act_ed25519_sign(c.sig, c.msg, 64, c.sk);
    act_sm2_keypair(c.seed, c.sm2pub, c.sm2priv);
    act_sm2_sign(c.sm2sig, c.msg, 64, c.sm2priv, nullptr);

    bench("sha512 (64 B)", 20000, b_sha512, &c);
    bench("sm3 (64 B)", 20000, b_sm3, &c);
    bench("hmac-sha512 (64 B)", 10000, b_hmac, &c);
    bench("hkdf-sha512 (32 B out)", 10000, b_hkdf, &c);
    bench("ed25519 sign (64 B msg)", 200, b_ed_sign, &c);
    bench("ed25519 verify (64 B msg)", 100, b_ed_verify, &c);
    bench("sm2 sign (64 B msg)", 50, b_sm2_sign, &c);
    bench("sm2 verify (64 B msg)", 25, b_sm2_verify, &c);
    bench("sm2 encrypt (32 B msg)", 50, b_sm2_encrypt, &c);

    std::printf("\nfull test suite: make test | end-to-end: make e2e\n");
    return 0;
}
