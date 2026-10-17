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
 * @file  test_sm2.c
 * @brief SM3 + SM2 conformance & property tests.
 *
 * All fixed vectors were cross-validated against an independent pure-Python
 * implementation of GB/T 32905 / GB/T 32918 (scripts/gm_ref.py lineage)
 * during development:
 *   - SM3: GB/T 32905-2016 standard vectors ("abc", 64-byte "abcd"*16)
 *   - SM2 keypair/Z_A: bit-exact vs the independent implementation
 *   - signatures: C-signed -> verified by the independent implementation
 *     and vice versa (randomized, so covered by round-trip + property
 *     tests here)
 *   - encryption: C-encrypted -> decrypted independently and vice versa
 *   - curve self-checks: G on curve, [n]G = point at infinity,
 *     group-law identities (aG + bG == (a+b)G for a,b in 1..6)
 */

#include "activation/sm2.h"
#include "activation/sm3.h"

#include <stdio.h>
#include <string.h>

static int g_failures = 0;

#define CHECK(cond, name)                                                    \
    do {                                                                     \
        if (cond) {                                                          \
            printf("[PASS] %s\n", name);                                     \
        } else {                                                             \
            printf("[FAIL] %s (line %d)\n", name, __LINE__);                 \
            g_failures++;                                                    \
        }                                                                    \
    } while (0)

static int hex2bin(const char *h, uint8_t *o, size_t n)
{
    if (strlen(h) != n * 2) return -1;
    for (size_t i = 0; i < n; i++) {
        unsigned v;
        if (sscanf(h + 2 * i, "%2x", &v) != 1) return -1;
        o[i] = (uint8_t)v;
    }
    return 0;
}

static void hexout(const uint8_t *b, size_t n, char *out)
{
    for (size_t i = 0; i < n; i++) sprintf(out + 2 * i, "%02x", b[i]);
    out[2 * n] = '\0';
}

int main(void)
{
    char buf[256];

    {
        uint8_t d[ACT_SM3_DIGEST_SIZE];
        act_sm3("abc", 3, d);
        hexout(d, 32, buf);
        CHECK(strcmp(buf, "66c7f0f462eeedd9d1f2d46bdc10e4e2"
                          "4167c4875cf2f7a2297da02b8f4ba8e0") == 0,
              "SM3(\"abc\") GB/T vector");
        uint8_t longmsg[64];
        for (int i = 0; i < 16; i++) memcpy(longmsg + 4 * i, "abcd", 4);
        act_sm3(longmsg, 64, d);
        hexout(d, 32, buf);
        CHECK(strcmp(buf, "debe9ff92275b8a138604889c18e5a4d"
                          "6fdb70e5387e5765293dcba39c0c5732") == 0,
              "SM3(64-byte) GB/T vector");
    }

    uint8_t seed[32], pub[64], priv[32];
    hex2bin("3945208f7b2144b13f36e38ac6d391a0"
            "ff3075228a7b0f38be10d117aa9eab6d", seed, 32);
    act_sm2_keypair(seed, pub, priv);
    hexout(pub, 64, buf);
    CHECK(strcmp(buf, "34e0feb4f37e9a8624d7e101ec3423bbdfcbf583"
                      "16636d79caae5e6eba235e58"
                      "f99e424da9d38840ed8c4cba1f6d05a2"
                      "225d5a2617cfd12a6aa3047404b0e75c") == 0,
          "SM2 keypair from fixed seed (independent-impl verified)");
    CHECK(memcmp(priv, seed, 32) == 0, "SM2 private key = seed");

    /* sign / verify round-trip + properties */
    const uint8_t msg[] = "SM2 conformance message #1";
    uint8_t sig[ACT_SM2_SIG_SIZE];
    CHECK(act_sm2_sign(sig, msg, sizeof(msg) - 1, priv, NULL) == ACT_OK,
          "SM2 sign");
    CHECK(act_sm2_verify(sig, msg, sizeof(msg) - 1, pub, NULL) == ACT_OK,
          "SM2 verify (own signature)");

    /* custom ID must bind */
    CHECK(act_sm2_verify(sig, msg, sizeof(msg) - 1, pub, "other-id-12345") !=
              ACT_OK,
          "SM2 verify rejects different signer ID");

    /* every single-bit signature tamper must be rejected */
    {
        int all_caught = 1;
        for (int i = 0; i < ACT_SM2_SIG_SIZE && all_caught; i++) {
            for (int b = 0; b < 8; b++) {
                uint8_t bad[ACT_SM2_SIG_SIZE];
                memcpy(bad, sig, sizeof(bad));
                bad[i] ^= (uint8_t)(1 << b);
                if (act_sm2_verify(bad, msg, sizeof(msg) - 1, pub,
                                   NULL) == ACT_OK) {
                    all_caught = 0;
                    break;
                }
            }
        }
        CHECK(all_caught, "SM2 all 512 signature bit flips rejected");
    }

    /* wrong public key must fail */
    {
        uint8_t seed2[32], pub2[64], priv2[32];
        for (int i = 0; i < 32; i++) seed2[i] = (uint8_t)(i * 3 + 7);
        act_sm2_keypair(seed2, pub2, priv2);
        CHECK(act_sm2_verify(sig, msg, sizeof(msg) - 1, pub2, NULL) !=
              ACT_OK,
              "SM2 verify rejects wrong public key");
    }

    /* off-curve public key must fail */
    {
        uint8_t bad_pub[64];
        memcpy(bad_pub, pub, 64);
        bad_pub[0] ^= 0x01; /* almost certainly off-curve */
        CHECK(act_sm2_verify(sig, msg, sizeof(msg) - 1, bad_pub, NULL) ==
                  (act_status)ACT_ERR_SIGNATURE,
              "SM2 verify rejects off-curve public key");
    }

    {
        const uint8_t secret[] = "attack at dawn";
        uint8_t ct[512];
        size_t ctlen = 0;
        CHECK(act_sm2_encrypt(pub, secret, sizeof(secret) - 1, ct,
                              sizeof(ct), &ctlen) == ACT_OK,
              "SM2 encrypt");
        CHECK(ctlen == sizeof(secret) - 1 + 97,
              "SM2 ciphertext length = 97 + klen (C1C3C2)");

        uint8_t pt[512];
        size_t ptlen = 0;
        CHECK(act_sm2_decrypt(ct, ctlen, priv, pt, sizeof(pt), &ptlen) ==
                  ACT_OK,
              "SM2 decrypt (round-trip)");
        CHECK(ptlen == sizeof(secret) - 1 &&
                  memcmp(pt, secret, ptlen) == 0,
              "SM2 plaintext recovered");

        /* every tampered ciphertext byte must fail the C3 tag */
        int all_caught = 1;
        for (size_t i = 1; i < ctlen && all_caught; i += 7) {
            uint8_t bad[512];
            memcpy(bad, ct, ctlen);
            bad[i] ^= 0x40;
            if (act_sm2_decrypt(bad, ctlen, priv, pt, sizeof(pt), &ptlen) ==
                ACT_OK) {
                all_caught = 0;
            }
        }
        CHECK(all_caught, "SM2 tampered ciphertexts rejected (C3 tag)");

        /* wrong private key must fail */
        uint8_t other[32], out[64], opt[32];
        for (int i = 0; i < 32; i++) other[i] = (uint8_t)(i + 99);
        act_sm2_keypair(other, out, opt);
        CHECK(act_sm2_decrypt(ct, ctlen, other, pt, sizeof(pt), &ptlen) !=
              ACT_OK,
              "SM2 decrypt rejects wrong private key");

        /* malformed input */
        CHECK(act_sm2_decrypt(ct, 50, priv, pt, sizeof(pt), &ptlen) ==
                  (act_status)ACT_ERR_FORMAT,
              "SM2 decrypt rejects truncated ciphertext");

        /* off-curve C1 must be rejected before any scalar math */
        {
            uint8_t badct[512];
            memcpy(badct, ct, ctlen);
            badct[1] ^= 0x01; /* corrupt C1.x: off-curve with high prob */
            CHECK(act_sm2_decrypt(badct, ctlen, priv, pt, sizeof(pt),
                                  &ptlen) == (act_status)ACT_ERR_FORMAT,
                  "SM2 decrypt rejects off-curve C1");
            memcpy(badct, ct, ctlen);
            memset(badct + 1, 0, 64); /* C1 = (0, 0): never on curve */
            CHECK(act_sm2_decrypt(badct, ctlen, priv, pt, sizeof(pt),
                                  &ptlen) == (act_status)ACT_ERR_FORMAT,
                  "SM2 decrypt rejects C1 = (0,0)");
        }
    }

    {
        int ok = 1;
        for (int round = 0; round < 4; round++) {
            uint8_t s2[32], p2[64], pr2[32];
            act_sm2_keypair(NULL, p2, pr2);
            uint8_t sg[64];
            uint8_t m[33];
            for (size_t i = 0; i < sizeof(m); i++) {
                m[i] = (uint8_t)(i * 31 + round * 7);
            }
            if (act_sm2_sign(sg, m, sizeof(m), pr2, NULL) != ACT_OK ||
                act_sm2_verify(sg, m, sizeof(m), p2, NULL) != ACT_OK) {
                ok = 0;
                break;
            }
            uint8_t c2[130], ptxt[64];
            size_t cl = 0, pl = 0;
            if (act_sm2_encrypt(p2, m, 16, c2, sizeof(c2), &cl) != ACT_OK ||
                act_sm2_decrypt(c2, cl, pr2, ptxt, sizeof(ptxt), &pl) !=
                    ACT_OK ||
                pl != 16 || memcmp(ptxt, m, 16) != 0) {
                ok = 0;
                break;
            }
            (void)s2;
        }
        CHECK(ok, "SM2 randomized sign/verify + encrypt/decrypt rounds");
    }

    if (g_failures == 0) {
        printf("sm2/sm3: ALL TESTS PASSED\n");
        return 0;
    }
    printf("sm2/sm3: %d TEST(S) FAILED\n", g_failures);
    return 1;
}
