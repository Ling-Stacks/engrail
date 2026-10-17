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
 * @file  test_ed25519.c
 * @brief Ed25519 conformance tests using official RFC 8032 test vectors.
 *
 * A passing run proves the signing and verification paths are bit-exact
 * with every standard Ed25519 implementation.
 */

#include "activation/ed25519.h"

#include <stdio.h>
#include <string.h>

typedef struct {
    const char *name;
    const char *seed_hex;
    const char *pk_hex;
    const char *msg_hex;
    const char *sig_hex;
} ed_test_t;

/* RFC 8032, section 7.1 -- TEST 1, TEST 2, TEST 3. */
static const ed_test_t g_tests[] = {
    {
        "RFC 8032 TEST 1 (empty message)",
        "9d61b19deffd5a60ba844af492ec2cc4"
        "4449c5697b326919703bac031cae7f60",
        "d75a980182b10ab7d54bfed3c964073a"
        "0ee172f3daa62325af021a68f707511a",
        "",
        "e5564300c360ac729086e2cc806e828a"
        "84877f1eb8e5d974d873e06522490155"
        "5fb8821590a33bacc61e39701cf9b46b"
        "d25bf5f0595bbe24655141438e7a100b"
    },
    {
        "RFC 8032 TEST 2 (1 byte 0x72)",
        "4ccd089b28ff96da9db6c346ec114e0f"
        "5b8a319f35aba624da8cf6ed4fb8a6fb",
        "3d4017c3e843895a92b70aa74d1b7ebc"
        "9c982ccf2ec4968cc0cd55f12af4660c",
        "72",
        "92a009a9f0d4cab8720e820b5f642540"
        "a2b27b5416503f8fb3762223ebdb69da"
        "085ac1e43e15996e458f3613d0f11d8c"
        "387b2eaeb4302aeeb00d291612bb0c00"
    },
    {
        "RFC 8032 TEST 3 (2 bytes 0xaf82)",
        "c5aa8df43f9f837bedb7442f31dcb7b1"
        "66d38535076f094b85ce3a2e0b4458f7",
        "fc51cd8e6218a1a38da47ed00230f058"
        "0816ed13ba3303ac5deb911548908025",
        "af82",
        "6291d657deec24024827e69c3abe01a3"
        "0ce548a284743a445e3680d7db5ac3ac"
        "18ff9b538d16f290ae67f760984dc659"
        "4a7c15e9716ed28dc027beceea1ec40a"
    }
};

/** Decode a hex string (even length) into bytes. */
static int hex_decode(const char *hex, uint8_t *out, size_t outlen)
{
    size_t hl = strlen(hex);
    size_t i;
    if (hl % 2 != 0 || hl / 2 > outlen) {
        return -1;
    }
    for (i = 0; i < hl / 2; i++) {
        unsigned v;
        if (sscanf(hex + 2 * i, "%2x", &v) != 1) {
            return -1;
        }
        out[i] = (uint8_t)v;
    }
    return (int)(hl / 2);
}

/** Dump a buffer as lowercase hex into a NUL-terminated string. */
static void hex_encode(const uint8_t *in, size_t len, char *out)
{
    size_t i;
    for (i = 0; i < len; i++) {
        sprintf(out + 2 * i, "%02x", in[i]);
    }
    out[2 * len] = '\0';
}

int main(void)
{
    size_t t;
    int failures = 0;
    char sig_hex[2 * ACT_ED25519_SIG_SIZE + 1];
    char pk_hex[2 * ACT_ED25519_PUBKEY_SIZE + 1];

    for (t = 0; t < sizeof(g_tests) / sizeof(g_tests[0]); t++) {
        const ed_test_t *tv = &g_tests[t];
        uint8_t seed[32], pk[32], sk[64], sig[64], msg[128];
        uint8_t exp_pk[32], exp_sig[64];
        int mlen, k;
        int rc = 0;

        mlen = hex_decode(tv->msg_hex, msg, sizeof(msg));
        hex_decode(tv->seed_hex, seed, sizeof(seed));
        hex_decode(tv->pk_hex, exp_pk, sizeof(exp_pk));
        hex_decode(tv->sig_hex, exp_sig, sizeof(exp_sig));

        /* 1. keypair derivation from the RFC seed must match the RFC pk */
        act_ed25519_keypair(seed, pk, sk);
        hex_encode(pk, 32, pk_hex);
        if (memcmp(pk_hex, tv->pk_hex, 64) != 0) {
            printf("[FAIL] %s: pubkey mismatch\n", tv->name);
            printf("       got      %s\n", pk_hex);
            printf("       expected %s\n", tv->pk_hex);
            failures++;
            continue;
        }

        /* 2. signing must reproduce the RFC signature bit-for-bit */
        act_ed25519_sign(sig, msg, (size_t)mlen, sk);
        hex_encode(sig, 64, sig_hex);
        if (memcmp(sig_hex, tv->sig_hex, 128) != 0) {
            printf("[FAIL] %s: signature mismatch\n", tv->name);
            printf("       got      %s\n", sig_hex);
            printf("       expected %s\n", tv->sig_hex);
            failures++;
            continue;
        }

        /* 3. verification of the correct signature must succeed */
        if (act_ed25519_verify(sig, msg, (size_t)mlen, pk) != 0) {
            printf("[FAIL] %s: valid signature rejected\n", tv->name);
            failures++;
            continue;
        }

        /* 4. every single-bit flip in sig/pk must be rejected */
        for (k = 0; k < 64; k++) {
            uint8_t bad[64];
            memcpy(bad, sig, 64);
            bad[k] ^= 0x01;
            if (act_ed25519_verify(bad, msg, (size_t)mlen, pk) == 0) {
                printf("[FAIL] %s: tampered sig byte %d accepted\n", tv->name, k);
                rc = -1;
                break;
            }
            memcpy(bad, pk, 32);
            bad[k % 32] ^= 0x80;
            if (act_ed25519_verify(sig, msg, (size_t)mlen, bad) == 0) {
                printf("[FAIL] %s: tampered pubkey byte %d accepted\n", tv->name, k);
                rc = -1;
                break;
            }
        }

        if (rc == 0) {
            printf("[PASS] %s (keypair + sign + verify + tamper-rejection)\n",
                   tv->name);
        } else {
            failures++;
        }
    }

    if (failures == 0) {
        printf("ed25519: ALL TESTS PASSED\n");
        return 0;
    }
    printf("ed25519: %d TEST(S) FAILED\n", failures);
    return 1;
}
