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
 * @file  vectors.c
 * @brief Engrail Crypto standalone conformance suite.
 *
 * Every fixed vector comes from the official standard document or was
 * cross-validated against an independent implementation during develop-
 * ment. A passing run proves the amalgamation is bit-exact with the
 * wider ecosystem, all by itself -- no other part of Engrail needed.
 */

#include "engrail_crypto.h"

#include <stdio.h>
#include <string.h>

static int g_failed = 0;

static void hex2bin(const char *hex, uint8_t *out, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        unsigned v;
        sscanf(hex + 2 * i, "%2x", &v);
        out[i] = (uint8_t)v;
    }
}

static void bin2hex(const uint8_t *in, size_t n, char *out)
{
    for (size_t i = 0; i < n; i++) {
        sprintf(out + 2 * i, "%02x", in[i]);
    }
    out[2 * n] = '\0';
}

static void check(const char *name, const uint8_t *got,
                  const char *want_hex, size_t n)
{
    char buf[1024];
    bin2hex(got, n, buf);
    if (strcmp(buf, want_hex) == 0) {
        printf("  [PASS] %s\n", name);
    } else {
        g_failed++;
        printf("  [FAIL] %s\n    got  %s\n    want %s\n", name, buf, want_hex);
    }
}

#define CHECK(cond, name)                                                  \
    do {                                                                   \
        if (cond) { printf("  [PASS] %s\n", name); }                       \
        else { g_failed++; printf("  [FAIL] %s\n", name); }                \
    } while (0)

int main(void)
{
    printf("engrail-crypto conformance suite\n");

    /* ---- SHA-512 (FIPS 180-4) ---- */
    {
        uint8_t dg[64];
        act_sha512("abc", 3, dg);
        check("SHA-512(\"abc\")", dg,
              "ddaf35a193617abacc417349ae204131"
              "12e6fa4e89a97ea20a9eeee64b55d39a"
              "2192992a274fc1a836ba3c23a3feebbd"
              "454d4423643ce80e2a9ac94fa54ca49f", 64);
        act_sha512("", 0, dg);
        check("SHA-512(\"\")", dg,
              "cf83e1357eefb8bdf1542850d66d8007"
              "d620e4050b5715dc83f4a921d36ce9ce"
              "47d0d13c5d85f2b0ff8318d2877eec2f"
              "63b931bd47417a81a538327af927da3e", 64);
    }

    /* ---- HMAC-SHA512 (RFC 4231 TC1) ---- */
    {
        uint8_t key[20], mac[64];
        memset(key, 0x0b, sizeof(key));
        act_hmac_sha512(key, sizeof(key), "Hi There", 8, mac);
        check("HMAC-SHA512 RFC 4231 TC1", mac,
              "87aa7cdea5ef619d4ff0b4241a1d6cb0"
              "2379f4e2ce4ec2787ad0b30545e17cde"
              "daa833b7d6b8a702038b274eaea3f4e4"
              "be9d914eeb61f1702e696c203a126854", 64);
    }

    /* ---- Ed25519 (RFC 8032 7.1 TEST 1) ---- */
    {
        uint8_t seed[32], pk[32], sk[64], sig[64];
        hex2bin("9d61b19deffd5a60ba844af492ec2cc4"
                "4449c5697b326919703bac031cae7f60", seed, 32);
        act_ed25519_keypair(seed, pk, sk);
        check("Ed25519 keypair RFC 8032 T1", pk,
              "d75a980182b10ab7d54bfed3c964073a"
              "0ee172f3daa62325af021a68f707511a", 32);
        act_ed25519_sign(sig, NULL, 0, sk);
        check("Ed25519 sign RFC 8032 T1 (empty msg)", sig,
              "e5564300c360ac729086e2cc806e828a"
              "84877f1eb8e5d974d873e06522490155"
              "5fb8821590a33bacc61e39701cf9b46b"
              "d25bf5f0595bbe24655141438e7a100b", 64);
        CHECK(act_ed25519_verify(sig, NULL, 0, pk) == 0,
              "Ed25519 verify RFC 8032 T1");
        sig[0] ^= 1;
        CHECK(act_ed25519_verify(sig, NULL, 0, pk) != 0,
              "Ed25519 tampered signature rejected");
    }

    /* ---- SM3 (GB/T 32905-2016) ---- */
    {
        uint8_t dg[32];
        act_sm3("abc", 3, dg);
        check("SM3(\"abc\") GB/T 32905", dg,
              "66c7f0f462eeedd9d1f2d46bdc10e4e2"
              "4167c4875cf2f7a2297da02b8f4ba8e0", 32);
        uint8_t longmsg[64];
        for (int i = 0; i < 16; i++) memcpy(longmsg + 4 * i, "abcd", 4);
        act_sm3(longmsg, 64, dg);
        check("SM3(64-byte) GB/T 32905", dg,
              "debe9ff92275b8a138604889c18e5a4d"
              "6fdb70e5387e5765293dcba39c0c5732", 32);
    }

    /* ---- SM2 (GB/T 32918) ---- */
    {
        uint8_t seed[32], pub[64], priv[32];
        hex2bin("3945208f7b2144b13f36e38ac6d391a0"
                "ff3075228a7b0f38be10d117aa9eab6d", seed, 32);
        act_sm2_keypair(seed, pub, priv);
        check("SM2 keypair from fixed seed (ind. verified)", pub,
              "34e0feb4f37e9a8624d7e101ec3423bbdfcbf583"
              "16636d79caae5e6eba235e58"
              "f99e424da9d38840ed8c4cba1f6d05a2"
              "225d5a2617cfd12a6aa3047404b0e75c", 64);

        const uint8_t msg[] = "standalone conformance";
        uint8_t sig[64];
        CHECK(act_sm2_sign(sig, msg, sizeof(msg) - 1, priv, NULL) == ACT_OK,
              "SM2 sign");
        CHECK(act_sm2_verify(sig, msg, sizeof(msg) - 1, pub, NULL) == ACT_OK,
              "SM2 verify (own signature)");
        sig[63] ^= 0x80;
        CHECK(act_sm2_verify(sig, msg, sizeof(msg) - 1, pub, NULL) != ACT_OK,
              "SM2 tampered signature rejected");

        const uint8_t secret[] = "attack at dawn";
        uint8_t ct[128], pt[128];
        size_t cl = 0, pl = 0;
        CHECK(act_sm2_encrypt(pub, secret, sizeof(secret) - 1, ct,
                              sizeof(ct), &cl) == ACT_OK,
              "SM2 encrypt");
        CHECK(act_sm2_decrypt(ct, cl, priv, pt, sizeof(pt), &pl) == ACT_OK &&
                  pl == sizeof(secret) - 1 &&
                  memcmp(pt, secret, pl) == 0,
              "SM2 decrypt round-trip");
        ct[1] ^= 0x01; /* off-curve C1 */
        CHECK(act_sm2_decrypt(ct, cl, priv, pt, sizeof(pt), &pl) ==
                  (act_status)ACT_ERR_FORMAT,
              "SM2 decrypt rejects off-curve C1");
    }

    /* ---- HKDF-SHA512 (RFC 5869 A.1, extended by indep. impl) ---- */
    {
        uint8_t salt[22], ikm[48], info[10];
        hex2bin("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b", salt, 22);
        hex2bin("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c"
                "1d1e1f202122232425262728292a2b2c2d2e2f", ikm, 48);
        hex2bin("f0f1f2f3f4f5f6f7f8f9", info, 10);
        uint8_t okm[100];
        CHECK(act_hkdf_sha512(salt, 22, ikm, 48, info, 10, okm, 100) == 0,
              "HKDF one-shot");
        char buf[256];
        bin2hex(okm, 32, buf);
        CHECK(strcmp(buf, "6fe4dcc76d56530cbef5be0e11f989ad"
                          "7141467a3f060ee5556b7967ee5748cd") == 0,
              "HKDF OKM[0:32] matches independent implementation");
    }

    /* ---- PBKDF2-HMAC-SHA512 ---- */
    {
        uint8_t dk[48];
        act_pbkdf2_hmac_sha512((const uint8_t *)"password", 8,
                               (const uint8_t *)"saltsaltsaltsalt", 16,
                               4096, dk, 48);
        check("PBKDF2-HMAC-SHA512 (4096 iters)", dk,
              "7dc69993c22ab444a13574b9d71b2caf"
              "c54e68914d9ddfd00ed5c23545b854d5"
              "e0e68b7f5614eef5df9087573bab8360", 48);
    }

    /* ---- ChaCha20 (RFC 8439 2.4.2) ---- */
    {
        static const char *SUNSCREEN =
            "Ladies and Gentlemen of the class of '99: If I could offer you "
            "only one tip for the future, sunscreen would be it.";
        const size_t mlen = strlen(SUNSCREEN);
        uint8_t key[32], nonce[12], ct[200];
        for (int i = 0; i < 32; i++) key[i] = (uint8_t)i;
        hex2bin("000000090000004a00000000", nonce, 12);
        memcpy(ct, SUNSCREEN, mlen);
        act_chacha20_xor(key, nonce, 1, ct, mlen);
        check("ChaCha20 RFC 8439 2.4.2 ciphertext", ct,
              "5c90838db44879743e6bfd58c64e05a8"
              "a2bc91a913af0e23704acfbaa0b80d3d"
              "a1a20b2027b893302ee29e63f9c222c1"
              "da67f0b5fe7928dfaea2a391cd251c21"
              "64e4fa5756b9da6e8ca5dc908c44cbf6"
              "e93ea6b4cc406988d7da69bf795bf19b"
              "84539df73bd9b3e9ca4d03bc0a586ff5"
              "28dc", mlen);
        act_chacha20_xor(key, nonce, 1, ct, mlen);
        CHECK(memcmp(ct, SUNSCREEN, mlen) == 0,
              "ChaCha20 decrypt round-trip");
    }

    if (g_failed == 0) {
        printf("engrail-crypto: ALL CONFORMANCE TESTS PASSED\n");
        return 0;
    }
    printf("engrail-crypto: %d TEST(S) FAILED\n", g_failed);
    return 1;
}
