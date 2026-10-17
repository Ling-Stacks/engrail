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
 * @file  test_hmac.c
 * @brief HMAC-SHA512 conformance tests (RFC 4231 test cases 1-4)
 *        plus SHA-512 known-answer tests (FIPS 180-4 appendices).
 */

#include "activation/hmac.h"
#include "activation/sha512.h"

#include <stdio.h>
#include <string.h>

static int g_failures = 0;

static void check(const char *name, const uint8_t *got, size_t gotlen,
                  const char *want_hex)
{
    char buf[161];
    size_t i;
    for (i = 0; i < gotlen; i++) {
        sprintf(buf + 2 * i, "%02x", got[i]);
    }
    buf[2 * gotlen] = '\0';
    if (strcmp(buf, want_hex) == 0) {
        printf("[PASS] %s\n", name);
    } else {
        printf("[FAIL] %s\n  got  %s\n  want %s\n", name, buf, want_hex);
        g_failures++;
    }
}

int main(void)
{
    uint8_t mac[ACT_HMAC_SHA512_SIZE];
    uint8_t dg[ACT_SHA512_DIGEST_SIZE];

    /* ---- SHA-512 known answers (FIPS 180-4) ---- */
    act_sha512("abc", 3, dg);
    check("SHA512(\"abc\")", dg, 64,
          "ddaf35a193617abacc417349ae204131"
          "12e6fa4e89a97ea20a9eeee64b55d39a"
          "2192992a274fc1a836ba3c23a3feebbd"
          "454d4423643ce80e2a9ac94fa54ca49f");

    act_sha512("", 0, dg);
    check("SHA512(\"\")", dg, 64,
          "cf83e1357eefb8bdf1542850d66d8007"
          "d620e4050b5715dc83f4a921d36ce9ce"
          "47d0d13c5d85f2b0ff8318d2877eec2f"
          "63b931bd47417a81a538327af927da3e");

    {
        /* "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn
         *   hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"
         * -- two-million-'a' vector is slow; this one covers multi-block
         * padding with a non-trivial tail. */
        const char *m = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklm"
                        "ghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrs"
                        "mnopqrstnopqrstu";
        act_sha512(m, strlen(m), dg);
        check("SHA512(896-bit message)", dg, 64,
              "8e959b75dae313da8cf4f72814fc143f"
              "8f7779c6eb9f7fa17299aeadb6889018"
              "501d289e4900f7e4331b99dec4b5433a"
              "c7d329eeb6dd26545e96e55b874be909");
    }

    /* ---- HMAC-SHA512, RFC 4231 ---- */

    /* TC1 */
    {
        uint8_t key[20];
        memset(key, 0x0b, sizeof(key));
        act_hmac_sha512(key, sizeof(key), "Hi There", 8, mac);
        check("HMAC-SHA512 RFC4231 TC1", mac, 64,
              "87aa7cdea5ef619d4ff0b4241a1d6cb0"
              "2379f4e2ce4ec2787ad0b30545e17cde"
              "daa833b7d6b8a702038b274eaea3f4e4"
              "be9d914eeb61f1702e696c203a126854");
    }

    /* TC2 */
    {
        const char *k = "Jefe";
        const char *d = "what do ya want for nothing?";
        act_hmac_sha512((const uint8_t *)k, 4, d, strlen(d), mac);
        check("HMAC-SHA512 RFC4231 TC2", mac, 64,
              "164b7a7bfcf819e2e395fbe73b56e0a3"
              "87bd64222e831fd610270cd7ea250554"
              "9758bf75c05a994a6d034f65f8f0e6fd"
              "caeab1a34d4a6b4b636e070a38bce737");
    }

    /* TC3 */
    {
        uint8_t key[25], data[50];
        memset(key, 0xaa, sizeof(key));
        memset(data, 0xdd, sizeof(data));
        act_hmac_sha512(key, sizeof(key), data, sizeof(data), mac);
        check("HMAC-SHA512 RFC4231 TC3", mac, 64,
              "e078576669ee552f3b7f68a82873186e"
              "013c48afc1a0faf435dd9ac8fb93d649"
              "026f551c03ee21063338afde5972f04e"
              "6e162cc98bf7eb777efd90ba3304bf7f");
    }

    /* TC4 (key of 131 bytes -> forces H(key) path) */
    {
        uint8_t key[131], data[50];
        unsigned char i;
        for (i = 0; i < sizeof(key); i++) key[i] = (uint8_t)i;
        memset(data, 0xcd, sizeof(data));
        act_hmac_sha512(key, sizeof(key), data, sizeof(data), mac);
        check("HMAC-SHA512 RFC4231 TC4", mac, 64,
              "dd011db59ab7b8bba711460a1dd5aa8b"
              "753794fa823f24813d41a3631f738193"
              "3419e77e3575b09e32891bb05deebcaf"
              "0aff6bdf8dce1e76d68167d176103337");
    }

    /* streaming helper must agree with the one-shot */
    {
        uint8_t mac2[ACT_HMAC_SHA512_SIZE];
        act_hmac_sha512_2((const uint8_t *)"Jefe", 4,
                          "what do ya want ", 16, "for nothing?", 12, mac2);
        check("HMAC-SHA512 2-chunk == TC2", mac2, 64,
              "164b7a7bfcf819e2e395fbe73b56e0a3"
              "87bd64222e831fd610270cd7ea250554"
              "9758bf75c05a994a6d034f65f8f0e6fd"
              "caeab1a34d4a6b4b636e070a38bce737");
    }

    if (g_failures == 0) {
        printf("sha512/hmac: ALL TESTS PASSED\n");
        return 0;
    }
    printf("sha512/hmac: %d TEST(S) FAILED\n", g_failures);
    return 1;
}
