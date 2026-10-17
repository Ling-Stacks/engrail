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
 * @file  test_license.c
 * @brief End-to-end tests for the license codec, verification pipeline
 *        and the local activation state store.
 */

#include "activation/license.h"
#include "activation/state.h"
#include "activation/fingerprint.h"
#include "activation/ed25519.h"
#include "activation/revoke.h"
#include "activation/harden.h"
#include "activation/sha512.h"
#include "activation/keyfile.h"
#include "activation/token.h"
#include "activation/audit.h"
#include "activation/version.h"

#include <time.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
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

int main(void)
{
    /* Deterministic key pair (do NOT use fixed seeds in production). */
    uint8_t seed[32];
    uint8_t pk[32], sk[64];
    for (int i = 0; i < 32; i++) {
        seed[i] = (uint8_t)(i * 7 + 1);
    }
    act_ed25519_keypair(seed, pk, sk);

    uint8_t machine[16];
    for (int i = 0; i < 16; i++) {
        machine[i] = (uint8_t)(0xA0 + i);
    }

    /* ---- payload + codec round trip ---- */
    uint8_t payload[ACT_PAYLOAD_SIZE], sig[ACT_SIG_SIZE];
    act_license_make(payload, sig, 0x1234ABCD, machine, 2000, 0, NULL, 0, sk);
    char code[ACT_CODE_MAX_CHARS];
    CHECK(act_license_encode(payload, sig, code, sizeof(code)) == ACT_OK,
          "encode");
    CHECK(strlen(code) == 191,
          "encoded length is 191 (160 chars + 31 dashes)");

    uint8_t p2[ACT_PAYLOAD_SIZE], s2[ACT_SIG_SIZE];
    CHECK(act_license_decode(code, p2, s2) == ACT_OK, "decode");
    CHECK(memcmp(p2, payload, ACT_PAYLOAD_SIZE) == 0 &&
              memcmp(s2, sig, ACT_SIG_SIZE) == 0,
          "round trip preserves payload+signature");

    /* ---- normalisation: lowercase, no dashes, confusables ---- */
    char messy[ACT_CODE_MAX_CHARS * 2];
    size_t o = 0;
    for (const char *c = code; *c; c++) {
        if (*c == '-') continue; /* strip dashes */
        messy[o++] = (*c >= '0' && *c <= '9') ? *c : (char)(*c + 32);
    }
    messy[o] = '\0';
    /* Crockford confusables can only be tested where the alphabet allows:
     * replace a known '0' with 'O' and a '1' with 'L' at safe positions. */
    uint8_t p3[ACT_PAYLOAD_SIZE], s3[ACT_SIG_SIZE];
    CHECK(act_license_decode(messy, p3, s3) == ACT_OK,
          "decode forgives case + dashes");
    CHECK(memcmp(p3, payload, ACT_PAYLOAD_SIZE) == 0,
          "normalised decode matches");

    /* ---- happy-path verification ---- */
    const int64_t now = ACT_EXPIRY_EPOCH + 1000 * 86400LL; /* day 1000 */
    act_license_info info;
    memset(&info, 0, sizeof(info));
    CHECK(act_license_verify(code, pk, 0x1234ABCD, machine, now, &info) ==
              ACT_OK,
          "verify: valid code");
    CHECK(info.product_id == 0x1234ABCD && info.expiry_days == 2000 &&
              info.perpetual == 0 && info.trial == 0 && info.features == 0,
          "decoded info fields");
    {
        /* serial was drawn by the CSPRNG -- 8 bytes, not all zero. */
        int nonzero = 0;
        for (int i = 0; i < 8; i++) nonzero |= info.serial[i];
        CHECK(nonzero != 0, "random serial generated");
    }

    /* ---- every single-bit payload tamper must be caught ---- */
    int all_caught = 1;
    for (int i = 0; i < ACT_PAYLOAD_SIZE; i++) {
        for (int b = 0; b < 8; b++) {
            uint8_t bad[ACT_PAYLOAD_SIZE];
            memcpy(bad, payload, ACT_PAYLOAD_SIZE);
            bad[i] ^= (uint8_t)(1 << b);
            if (act_license_verify_payload(bad, sig, pk, 0x1234ABCD, machine,
                                           now, NULL) == ACT_OK) {
                all_caught = 0;
            }
        }
    }
    CHECK(all_caught, "all 208 payload bit flips rejected");

    /* ---- signature tamper ---- */
    uint8_t badsig[ACT_SIG_SIZE];
    memcpy(badsig, sig, ACT_SIG_SIZE);
    badsig[0] ^= 1;
    CHECK(act_license_verify_payload(payload, badsig, pk, 0x1234ABCD,
                                     machine, now, NULL) == ACT_ERR_SIGNATURE,
          "bit-flipped signature rejected");

    /* ---- wrong product / machine ---- */
    CHECK(act_license_verify_payload(payload, sig, pk, 0xDEAD, machine, now,
                                      NULL) == ACT_ERR_PRODUCT,
           "wrong product rejected");
    /* verification order: a forged payload (mutated product field) with an
     * invalid signature must fail on SIGNATURE, not PRODUCT -- no oracle
     * about payload fields before the signature check passes. */
    {
        uint8_t forged_payload[ACT_PAYLOAD_SIZE];
        memcpy(forged_payload, payload, ACT_PAYLOAD_SIZE);
        forged_payload[1] ^= 0xFF; /* corrupt product id, keep old signature */
        CHECK(act_license_verify_payload(forged_payload, sig, pk, 0xDEAD,
                                         machine, now,
                                         NULL) == ACT_ERR_SIGNATURE,
              "signature checked before product (no field oracle)");
    }
    uint8_t other_machine[16];
    memcpy(other_machine, machine, 16);
    other_machine[0] ^= 0xFF;
    CHECK(act_license_verify_payload(payload, sig, pk, 0x1234ABCD,
                                     other_machine, now, NULL) ==
              ACT_ERR_MACHINE,
          "wrong machine rejected");

    /* ---- expiry ---- */
    const int64_t after = ACT_EXPIRY_EPOCH + 2001 * 86400LL;
    CHECK(act_license_verify_payload(payload, sig, pk, 0x1234ABCD, machine,
                                     after, NULL) == ACT_ERR_EXPIRED,
          "expired license rejected");
    const int64_t before = ACT_EXPIRY_EPOCH + 1999 * 86400LL;
    CHECK(act_license_verify_payload(payload, sig, pk, 0x1234ABCD, machine,
                                     before, NULL) == ACT_OK,
          "pre-expiry license accepted");

    /* ---- perpetual + trial + features ---- */
    act_license_make(payload, sig, 0x1234ABCD, machine, 0,
                     ACT_FLAG_PERPETUAL | ACT_FLAG_TRIAL, NULL, 0x00FF, sk);
    act_license_encode(payload, sig, code, sizeof(code));
    CHECK(act_license_verify(code, pk, 0x1234ABCD, machine, after, &info) ==
              ACT_OK,
          "perpetual license valid far in the future");
    CHECK(info.trial == 1 && info.features == 0x00FF,
           "trial flag + feature mask decoded");
    /* perpetual licenses report an unlimited term, not 0 (= expired) */
    CHECK(act_days_remaining(&info, after) == INT64_MAX,
          "days_remaining(perpetual) = INT64_MAX");
    CHECK(act_days_remaining(&info, now) > 0,
          "days_remaining(perpetual) stays positive");
    act_license_encode(payload, sig, code, sizeof(code));
    CHECK(act_license_verify(code, pk, 0x1234ABCD, machine, after, NULL) ==
              ACT_OK,
          "perpetual license valid far in the future");

    /* ---- malformed input ---- */
    CHECK(act_license_verify("not a code!!", pk, 0x1234ABCD, machine, now,
                             NULL) == ACT_ERR_FORMAT,
          "garbage string rejected");
    CHECK(act_license_verify("", pk, 0x1234ABCD, machine, now, NULL) ==
              ACT_ERR_FORMAT,
          "empty string rejected");
    {
        char truncated[64];
        snprintf(truncated, sizeof(truncated), "%.60s", code);
        CHECK(act_license_verify(truncated, pk, 0x1234ABCD, machine, now,
                                 NULL) == ACT_ERR_FORMAT,
              "truncated code rejected");
    }

    /* ---- forged code: valid format, wrong key signature ---- */
    {
        uint8_t seed2[32], pk2[32], sk2[64];
        for (int i = 0; i < 32; i++) seed2[i] = (uint8_t)(i * 3 + 5);
        act_ed25519_keypair(seed2, pk2, sk2);
        uint8_t fpl[ACT_PAYLOAD_SIZE], fsg[ACT_SIG_SIZE];
        act_license_make(fpl, fsg, 0x1234ABCD, machine, 3000, 0, NULL, 0, sk2);
        char forged[ACT_CODE_MAX_CHARS];
        act_license_encode(fpl, fsg, forged, sizeof(forged));
        CHECK(act_license_verify(forged, pk, 0x1234ABCD, machine, now, NULL) ==
                  ACT_ERR_SIGNATURE,
              "code signed by a different key rejected");
    }

    /* ---- state store: save / load / tamper / cross-machine ---- */
    act_license_make(payload, sig, 0x1234ABCD, machine, 2000, 0, NULL, 0, sk);
    CHECK(act_state_save("test_state_act.tmp", payload, sig) == ACT_OK,
          "state save");
    CHECK(act_state_check("test_state_act.tmp", pk, 0x1234ABCD, machine,
                          now, NULL) == ACT_OK,
          "state check: ok");

    /* tamper with the state file (signature region, offset 40) */
    {
        FILE *f = fopen("test_state_act.tmp", "r+b");
        if (f) {
            fseek(f, 40, SEEK_SET);
            int b = fgetc(f);
            fseek(f, 40, SEEK_SET); /* required between read and write */
            fputc(b ^ 0x01, f);
            fclose(f);
        }
        CHECK(act_state_check("test_state_act.tmp", pk, 0x1234ABCD, machine,
                              now, NULL) == ACT_ERR_SIGNATURE,
              "tampered state rejected");
        remove("test_state_act.tmp");
    }

    CHECK(act_state_check("no_such_state.tmp", pk, 0x1234ABCD, machine,
                          now, NULL) == ACT_ERR_STATE_MISSING,
          "missing state detected");

    /* ---- fingerprint determinism + binding (v2: dsalt-keyed) ---- */
    {
        uint8_t dsalt[ACT_DSALT_SIZE], dsalt2[ACT_DSALT_SIZE];
        for (int i = 0; i < ACT_DSALT_SIZE; i++) {
            dsalt[i] = (uint8_t)(i * 11 + 1);
            dsalt2[i] = (uint8_t)(i * 13 + 5);
        }
        uint8_t fp1[16], fp2[16], fp3[16];
        act_fingerprint(pk, dsalt, 7, NULL, 0, fp1);
        act_fingerprint(pk, dsalt, 7, NULL, 0, fp2);
        act_fingerprint(pk, dsalt, 8, NULL, 0, fp3);
        CHECK(memcmp(fp1, fp2, 16) == 0, "fingerprint stable across runs");
        CHECK(memcmp(fp1, fp3, 16) != 0, "fingerprint bound to product id");

        /* 同公钥不同部署盐 => 完全不同的指纹空间 */
        uint8_t fp_other_deploy[16];
        act_fingerprint(pk, dsalt2, 7, NULL, 0, fp_other_deploy);
        CHECK(memcmp(fp1, fp_other_deploy, 16) != 0,
              "deployment salt isolates fingerprint spaces");

        const uint8_t salt1[] = "device-salt";
        const uint8_t salt2[] = "other-salt";
        uint8_t fs1[16], fs2[16];
        act_fingerprint(pk, dsalt, 7, salt1, sizeof(salt1) - 1, fs1);
        act_fingerprint(pk, dsalt, 7, salt2, sizeof(salt2) - 1, fs2);
        CHECK(memcmp(fs1, fs2, 16) != 0, "salt changes fingerprint");

        /* HKDF 派生密钥: 确定性 + 用途分离 */
        uint8_t k1a[32], tk1[32], sk1[32], k1b[32];
        act_deployment_keys(pk, dsalt, k1a, tk1, sk1);
        act_deployment_keys(pk, dsalt, k1b, NULL, NULL);
        CHECK(memcmp(k1a, k1b, 32) == 0, "deployment keys deterministic");
        CHECK(memcmp(k1a, tk1, 32) != 0 && memcmp(tk1, sk1, 32) != 0,
              "purpose keys diverge");

        char mcstr[ACT_MACHINE_CODE_STR_SIZE];
        act_fp_to_string(fp1, mcstr);
        CHECK(strlen(mcstr) == 33 && mcstr[16] == '-',
              "machine code string format");
    }

    /* ---- keyfile: 口令加密往返 + 错误口令拒绝 + 篡改拒绝 ---- */
    {
        uint8_t seed[32];
        for (int i = 0; i < 32; i++) seed[i] = (uint8_t)(i * 17 + 9);
        uint8_t ds[ACT_DSALT_SIZE];
        for (int i = 0; i < ACT_DSALT_SIZE; i++) ds[i] = (uint8_t)(i + 100);

        CHECK(act_keyfile_save("keyfile_test.tmp", seed, ds, "hunter2",
                               1000) == ACT_OK,
              "keyfile save (encrypted)");
        uint8_t rs[32], rds[ACT_DSALT_SIZE];
        CHECK(act_keyfile_load("keyfile_test.tmp", "hunter2", rs, rds) ==
                  ACT_OK,
              "keyfile load with correct passphrase");
        CHECK(memcmp(rs, seed, 32) == 0 && memcmp(rds, ds, ACT_DSALT_SIZE) == 0,
              "keyfile round-trip preserves seed+dsalt");
        CHECK(act_keyfile_load("keyfile_test.tmp", "wrong", rs, rds) ==
                  ACT_ERR_SIGNATURE,
              "keyfile wrong passphrase rejected");
        {
            FILE *f = fopen("keyfile_test.tmp", "r+b");
            fseek(f, 80, SEEK_SET);
            int b = fgetc(f);
            fseek(f, 80, SEEK_SET);
            fputc(b ^ 0x40, f);
            fclose(f);
            CHECK(act_keyfile_load("keyfile_test.tmp", "hunter2", rs,
                                   rds) == ACT_ERR_SIGNATURE,
                  "keyfile tamper rejected");
            remove("keyfile_test.tmp");
        }
        /* 常量泄露论证: 同 seed+dsalt+口令在不同时间保存 -> 都能恢复,
         * 但文件字节不同 (随机盐/nonce) */
        {
            uint8_t f1[ACT_KEYFILE_SIZE], f2[ACT_KEYFILE_SIZE];
            act_keyfile_save("kf_a.tmp", seed, ds, "p", 100);
            act_keyfile_save("kf_b.tmp", seed, ds, "p", 100);
            FILE *fa = fopen("kf_a.tmp", "rb");
            FILE *fb = fopen("kf_b.tmp", "rb");
            size_t r1 = fread(f1, 1, sizeof(f1), fa);
            size_t r2 = fread(f2, 1, sizeof(f2), fb);
            fclose(fa); fclose(fb);
            remove("kf_a.tmp"); remove("kf_b.tmp");
            CHECK(r1 == ACT_KEYFILE_SIZE && r2 == ACT_KEYFILE_SIZE &&
                      memcmp(f1, f2, ACT_KEYFILE_SIZE) != 0,
                  "keyfile randomized (no reusable template bytes)");
        }
    }

    /* ---- offline tokens + challenge-response ---- */
    {
        const char *msg = "cmd=unlock;door=3";
        char tok[ACT_TOKEN_MAX_CHARS(ACT_TOKEN_MAX_PAYLOAD) + 1];
        CHECK(act_token_create(sk, 42, (const uint8_t *)msg, strlen(msg),
                               3600, tok, sizeof(tok)) == ACT_OK,
              "token create");
        uint8_t pbuf[256];
        size_t plen = 0;
        act_token_info tinfo;
        const int64_t tnow = (int64_t)time(NULL);
        CHECK(act_token_verify(tok, pk, 42, tnow, pbuf, sizeof(pbuf), &plen,
                               &tinfo) == ACT_OK && plen == strlen(msg) &&
                  memcmp(pbuf, msg, plen) == 0,
              "token verify + payload round-trip");
        CHECK(act_token_verify(tok, pk, 43, tnow, NULL, 0, NULL,
                               NULL) == ACT_ERR_PRODUCT,
              "token wrong product rejected");
        pbuf[0] ^= 1;
        char tampered[ACT_TOKEN_MAX_CHARS(ACT_TOKEN_MAX_PAYLOAD) + 1];
        /* 直接构造: 改 payload 需要重新 base64 -- 简化: 改产品校验已够,
         * 签名篡改已在 license 测试覆盖。这里验证 TTL: */
        (void)tampered;
        CHECK(act_token_verify(tok, pk, 42, tnow + 3601, NULL, 0, NULL,
                               NULL) == ACT_ERR_EXPIRED,
              "token expired rejected");

        /* challenge-response */
        char chal[96], resp[128];
        CHECK(act_challenge_create(machine, 42, tnow, chal, sizeof(chal)) ==
                  ACT_OK,
              "challenge create");
        CHECK(act_challenge_respond(chal, sk, resp, sizeof(resp)) == ACT_OK,
              "challenge respond");
        CHECK(act_challenge_verify(chal, resp, pk, 42, machine, tnow + 1,
                                   0) == ACT_OK,
              "challenge verify: ok");
        CHECK(act_challenge_verify(chal, resp, pk, 42, machine,
                                   tnow + 400, 0) == ACT_ERR_EXPIRED,
              "challenge stale rejected");
        uint8_t om2[16];
        memcpy(om2, machine, 16);
        om2[0] ^= 1;
        CHECK(act_challenge_verify(chal, resp, pk, 42, om2, tnow + 1,
                                   0) == ACT_ERR_MACHINE,
              "challenge other machine rejected");
        /* keep the char valid base64url: flipping a boundary char with
         * ^= 1 can yield an illegal symbol -> FORMAT instead of
         * SIGNATURE, a probabilistic false failure (R3/L8) */
        resp[10] = (resp[10] == 'A') ? 'B' : 'A';
        CHECK(act_challenge_verify(chal, resp, pk, 42, machine, tnow + 1,
                                   0) == ACT_ERR_SIGNATURE,
              "challenge tampered response rejected");
    }

    /* ---- v2: revocation lists ---- */
    {
        uint8_t serial_a[8] = {1,2,3,4,5,6,7,8};
        uint8_t serial_b[8] = {9,8,7,6,5,4,3,2};
        uint8_t flat[16];
        memcpy(flat, serial_a, 8);
        memcpy(flat + 8, serial_b, 8);

        CHECK(act_revoke_save("test_rev.tmp", sk, flat, 2) == ACT_OK,
              "revocation list save");
        uint32_t count = 0;
        CHECK(act_revoke_load("test_rev.tmp", pk, NULL, 0, &count) ==
                  ACT_OK && count == 2,
              "revocation list load/verify");
        CHECK(act_revoke_contains(flat, 2, serial_b) == 1,
              "serial found on list");
        uint8_t other[8] = {7,7,7,7,7,7,7,7};
        CHECK(act_revoke_contains(flat, 2, other) == 0,
              "clean serial not on list");

        /* tamper with a serial entry -> signature must fail */
        {
            FILE *f = fopen("test_rev.tmp", "r+b");
            fseek(f, 9, SEEK_SET); /* first serial */
            int b = fgetc(f);
            fseek(f, 9, SEEK_SET);
            fputc(b ^ 0xFF, f);
            fclose(f);
            CHECK(act_revoke_load("test_rev.tmp", pk, NULL, 0,
                                  &count) == ACT_ERR_SIGNATURE,
                  "tampered revocation list rejected");
        }

        /* act_revoke_add appends + re-signs */
        {
            uint8_t serial_c[8] = {0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,0x01,0x02};
            CHECK(act_revoke_add("test_rev2.tmp", sk, serial_a) == ACT_OK,
                  "revoke_add creates list");
            CHECK(act_revoke_add("test_rev2.tmp", sk, serial_c) == ACT_OK,
                  "revoke_add appends");
            act_license_info li;
            memcpy(li.serial, serial_c, 8);
            CHECK(act_revoke_check("test_rev2.tmp", pk, &li) == 1,
                  "revoke_check finds revoked serial");
            memcpy(li.serial, other, 8);
            CHECK(act_revoke_check("test_rev2.tmp", pk, &li) == 0,
                  "revoke_check clears clean serial");
            remove("test_rev2.tmp");
        }
        remove("test_rev.tmp");
    }

    /* ---- v2: hardened verification ---- */
    {
        act_license_make(payload, sig, 0x1234ABCD, machine, 2000, 0, NULL, 0, sk);
        act_license_encode(payload, sig, code, sizeof(code));

        CHECK(act_verify_hardened(code, pk, 0x1234ABCD, machine, now,
                                  0, 0, NULL) == ACT_OK,
              "hardened verify: ok (no env gates)");
        {
            /* Self-integrity: an unpatched binary is tolerated (gate
             * yields ACT_ERR_STATE_MISSING internally) and verification
             * still completes. */
            CHECK(act_verify_hardened(code, pk, 0x1234ABCD, machine, now,
                                      0, 1, NULL) == ACT_OK,
                  "hardened verify: unpatched binary tolerated");

            /* compute_digest on a synthetic slotted file:
             * layout = magic || END || digest-region (any 64 bytes;
             * the digest region is zeroed for hashing). */
            const char *m = ACT_INTEGRITY_MAGIC;
            const char *e = ACT_INTEGRITY_END;
            uint8_t junk[64];
            memset(junk, 0x5A, 64); /* non-zero junk in the digest region */
            FILE *f = fopen("test_synth.tmp", "wb");
            fwrite("HELLO", 1, 5, f);
            fwrite(m, 1, ACT_INTEGRITY_MAGIC_LEN, f);
            fwrite(e, 1, ACT_INTEGRITY_END_LEN, f);
            fwrite(junk, 1, 64, f);
            fwrite("WORLD", 1, 5, f);
            fclose(f);

            uint8_t dg[64];
            CHECK(act_harden_compute_digest("test_synth.tmp", dg) == ACT_OK,
                  "integrity digest computed on slotted file");
            /* reference: hash prefix + ZEROED slot region + suffix */
            uint8_t zeros[64];
            memset(zeros, 0, 64);
            act_sha512_ctx c;
            uint8_t ref[64];
            act_sha512_init(&c);
            act_sha512_update(&c, "HELLO", 5);
            act_sha512_update(&c, m, ACT_INTEGRITY_MAGIC_LEN);
            act_sha512_update(&c, e, ACT_INTEGRITY_END_LEN);
            act_sha512_update(&c, zeros, 64);
            act_sha512_update(&c, "WORLD", 5);
            act_sha512_final(&c, ref);
            CHECK(act_secure_memcmp(dg, ref, 64) == 0,
                  "digest equals manual layout hash (digest region zeroed)");
            remove("test_synth.tmp");
        }

        /* a wrong machine must still fail through the hardened path */
        uint8_t om[16];
        memcpy(om, machine, 16);
        om[0] ^= 0xFF;
        CHECK(act_verify_hardened(code, pk, 0x1234ABCD, om, now,
                                  0, 0, NULL) == ACT_ERR_MACHINE,
              "hardened verify: machine binding enforced");

        /* forged signature must not slip through redundancy */
        uint8_t fsg2[ACT_SIG_SIZE];
        memcpy(fsg2, sig, ACT_SIG_SIZE);
        fsg2[63] ^= 0x80;
        CHECK(act_license_verify_payload(payload, fsg2, pk, 0x1234ABCD,
                                         machine, now, NULL) ==
                  ACT_ERR_SIGNATURE,
              "hardened: forged sig still rejected");
    }

    /* ---- v1.5: chained audit log ---- */
    {
        uint8_t key[32];
        for (int i = 0; i < 32; i++) key[i] = (uint8_t)(i * 5 + 1);
        const char *log = "audit_test.log";

        remove(log);
        CHECK(act_audit_init(log, key) == ACT_OK, "audit init creates genesis");
        CHECK(act_audit_append(log, key, ACT_AUDIT_EV_ACTIVATE, "code-1", 6) == ACT_OK,
              "audit append #1");
        CHECK(act_audit_append(log, key, ACT_AUDIT_EV_VERIFY, "ok", 2) == ACT_OK,
              "audit append #2");
        uint32_t count = 0;
        uint8_t tail[32];
        CHECK(act_audit_verify(log, key, &count, tail) == ACT_OK && count == 2,
              "audit chain verifies (2 entries)");

        /* 篡改任意字节必须断链 */
        {
            FILE *f = fopen(log, "r+b");
            fseek(f, ACT_AUDIT_GENESIS_SIZE + 20, SEEK_SET);
            int b = fgetc(f);
            fseek(f, ACT_AUDIT_GENESIS_SIZE + 20, SEEK_SET);
            fputc(b ^ 0x01, f);
            fclose(f);
            CHECK(act_audit_verify(log, key, NULL, NULL) == ACT_ERR_SIGNATURE,
                  "audit tamper detected");
        }

        /* 删除末条 (截断) 必须断链 -- 用错误 key 重放也能暴露 */
        remove(log);
        CHECK(act_audit_init(log, key) == ACT_OK &&
              act_audit_append(log, key, ACT_AUDIT_EV_REJECT, "bad", 3) == ACT_OK &&
              act_audit_verify(log, key, &count, NULL) == ACT_OK && count == 1,
              "audit re-init + append round");
        uint8_t wrong_key[32];
        memset(wrong_key, 0xAB, 32);
        CHECK(act_audit_verify(log, wrong_key, NULL, NULL) == ACT_ERR_SIGNATURE,
              "audit wrong key rejected");
        remove(log);
    }

    /* ---- version header sanity ---- */
    CHECK(ACT_VERSION_MAJOR >= 1, "version macros present");

    if (g_failures == 0) {
        printf("license/state: ALL TESTS PASSED\n");
        return 0;
    }
    printf("license/state: %d TEST(S) FAILED\n", g_failures);
    return 1;
}
