/*
 * MIT License
 *
 * Copyright (c) 2026 ActivationSystem Contributors
 *
 * smoke -- post-build self-test: linked against the freshly built
 * library, must complete in under a second. `make` runs this
 * automatically after a successful build (disable with
 * NO_SMOKETEST=1); a failure aborts the build with a clear error.
 *
 * Checks: version coherence, SM3/SHA-512 known answers, Ed25519
 * sign/verify, SM2 sign/verify, fingerprint shape, license
 * round-trip, keyfile encryption round-trip.
 */

#include "activation/ed25519.h"
#include "activation/fingerprint.h"
#include "activation/keyfile.h"
#include "activation/license.h"
#include "activation/random.h"
#include "activation/sha512.h"
#include "activation/sm2.h"
#include "activation/sm3.h"
#include "activation/version.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int failures = 0;

#define SMOKE(cond, msg)                                                       \
    do {                                                                       \
        if (cond) {                                                            \
            printf("  ok   %s\n", msg);                                        \
        } else {                                                               \
            printf("  FAIL %s\n", msg);                                        \
            failures++;                                                        \
        }                                                                      \
    } while (0)

int main(void)
{
    printf("smoke: ActivationSystem v%s post-build self-test\n", ACT_VERSION);

    /* 1. version coherence (configure injects the same version) */
    SMOKE(ACT_VERSION_MAJOR == 1 && ACT_VERSION_MINOR >= 5,
          "version macros coherent");

    /* 2. hash known answers */
    {
        uint8_t d[64];
        act_sha512("abc", 3, d);
        SMOKE(d[0] == 0xdd && d[1] == 0xaf, "sha512 KAT");
        act_sm3((const uint8_t *)"abc", 3, d);
        SMOKE(d[0] == 0x66 && d[1] == 0xc7, "sm3 KAT");
    }

    /* 3. Ed25519 sign/verify round-trip */
    {
        uint8_t seed[32], pk[32], sk[64], sig[64];
        for (int i = 0; i < 32; i++) {
            seed[i] = (uint8_t)(i * 3 + 1);
        }
        act_ed25519_keypair(seed, pk, sk);
        const uint8_t msg[] = "smoke";
        act_ed25519_sign(sig, msg, sizeof(msg) - 1, sk);
        SMOKE(act_ed25519_verify(sig, msg, sizeof(msg) - 1, pk) == 0,
              "ed25519 sign/verify");
        sig[0] ^= 1;
        SMOKE(act_ed25519_verify(sig, msg, sizeof(msg) - 1, pk) != 0,
              "ed25519 tamper rejection");
    }

    /* 4. SM2 sign/verify */
    {
        uint8_t pub[64], priv[32], sig[64];
        act_sm2_keypair(NULL, pub, priv);
        const uint8_t msg[] = "smoke-sm2";
        SMOKE(act_sm2_sign(sig, msg, sizeof(msg) - 1, priv, NULL) == ACT_OK,
              "sm2 sign");
        SMOKE(act_sm2_verify(sig, msg, sizeof(msg) - 1, pub, NULL) == ACT_OK,
              "sm2 verify");
    }

    /* 5. CSPRNG alive */
    {
        uint8_t a[32], b[32];
        act_random_bytes(a, 32);
        act_random_bytes(b, 32);
        SMOKE(memcmp(a, b, 32) != 0, "csprng draws differ");
    }

    /* 6. fingerprint shape */
    {
        uint8_t pk[32], ds[32], mc[16];
        memset(pk, 0x11, 32);
        memset(ds, 0x22, 32);
        act_fingerprint(pk, ds, 1, NULL, 0, mc);
        int nonzero = 0;
        for (int i = 0; i < 16; i++) {
            nonzero |= mc[i];
        }
        SMOKE(nonzero != 0, "fingerprint non-degenerate");
    }

    /* 7. license round-trip (fixed keys, no randomness in the path) */
    {
        uint8_t seed[32], pk[32], sk[64], mc[16];
        for (int i = 0; i < 32; i++) {
            seed[i] = (uint8_t)(i * 5 + 2);
        }
        act_ed25519_keypair(seed, pk, sk);
        for (int i = 0; i < 16; i++) {
            mc[i] = (uint8_t)(0x20 + i);
        }
        uint8_t payload[ACT_PAYLOAD_SIZE], sig[ACT_SIG_SIZE];
        act_license_make(payload, sig, 1, mc, 3000, 0, NULL, 0x1, sk);
        char code[ACT_CODE_MAX_CHARS];
        act_license_encode(payload, sig, code, sizeof(code));
        SMOKE(act_license_verify(code, pk, 1, mc, ACT_EXPIRY_EPOCH + 100 *
                                                          86400LL,
                                 NULL) == ACT_OK,
              "license round-trip");
    }

    /* 8. keyfile encryption round-trip (fast KDF for smoke only) */
    {
        uint8_t seed[32], ds[32], rs[32], rds[32];
        for (int i = 0; i < 32; i++) {
            seed[i] = (uint8_t)(i * 9 + 3);
            ds[i] = (uint8_t)(i * 4 + 7);
        }
        SMOKE(act_keyfile_save("smoke_kf.tmp", seed, ds, "pw", 64) == ACT_OK,
              "keyfile save");
        SMOKE(act_keyfile_load("smoke_kf.tmp", "pw", rs, rds) == ACT_OK &&
                  memcmp(rs, seed, 32) == 0,
              "keyfile load round-trip");
        SMOKE(act_keyfile_load("smoke_kf.tmp", "wrong", rs, rds) ==
                  ACT_ERR_SIGNATURE,
              "keyfile wrong passphrase rejected");
        remove("smoke_kf.tmp");
    }

    if (failures == 0) {
        printf("smoke: ALL CHECKS PASSED\n");
        return 0;
    }
    printf("smoke: %d CHECK(S) FAILED -- build output is broken\n", failures);
    return 1;
}
