/*
 * MIT License
 *
 * Copyright (c) 2026 ActivationSystem Contributors
 *
 * test_dual -- dual-stack key derivation (Ed25519 seed -> SM2 keys)
 * and cross-stack signature interop.
 */

#include "common.h"
#include "activation/ed25519.h"
#include "activation/sm2.h"
#include "activation/random.h"
#include "activation/sha512.h"

int main(void)
{
    SUITE_BEGIN("dual");

    uint8_t seed[32], edpk[32], edsk[64];
    uint8_t sm2pub[64], sm2priv[32];

    /* deterministic seed battery */
    for (int variant = 0; variant < 4; variant++) {
        for (int i = 0; i < 32; i++) {
            seed[i] = (uint8_t)(i * 7 + variant * 31 + 1);
        }
        act_ed25519_keypair(seed, edpk, edsk);
        act_sm2_keypair_from_ed25519_seed(seed, NULL, sm2pub, sm2priv);

        char tag[96];

        /* determinism */
        {
            uint8_t pub2[64], priv2[32];
            act_sm2_keypair_from_ed25519_seed(seed, NULL, pub2, priv2);
            snprintf(tag, sizeof(tag), "v%d: deterministic", variant);
            CHECK(memcmp(sm2pub, pub2, 64) == 0 &&
                      memcmp(sm2priv, priv2, 32) == 0,
                  tag);
        }

        /* info diversification */
        {
            uint8_t pub_b[64], priv_b[32];
            act_sm2_keypair_from_ed25519_seed(seed, "purpose-b", pub_b,
                                              priv_b);
            snprintf(tag, sizeof(tag), "v%d: info diversifies", variant);
            CHECK(memcmp(sm2priv, priv_b, 32) != 0, tag);

            /* different info still yields a WORKING keypair */
            const uint8_t msg[] = "dual info-b";
            uint8_t sig[64];
            snprintf(tag, sizeof(tag), "v%d: info-b key signs", variant);
            CHECK(act_sm2_sign(sig, msg, sizeof(msg) - 1, priv_b, NULL) ==
                      ACT_OK &&
                  act_sm2_verify(sig, msg, sizeof(msg) - 1, pub_b, NULL) ==
                      ACT_OK,
                  tag);
        }

        /* dual-stack: same message, both stacks sign & verify */
        {
            const uint8_t msg[] = "dual-stack message";
            uint8_t sm2sig[64], edsig[64];
            snprintf(tag, sizeof(tag), "v%d: sm2 stack works", variant);
            CHECK(act_sm2_sign(sm2sig, msg, sizeof(msg) - 1, sm2priv,
                               NULL) == ACT_OK &&
                  act_sm2_verify(sm2sig, msg, sizeof(msg) - 1, sm2pub,
                                 NULL) == ACT_OK,
                  tag);
            snprintf(tag, sizeof(tag), "v%d: ed25519 stack works", variant);
            act_ed25519_sign(edsig, msg, sizeof(msg) - 1, edsk);
            CHECK(act_ed25519_verify(edsig, msg, sizeof(msg) - 1, edpk) == 0,
                  tag);

            /* cross-stack non-confusion: ed sig never validates under sm2 */
            snprintf(tag, sizeof(tag), "v%d: stacks do not cross-accept",
                     variant);
            CHECK(act_sm2_verify(edsig, msg, sizeof(msg) - 1, sm2pub,
                                 NULL) != ACT_OK,
                  tag);
        }

        /* distinct seeds -> distinct derived keys */
        {
            uint8_t seed2[32], pub2[64], priv2[32];
            memcpy(seed2, seed, 32);
            seed2[0] ^= 0x01;
            act_sm2_keypair_from_ed25519_seed(seed2, NULL, pub2, priv2);
            snprintf(tag, sizeof(tag), "v%d: seed bit-flip changes keys",
                     variant);
            CHECK(memcmp(sm2priv, priv2, 32) != 0, tag);
        }
    }

    /* full-round: license signed on ed25519 stack, SM2-encrypted secret,
     * all from ONE seed (the dual-compliance vendor story) */
    {
        uint8_t seed[32];
        act_random_bytes(seed, 32);
        uint8_t edpk[32], edsk[64], sm2pub[64], sm2priv[32];
        act_ed25519_keypair(seed, edpk, edsk);
        act_sm2_keypair_from_ed25519_seed(seed, NULL, sm2pub, sm2priv);

        uint8_t machine[16];
        for (int i = 0; i < 16; i++) {
            machine[i] = (uint8_t)(0x30 + i);
        }
        uint8_t payload[ACT_PAYLOAD_SIZE], sig[ACT_SIG_SIZE];
        act_license_make(payload, sig, 7, machine, 999, 0, NULL, 0x11, edsk);
        CHECK(act_license_verify_payload(payload, sig, edpk, 7, machine,
                                         ACT_EXPIRY_EPOCH + 500 * 86400LL,
                                         NULL) == ACT_OK,
              "vendor story: ed25519 license verifies");

        const uint8_t secret[] = "premium-tier unlock";
        uint8_t ct[97 + sizeof(secret)];
        size_t ctlen = 0;
        CHECK(act_sm2_encrypt(sm2pub, secret, sizeof(secret) - 1, ct,
                              sizeof(ct), &ctlen) == ACT_OK,
              "vendor story: sm2 encrypt from same seed");
        uint8_t pt[64];
        size_t ptlen = 0;
        CHECK(act_sm2_decrypt(ct, ctlen, sm2priv, pt, sizeof(pt), &ptlen) ==
                  ACT_OK &&
                  ptlen == sizeof(secret) - 1 &&
                  memcmp(pt, secret, ptlen) == 0,
              "vendor story: sm2 decrypt round-trip");
    }

    SUITE_END();
}
