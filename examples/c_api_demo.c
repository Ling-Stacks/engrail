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
 * @file  c_api_demo.c
 * @brief Pure-C integration demo: activation lifecycle without C++.
 *
 * Build (single-file amalgamation):
 *   cc -Idist c_api_demo.c dist/activation.c -o c_api_demo
 * Or against the static library:
 *   cc -Iinclude c_api_demo.c build/libactivation.a -o c_api_demo
 *
 * This demo embeds a demo public key + deployment salt (both PUBLIC
 * values) and walks through: machine code -> activation -> status query
 * -> feature tiers -> days remaining -> re-verify on "next startup".
 */

#include "activation/license.h"
#include "activation/fingerprint.h"
#include "activation/state.h"
#include "activation/sm2.h"

#include <stdio.h>
#include <string.h>
#include <time.h>

/* Demo deployment (public values from `engrail-keygen keygen`). */
static const uint8_t DEMO_PUBKEY[32] = {
    0x3b, 0x6a, 0x27, 0xbc, 0xce, 0xb6, 0xa4, 0x2d,
    0x62, 0xa3, 0xa8, 0xd0, 0x2a, 0x6f, 0x0d, 0x73,
    0x65, 0x32, 0x15, 0x77, 0x1d, 0xe2, 0x43, 0xa6,
    0x3a, 0xc0, 0x48, 0xa1, 0x8b, 0x59, 0xda, 0x29
};
static const uint8_t DEMO_DSALT[32] = { 0 }; /* demo: all-zero salt */

static const char *STATE_FILE = "demo_c_api.act";

static const char *status_text(act_status st)
{
    switch (st) {
    case ACT_OK:                return "ok";
    case ACT_ERR_FORMAT:        return "malformed code";
    case ACT_ERR_SIGNATURE:     return "forged / tampered";
    case ACT_ERR_MACHINE:       return "wrong machine";
    case ACT_ERR_EXPIRED:       return "expired";
    case ACT_ERR_STATE_MISSING: return "not activated yet";
    case ACT_ERR_REVOKED:       return "revoked";
    default:                    return "other error";
    }
}

int main(int argc, char **argv)
{
    uint8_t machine[16];
    char mc[ACT_MACHINE_CODE_STR_SIZE];

    /* 1. Machine code: what the customer sends to the vendor. */
    act_fingerprint(DEMO_PUBKEY, DEMO_DSALT, 1, NULL, 0, machine);
    act_fp_to_string(machine, mc);
    printf("machine code : %s\n", mc);

    /* 2. Activation (when a code is supplied on the command line). */
    if (argc > 1) {
        const act_status st = act_license_verify(argv[1], DEMO_PUBKEY, 1,
                                                  machine, (int64_t)time(NULL),
                                                  NULL);
        printf("code check   : %s\n", status_text(st));
        if (st != ACT_OK) {
            return 1;
        }
        uint8_t payload[ACT_PAYLOAD_SIZE], sig[ACT_SIG_SIZE];
        act_license_decode(argv[1], payload, sig);
        act_state_save(STATE_FILE, payload, sig);
        printf("state saved  : %s\n", STATE_FILE);
    }

    /* 3. SM2 bonus: national-crypto sign/verify in six lines. */
    {
        uint8_t pub[64], priv[32], sig[64];
        const char *msg = "pure C, zero deps";
        act_sm2_keypair(NULL, pub, priv);
        act_sm2_sign(sig, (const uint8_t *)msg, strlen(msg), priv, NULL);
        printf("SM2 sign/verify: %s\n",
               act_sm2_verify(sig, (const uint8_t *)msg, strlen(msg), pub,
                              NULL) == ACT_OK ? "ok" : "bad");
    }

    /* 4. Startup check: state file -> full re-verification. */
    {
        act_license_info info;
        memset(&info, 0, sizeof(info));
        const act_status st = act_state_check(STATE_FILE, DEMO_PUBKEY, 1,
                                              machine, (int64_t)time(NULL),
                                              &info);
        printf("license      : %s\n", status_text(st));
        if (st != ACT_OK) {
            printf("activate with: %s <activation-code>\n", argv[0]);
            return 0;
        }

        /* 5. Convenience queries. */
        printf("trial        : %s\n", info.trial ? "yes" : "no");
        printf("perpetual    : %s\n", info.perpetual ? "yes" : "no");
        printf("pro tier     : %s\n",
               act_has_feature(&info, 0) ? "yes" : "no");
        printf("days left    : %lld\n",
               (long long)act_days_remaining(&info, (int64_t)time(NULL)));
    }

    return 0;
}
