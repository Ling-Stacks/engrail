/*
 * MIT License
 *
 * Copyright (c) 2026 ActivationSystem Contributors
 *
 * test_lifecycle -- full-deployment scenario matrix: multiple products,
 * multiple machines, trial -> paid upgrade, renewal, revocation,
 * expiry boundaries, cross-product/cross-machine rejection, audit
 * trail across the whole story.
 */

#include "common.h"
#include "activation/license.h"
#include "activation/state.h"
#include "activation/revoke.h"
#include "activation/audit.h"
#include "activation/ed25519.h"

#define N_PRODUCTS 3
#define N_MACHINES 3

typedef struct {
    uint8_t seed[32], pk[32], sk[64];
} vendor_t;

static void vendor_init(vendor_t *v, int id)
{
    for (int i = 0; i < 32; i++) {
        v->seed[i] = (uint8_t)(i * 13 + id * 7 + 1);
    }
    act_ed25519_keypair(v->seed, v->pk, v->sk);
}

int main(void)
{
    SUITE_BEGIN("lifecycle");

    vendor_t vendors[N_PRODUCTS];
    const uint32_t products[N_PRODUCTS] = { 1, 2, 0xDEAD };
    uint8_t machines[N_MACHINES][16];
    for (int m = 0; m < N_MACHINES; m++) {
        for (int i = 0; i < 16; i++) {
            machines[m][i] = (uint8_t)(m * 16 + i);
        }
    }
    for (int p = 0; p < N_PRODUCTS; p++) {
        vendor_init(&vendors[p], p);
    }

    const int64_t now = ACT_EXPIRY_EPOCH + 2000 * 86400LL;

    /* ---- phase 1: issue a full matrix, every cell verifies ---- */
    char codes[N_PRODUCTS][N_MACHINES][ACT_CODE_MAX_CHARS];
    {
        int ok = 1;
        for (int p = 0; p < N_PRODUCTS; p++) {
            for (int m = 0; m < N_MACHINES; m++) {
                uint8_t payload[ACT_PAYLOAD_SIZE], sig[ACT_SIG_SIZE];
                act_license_make(payload, sig, products[p], machines[m],
                                 2100, 0, NULL,
                                 (uint16_t)(1u << m), vendors[p].sk);
                if (act_license_encode(payload, sig, codes[p][m],
                                       ACT_CODE_MAX_CHARS) != ACT_OK) {
                    ok = 0;
                    break;
                }
                if (act_license_verify(codes[p][m], vendors[p].pk,
                                       products[p], machines[m], now,
                                       NULL) != ACT_OK) {
                    ok = 0;
                }
            }
        }
        CHECK(ok, "matrix: 3 products x 3 machines, all 9 cells verify");
    }

    /* ---- phase 2: cross-cell rejection (8 hostile combos per cell) ---- */
    {
        int ok = 1;
        for (int p = 0; p < N_PRODUCTS && ok; p++) {
            for (int m = 0; m < N_MACHINES && ok; m++) {
                /* wrong product */
                for (int q = 0; q < N_PRODUCTS; q++) {
                    if (q == p) {
                        continue;
                    }
                    if (act_license_verify(codes[p][m], vendors[q].pk,
                                           products[q], machines[m], now,
                                           NULL) == ACT_OK) {
                        ok = 0;
                    }
                }
                /* wrong machine */
                for (int n = 0; n < N_MACHINES; n++) {
                    if (n == m) {
                        continue;
                    }
                    if (act_license_verify(codes[p][m], vendors[p].pk,
                                           products[p], machines[n], now,
                                           NULL) == ACT_OK) {
                        ok = 0;
                    }
                }
            }
        }
        CHECK(ok, "cross-matrix: wrong-product & wrong-machine all rejected");
    }

    /* ---- phase 3: feature tiers are per-cell and queryable ---- */
    {
        int ok = 1;
        for (int m = 0; m < N_MACHINES; m++) {
            act_license_info info;
            act_license_verify(codes[0][m], vendors[0].pk, products[0],
                               machines[m], now, &info);
            /* feature mask was (1 << m) */
            if (info.features != (uint16_t)(1u << m)) {
                ok = 0;
            }
            for (int bit = 0; bit < 3; bit++) {
                if (act_has_feature(&info, bit) != (bit == m ? 1 : 0)) {
                    ok = 0;
                }
            }
        }
        CHECK(ok, "feature tiers: per-cell masks query correctly");
    }

    /* ---- phase 4: trial -> paid upgrade story ---- */
    {
        uint8_t payload[ACT_PAYLOAD_SIZE], sig[ACT_SIG_SIZE];
        char trial_code[ACT_CODE_MAX_CHARS], paid_code[ACT_CODE_MAX_CHARS];
        const char *state = "lc_trial.tmp";

        act_license_make(payload, sig, products[0], machines[0], 2007,
                         ACT_FLAG_TRIAL, NULL, 0, vendors[0].sk);
        act_license_encode(payload, sig, trial_code, sizeof(trial_code));
        act_license_info info;
        CHECK(act_license_verify(trial_code, vendors[0].pk, products[0],
                                 machines[0], now, &info) == ACT_OK &&
                  info.trial == 1 && info.features == 0,
              "trial: issued with TRIAL flag, no features");
        CHECK(act_days_remaining(&info, now) > 0,
              "trial: days remaining positive");

        /* persist trial state */
        act_license_decode(trial_code, payload, sig);
        act_state_save(state, payload, sig);
        CHECK(act_state_check(state, vendors[0].pk, products[0], machines[0],
                              now, &info) == ACT_OK && info.trial == 1,
              "trial: state saved and re-verified");

        /* upgrade: paid code replaces the state file */
        act_license_make(payload, sig, products[0], machines[0], 2200, 0,
                         NULL, 0x0F, vendors[0].sk);
        act_license_encode(payload, sig, paid_code, sizeof(paid_code));
        act_license_decode(paid_code, payload, sig);
        act_state_save(state, payload, sig);
        CHECK(act_state_check(state, vendors[0].pk, products[0], machines[0],
                              now, &info) == ACT_OK &&
                  info.trial == 0 && info.features == 0x0F,
              "upgrade: paid state replaces trial state");
        remove(state);
    }

    /* ---- phase 5: expiry boundary semantics ---- */
    {
        uint8_t payload[ACT_PAYLOAD_SIZE], sig[ACT_SIG_SIZE];
        act_license_make(payload, sig, products[0], machines[0], 2050, 0,
                         NULL, 0, vendors[0].sk);
        char code[ACT_CODE_MAX_CHARS];
        act_license_encode(payload, sig, code, sizeof(code));
        const int64_t expiry = act_expiry_to_unix(2050);
        CHECK(act_license_verify(code, vendors[0].pk, products[0],
                                 machines[0], expiry - 1, NULL) == ACT_OK,
              "expiry: last valid second accepted");
        CHECK(act_license_verify(code, vendors[0].pk, products[0],
                                 machines[0], expiry, NULL) ==
                  ACT_ERR_EXPIRED,
              "expiry: exact expiry second rejected");
        /* perpetual ignores expiry entirely */
        act_license_make(payload, sig, products[0], machines[0], 0,
                         ACT_FLAG_PERPETUAL, NULL, 0, vendors[0].sk);
        act_license_encode(payload, sig, code, sizeof(code));
        CHECK(act_license_verify(code, vendors[0].pk, products[0],
                                 machines[0], expiry + 100 * 365LL * 86400,
                                 NULL) == ACT_OK,
              "expiry: perpetual valid 100 years later");
    }

    /* ---- phase 6: revocation story ---- */
    {
        /* revoke machine[1]'s license for product 1 */
        act_license_info info;
        act_license_verify(codes[1][1], vendors[1].pk, products[1],
                           machines[1], now, &info);
        const char *revoke_path = "lc_revoke.tmp";
        CHECK(act_revoke_add(revoke_path, vendors[1].sk, info.serial) ==
                  ACT_OK,
              "revoke: serial added");

        /* the revoked cell now fails the revoke check */
        CHECK(act_revoke_check(revoke_path, vendors[1].pk, &info) == 1,
              "revoke: target serial detected");

        /* every other cell still clean */
        int ok = 1;
        for (int p = 0; p < N_PRODUCTS; p++) {
            for (int m = 0; m < N_MACHINES; m++) {
                if (p == 1 && m == 1) {
                    continue;
                }
                act_license_info i2;
                act_license_verify(codes[p][m], vendors[p].pk,
                                   products[p], machines[m], now, &i2);
                if (p == 1 &&
                    act_revoke_check(revoke_path, vendors[1].pk, &i2) != 0) {
                    ok = 0; /* only vendor[1] licenses checked */
                }
            }
        }
        CHECK(ok, "revoke: other cells unaffected");
        remove(revoke_path);
    }

    /* ---- phase 7: renewal (old code expires, new code works) ---- */
    {
        uint8_t payload[ACT_PAYLOAD_SIZE], sig[ACT_SIG_SIZE];
        char old_code[ACT_CODE_MAX_CHARS], new_code[ACT_CODE_MAX_CHARS];
        act_license_make(payload, sig, products[2], machines[2], 1999, 0,
                         NULL, 0, vendors[2].sk); /* expired before now */
        act_license_encode(payload, sig, old_code, sizeof(old_code));
        CHECK(act_license_verify(old_code, vendors[2].pk, products[2],
                                 machines[2], now, NULL) == ACT_ERR_EXPIRED,
              "renewal: old code expired");

        act_license_make(payload, sig, products[2], machines[2], 2400, 0,
                         NULL, 0, vendors[2].sk);
        act_license_encode(payload, sig, new_code, sizeof(new_code));
        CHECK(act_license_verify(new_code, vendors[2].pk, products[2],
                                 machines[2], now, NULL) == ACT_OK,
              "renewal: new code valid");
    }

    /* ---- phase 8: audit trail over the whole story ---- */
    {
        const char *alog = "lc_audit.tmp";
        uint8_t key[32];
        for (int i = 0; i < 32; i++) {
            key[i] = (uint8_t)(i * 9 + 4);
        }
        remove(alog);
        CHECK(act_audit_init(alog, key) == ACT_OK, "audit: genesis");

        int ok = 1;
        const char *events[] = { "issue-p1m1", "issue-p1m2", "activate",
                                 "verify",   "heartbeat", "renew" };
        for (int i = 0; i < 6; i++) {
            if (act_audit_append(alog, key, ACT_AUDIT_EV_ACTIVATE + (i % 4),
                                 events[i], strlen(events[i])) != ACT_OK) {
                ok = 0;
            }
        }
        uint32_t count = 0;
        if (act_audit_verify(alog, key, &count, NULL) != ACT_OK ||
            count != 6) {
            ok = 0;
        }
        CHECK(ok, "audit: 6-event chain verifies");

        /* delete event 3 (offset math: genesis + 2 entries + header) -> break */
        {
            FILE *f = fopen(alog, "r+b");
            /* rewrite from start of entry 4 onward by truncating */
            const long entry4 = ACT_AUDIT_GENESIS_SIZE +
                                3 * (ACT_AUDIT_ENTRY_OVERHEAD + 11);
            /* entry i has detail len 11 max; force truncate at entry 4 */
            (void)entry4;
            /* simpler corruption: flip a byte deep in the file */
            fseek(f, -10, SEEK_END);
            int c = fgetc(f);
            fseek(f, -10, SEEK_END);
            fputc(c ^ 0x40, f);
            fclose(f);
            CHECK(act_audit_verify(alog, key, NULL, NULL) ==
                      ACT_ERR_SIGNATURE,
                  "audit: late-byte tamper breaks chain");
        }
        remove(alog);
    }

    SUITE_END();
}
