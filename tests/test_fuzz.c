/*
 * MIT License
 *
 * Copyright (c) 2026 ActivationSystem Contributors
 *
 * test_fuzz -- deterministic robustness fuzzing of every parser /
 * decoder surface. Driven by a seeded xorshift PRNG (reproducible:
 * same seed, same corpus). Every input must return a sane status
 * code; crashes, hangs and OOB are failures.
 */

#include "common.h"
#include "activation/license.h"
#include "activation/token.h"
#include "activation/keyfile.h"
#include "activation/sm2.h"
#include "activation/ed25519.h"

#define ITER_RANDOM 20000
#define ITER_MUTATE 4000

/* run one license_decode input; returns 1 if it survived sanely */
static int try_license(const uint8_t *in, size_t n)
{
    char buf[512];
    uint8_t payload[ACT_PAYLOAD_SIZE], sig[ACT_SIG_SIZE];
    if (n > sizeof(buf) - 1) {
        n = sizeof(buf) - 1;
    }
    memcpy(buf, in, n);
    buf[n] = '\0';
    const act_status st = act_license_decode(buf, payload, sig);
    return st == ACT_OK || st == ACT_ERR_FORMAT || st == ACT_ERR_ARG;
}

static int try_token(const uint8_t *in, size_t n)
{
    char buf[600];
    if (n > sizeof(buf) - 1) {
        n = sizeof(buf) - 1;
    }
    memcpy(buf, in, n);
    buf[n] = '\0';
    uint8_t out[ACT_TOKEN_MAX_PAYLOAD] = {0};
    size_t olen = 0;
    const act_status st = act_token_verify(buf, out, sizeof(out), 0, NULL,
                                           0, &olen, NULL);
    return st == ACT_OK || st == ACT_ERR_FORMAT || st == ACT_ERR_PRODUCT ||
           st == ACT_ERR_SIGNATURE || st == ACT_ERR_EXPIRED ||
           st == ACT_ERR_ARG;
}

static int try_challenge(const uint8_t *in, size_t n)
{
    static uint8_t sk[64]; /* any key works: only the challenge is parsed */
    static int init = 0;
    if (!init) {
        uint8_t seed[32], pk[32];
        for (int i = 0; i < 32; i++) {
            seed[i] = (uint8_t)(i * 3 + 1);
        }
        act_ed25519_keypair(seed, pk, sk);
        init = 1;
    }
    char buf[300];
    if (n > sizeof(buf) - 1) {
        n = sizeof(buf) - 1;
    }
    memcpy(buf, in, n);
    buf[n] = '\0';
    char resp[128];
    const act_status st = act_challenge_respond(buf, sk, resp, sizeof(resp));
    return st == ACT_OK || st == ACT_ERR_FORMAT || st == ACT_ERR_ARG;
}

static int try_sm2_decrypt(const uint8_t *in, size_t n)
{
    uint8_t priv[32], out[256];
    for (int i = 0; i < 32; i++) {
        priv[i] = (uint8_t)(i * 5);
    }
    size_t olen = 0;
    const act_status st = act_sm2_decrypt(in, n, priv, out, sizeof(out),
                                          &olen);
    return st == ACT_OK || st == ACT_ERR_FORMAT || st == ACT_ERR_SIGNATURE ||
           st == ACT_ERR_ARG;
}

static int try_keyfile(const uint8_t *in, size_t n)
{
    char path[] = "fuzz_key.tmp";
    FILE *f = fopen(path, "wb");
    if (f == NULL) {
        return 1;
    }
    fwrite(in, 1, n, f);
    fclose(f);
    uint8_t seed[32], ds[32];
    const act_status st = act_keyfile_load(path, "fuzz-pass", seed, ds);
    remove(path);
    return st == ACT_OK || st == ACT_ERR_SIGNATURE ||
           st == ACT_ERR_STATE_MISSING || st == ACT_ERR_STATE_CORRUPT ||
           st == ACT_ERR_ARG;
}

int main(void)
{
    SUITE_BEGIN("fuzz");

    uint8_t corpus[512];

    /* ---- phase 1: purely random inputs (wide length sweep) ---- */
    {
        act_srand(0xAC1D2026ull);
        int ok = 1;
        for (int i = 0; i < ITER_RANDOM && ok; i++) {
            const size_t n = (size_t)(act_rand64() % (sizeof(corpus) + 1));
            act_rand_bytes(corpus, n);
            switch (i % 5) {
            case 0: ok = try_license(corpus, n); break;
            case 1: ok = try_token(corpus, n); break;
            case 2: ok = try_challenge(corpus, n); break;
            case 3: ok = try_sm2_decrypt(corpus, n); break;
            default: ok = try_keyfile(corpus, n); break;
            }
        }
        CHECK(ok, "random fuzz: 20k inputs, all parsers return sane codes");
    }

    /* ---- phase 2: structure-aware mutation of VALID artifacts ---- */
    {
        uint8_t seed[32], pk[32], sk[64];
        for (int i = 0; i < 32; i++) {
            seed[i] = (uint8_t)(i * 11 + 3);
        }
        act_ed25519_keypair(seed, pk, sk);
        uint8_t machine[16];
        for (int i = 0; i < 16; i++) {
            machine[i] = (uint8_t)(0x60 + i);
        }
        uint8_t payload[ACT_PAYLOAD_SIZE], sig[ACT_SIG_SIZE];
        act_license_make(payload, sig, 3, machine, 800, 0, NULL, 0, sk);
        char valid[ACT_CODE_MAX_CHARS];
        act_license_encode(payload, sig, valid, sizeof(valid));
        const size_t vlen = strlen(valid);

        char tok[ACT_TOKEN_MAX_CHARS(32) + 1];
        act_token_create(sk, 3, (const uint8_t *)"fuzz", 4, 60, tok,
                         sizeof(tok));
        const size_t tlen = strlen(tok);

        char chal[96], resp[128];
        act_challenge_create(machine, 3, 1700000000, chal, sizeof(chal));
        act_challenge_respond(chal, sk, resp, sizeof(resp));
        const size_t rlen = strlen(resp);

        act_srand(0xFEED5EEDull);
        int ok = 1;
        char mutated[600];
        (void)pk; (void)sk; (void)machine;
        for (int i = 0; i < ITER_MUTATE && ok; i++) {
            const char *base;
            size_t blen;
            switch (i % 4) {
            case 0: base = valid; blen = vlen; break;
            case 1: base = tok; blen = tlen; break;
            case 2: base = resp; blen = rlen; break;
            default: base = chal; blen = strlen(chal); break;
            }
            size_t n = blen;
            if (n > sizeof(mutated) - 1) {
                n = sizeof(mutated) - 1;
            }
            memcpy(mutated, base, n);
            /* 1-4 random mutations: flip / insert / truncate / extend */
            const int ops = 1 + (int)(act_rand64() % 4);
            for (int op = 0; op < ops && n > 0; op++) {
                const uint64_t r = act_rand64();
                const size_t pos = (size_t)(r % n);
                switch ((r >> 32) % 4) {
                case 0: mutated[pos] ^= (uint8_t)(1 << ((r >> 40) % 8)); break;
                case 1: mutated[pos] = (uint8_t)(r >> 48); break;
                case 2: n = pos; break;             /* truncate */
                default:
                    if (n < sizeof(mutated) - 1) {  /* append junk */
                        mutated[n++] = (uint8_t)(r >> 48);
                    }
                    break;
                }
            }
            mutated[n] = '\0';
            const act_status st = act_license_decode(mutated, payload, sig);
            if (st != ACT_OK && st != ACT_ERR_FORMAT && st != ACT_ERR_ARG) {
                ok = 0;
            }
        }
        CHECK(ok, "mutation fuzz: 4k valid-artifact mutants, sane codes only");
    }

    /* ---- phase 3: hostile lengths ---- */
    {
        int ok = 1;
        const char *empty = "";
        ok &= try_license((const uint8_t *)empty, 0);
        ok &= try_token((const uint8_t *)empty, 0);
        ok &= try_challenge((const uint8_t *)empty, 0);
        /* exactly-at / past boundary lengths */
        for (size_t n = 190; n <= 200; n++) {
            uint8_t b[256];
            memset(b, 'A', sizeof(b));
            ok &= try_license(b, n);
        }
        /* huge single line (newline injection) */
        uint8_t nl[300];
        memset(nl, 'A', sizeof(nl));
        nl[150] = '\n';
        nl[151] = 0;
        nl[299] = 0;
        ok &= try_license(nl, 300);
        CHECK(ok, "hostile lengths: empty/boundary/newline inputs");
    }

    SUITE_END();
}
