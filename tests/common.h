/*
 * MIT License
 *
 * Copyright (c) 2026 ActivationSystem Contributors
 *
 * Shared test framework: check counting, hex helpers, deterministic
 * PRNG for fuzz-ish tests. Every suite includes this once.
 */

#ifndef ACT_TEST_COMMON_H
#define ACT_TEST_COMMON_H

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int act_t_pass = 0;
static int act_t_fail = 0;
static const char *act_t_suite = "?";

#define CHECK(cond, name)                                                    \
    do {                                                                     \
        if (cond) {                                                          \
            act_t_pass++;                                                    \
        } else {                                                             \
            act_t_fail++;                                                    \
            printf("[FAIL] %s (line %d)\n", name, __LINE__);                 \
        }                                                                    \
    } while (0)

#define CHECK_STR_EQ(got, want, name)                                        \
    do {                                                                     \
        if (strcmp((got), (want)) == 0) {                                    \
            act_t_pass++;                                                    \
        } else {                                                             \
            act_t_fail++;                                                    \
            printf("[FAIL] %s (line %d)\n  got  %s\n  want %s\n", name,       \
                   __LINE__, (got), (want));                                 \
        }                                                                    \
    } while (0)

#define SUITE_BEGIN(name)                                                    \
    do {                                                                     \
        act_t_suite = name;                                                  \
        printf("== %s ==\n", name);                                          \
    } while (0)

#define SUITE_END()                                                          \
    do {                                                                     \
        if (act_t_fail == 0) {                                               \
            printf("%s: ALL %d TESTS PASSED\n", act_t_suite, act_t_pass);    \
            return 0;                                                        \
        }                                                                    \
        printf("%s: %d FAILED, %d passed\n", act_t_suite, act_t_fail,        \
               act_t_pass);                                                  \
        return 1;                                                            \
    } while (0)

/* ---- hex helpers ---- */

static inline int act_hex2bin(const char *h, uint8_t *out, size_t n)
{
    if (strlen(h) != n * 2) {
        return -1;
    }
    for (size_t i = 0; i < n; i++) {
        unsigned v;
        if (sscanf(h + 2 * i, "%2x", &v) != 1) {
            return -1;
        }
        out[i] = (uint8_t)v;
    }
    return 0;
}

static inline void act_hex2bin_or_die(const char *h, uint8_t *out, size_t n)
{
    if (act_hex2bin(h, out, n) != 0) {
        fprintf(stderr, "bad hex fixture (len %zu want %zu)\n", strlen(h),
                n * 2);
        exit(2);
    }
}

static inline void act_bin2hex(const uint8_t *b, size_t n, char *out)
{
    static const char hx[] = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) {
        out[2 * i] = hx[b[i] >> 4];
        out[2 * i + 1] = hx[b[i] & 15];
    }
    out[2 * n] = '\0';
}

/* ---- deterministic PRNG (xorshift64*) for fuzz-ish suites ---- */

static uint64_t act_t_seed = 0x9E3779B97F4A7C15ull;

static inline void act_srand(uint64_t s)
{
    act_t_seed = s ? s : 1;
}

static inline uint64_t act_rand64(void)
{
    uint64_t x = act_t_seed;
    x ^= x >> 12;
    x ^= x << 25;
    x ^= x >> 27;
    act_t_seed = x;
    return x * 0x2545F4914F6CDD1Dull;
}

static inline void act_rand_bytes(uint8_t *buf, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        buf[i] = (uint8_t)(act_rand64() >> 32);
    }
}

#endif /* ACT_TEST_COMMON_H */
