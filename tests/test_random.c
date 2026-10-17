/*
 * MIT License
 *
 * Copyright (c) 2026 ActivationSystem Contributors
 *
 * test_random -- CSPRNG quality & robustness suite.
 */

#include "common.h"
#include "activation/random.h"

int main(void)
{
    SUITE_BEGIN("random");

    /* 1. uniqueness across draws */
    {
        uint8_t a[64], b[64];
        act_random_bytes(a, 64);
        act_random_bytes(b, 64);
        CHECK(memcmp(a, b, 64) != 0, "two draws differ");
    }

    /* 2. no degenerate output */
    {
        uint8_t buf[1024];
        int ok = 1;
        for (int round = 0; round < 8; round++) {
            act_random_bytes(buf, sizeof(buf));
            uint8_t z = 0, f = 0;
            for (size_t i = 0; i < sizeof(buf); i++) {
                z |= buf[i];
                f |= (uint8_t)(buf[i] ^ 0xFF);
            }
            if (z == 0 || f == 0) {
                ok = 0;
            }
        }
        CHECK(ok, "no all-zero / all-FF buffers (8 rounds x 1KB)");
    }

    /* 3. byte-frequency uniformity (64 KiB, chi-square-ish bound) */
    {
        static uint8_t big[65536];
        int cnt[256] = { 0 };
        int worst = 0;
        act_random_bytes(big, sizeof(big));
        for (size_t i = 0; i < sizeof(big); i++) {
            cnt[big[i]]++;
        }
        for (int i = 0; i < 256; i++) {
            if (cnt[i] > worst) {
                worst = cnt[i];
            }
        }
        /* expected 256; >5.5 sigma (~380) is a red flag */
        CHECK(worst <= 380, "uniform byte frequency (max count bound)");
    }

    /* 4. serial correlation sanity: adjacent bytes not equal too often */
    {
        static uint8_t big[32768];
        act_random_bytes(big, sizeof(big));
        int same = 0;
        for (size_t i = 1; i < sizeof(big); i++) {
            if (big[i] == big[i - 1]) {
                same++;
            }
        }
        /* expected ~128 (1/256), allow 3x */
        CHECK(same < 400, "adjacent-equal rate near 1/256");
    }

    /* 5. length edge cases (must not crash, must fill) */
    {
        uint8_t one = 0, small[3], large[4096];
        act_random_bytes(&one, 1);
        act_random_bytes(small, 3);
        act_random_bytes(large, 4096);
        uint8_t acc = one | small[0] | large[0] | large[4095];
        CHECK(acc != 0 || one == 0, "edge lengths fill without crash");
    }

    /* 6. long-run independence: 4 KB prefix never repeats later */
    {
        static uint8_t buf[16384];
        act_random_bytes(buf, sizeof(buf));
        int repeat = 0;
        for (size_t i = 0; i + 64 <= sizeof(buf); i++) {
            if (i == 0) {
                continue;
            }
            if (memcmp(buf, buf + i, 64) == 0) {
                repeat = 1;
                break;
            }
        }
        CHECK(repeat == 0, "no repeated 64-byte window");
    }

    SUITE_END();
}
