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
 * @file  sm2.c
 * @brief SM2 (GB/T 32918) over sm2p256v1. See sm2.h.
 *
 * Layering:
 *   1. 256-bit modular arithmetic -- Montgomery CIOS exactly as specified
 *      by Koc et al. ("Analyzing and Comparing Montgomery Multiplication
 *      Algorithms", IEEE Micro, 1996): n+1 word accumulator, per-row
 *      carry preserved into t[s], final conditional subtract.
 *      All domain constants (R, R^2, -m^-1 mod 2^32, m-2) are derived
 *      at runtime; the only literals are the published standard curve
 *      parameters.
 *   2. Jacobian point arithmetic -- doubling specialized for a = p - 3
 *      ( dbl-2001-b formula set), general addition (add-2007-bl),
 *      complete on the point-at-infinity via Z = 0.
 *   3. Constant-time scalar multiplication -- conditional-swap ladder,
 *      256 iterations, memory access independent of scalar bits.
 *   4. GB/T 32918.2-2016 signatures (Z_A || SM3, r/s with retry rules),
 *      GB/T 32918.4-2016 encryption (C1 || C3 || C2, KDF per 5.4.3).
 */

#include "activation/sm2.h"
#include "activation/random.h"
#include "activation/sha512.h"
#include "activation/sm3.h"

#include <stdlib.h>
#include <string.h>

/* Section 1: 256-bit integers and Montgomery arithmetic               */

/** 256-bit integer: 8 little-endian 32-bit limbs. */
typedef struct {
    uint32_t w[8];
} u256;

static int u256_cmp(const u256 *a, const u256 *b)
{
    for (int i = 7; i >= 0; i--) {
        if (a->w[i] != b->w[i]) {
            return a->w[i] < b->w[i] ? -1 : 1;
        }
    }
    return 0;
}

static int u256_is_zero(const u256 *a)
{
    uint32_t acc = 0;
    for (int i = 0; i < 8; i++) {
        acc |= a->w[i];
    }
    return acc == 0;
}

/** r = a + b (mod 2^256); returns the carry-out bit. */
static uint32_t u256_add_raw(u256 *r, const u256 *a, const u256 *b)
{
    uint64_t carry = 0;
    for (int i = 0; i < 8; i++) {
        carry += (uint64_t)a->w[i] + b->w[i];
        r->w[i] = (uint32_t)carry;
        carry >>= 32;
    }
    return (uint32_t)carry;
}

/** r = a - b (mod 2^256); returns the borrow-out bit. */
static uint32_t u256_sub_raw(u256 *r, const u256 *a, const u256 *b)
{
    uint32_t borrow = 0;
    for (int i = 0; i < 8; i++) {
        const uint64_t bi = (uint64_t)b->w[i] + borrow;
        if ((uint64_t)a->w[i] >= bi) {
            r->w[i] = (uint32_t)(a->w[i] - bi);
            borrow = 0;
        } else {
            /* a < b at this limb: wrap with 2^(32(i+1)) borrow */
            r->w[i] = (uint32_t)(((uint64_t)1 << 32) + a->w[i] - bi);
            borrow = 1;
        }
    }
    return borrow;
}

/** Load 32 big-endian bytes into limbs. */
static void u256_from_be(u256 *r, const uint8_t p[32])
{
    for (int i = 0; i < 8; i++) {
        const uint8_t *q = p + (28 - 4 * i);
        r->w[i] = ((uint32_t)q[0] << 24) | ((uint32_t)q[1] << 16) |
                  ((uint32_t)q[2] << 8) | (uint32_t)q[3];
    }
}

/** Store limbs as 32 big-endian bytes. */
static void u256_to_be(uint8_t out[32], const u256 *a)
{
    for (int i = 0; i < 8; i++) {
        uint8_t *q = out + (28 - 4 * i);
        q[0] = (uint8_t)(a->w[i] >> 24);
        q[1] = (uint8_t)(a->w[i] >> 16);
        q[2] = (uint8_t)(a->w[i] >> 8);
        q[3] = (uint8_t)(a->w[i]);
    }
}

/* Montgomery context                                                  */

typedef struct {
    u256 m;         /* modulus (odd, prime)                          */
    u256 r2;        /* 2^512 mod m -- to-Montgomery multiplier       */
    u256 one;       /* R mod m = 2^256 mod m -- Montgomery unity     */
    u256 m2;        /* m - 2 -- Fermat inversion exponent            */
    uint32_t n0inv; /* -m^-1 mod 2^32                                */
} mont_ctx;

/** x = 2*x mod m (shift left one bit, conditional subtract). */
static void mont_dblmod(u256 *x, const u256 *m)
{
    const uint32_t carry = (x->w[7] >> 31);
    for (int i = 7; i > 0; i--) {
        x->w[i] = (x->w[i] << 1) | (x->w[i - 1] >> 31);
    }
    x->w[0] <<= 1;
    if (carry || u256_cmp(x, m) >= 0) {
        u256 t;
        u256_sub_raw(&t, x, m);
        *x = t;
    }
}

static void mont_init(mont_ctx *ctx, const u256 *m)
{
    ctx->m = *m;

    /* n0inv = -(m^-1) mod 2^32 via Newton--Raphson on the odd low word:
     *   x_{k+1} = x_k * (2 - m0 * x_k)  mod 2^32
     * converges quadratically from x_0 = m0 (odd => correct mod 2^1). */
    uint32_t inv = m->w[0]; /* valid mod 2^1 */
    for (int i = 0; i < 5; i++) {
        inv *= 2u - m->w[0] * inv;
    }
    ctx->n0inv = 0u - inv; /* negate */

    /* one = 2^256 mod m: double 1 exactly 256 times.
     * r2   = 2^512 mod m: continue doubling 256 more times. */
    memset(&ctx->one, 0, sizeof(u256));
    ctx->one.w[0] = 1;
    for (int i = 0; i < 256; i++) {
        mont_dblmod(&ctx->one, m);
    }
    ctx->r2 = ctx->one;
    for (int i = 0; i < 256; i++) {
        mont_dblmod(&ctx->r2, m);
    }

    /* m - 2 (m > 2 for both field and order moduli). */
    u256 two = { { 2, 0, 0, 0, 0, 0, 0, 0 } };
    u256_sub_raw(&ctx->m2, m, &two);
}

/**
 * Montgomery multiplication, CIOS (coarsely integrated operand
 * scanning), Koc et al. 1996, with s = 8 words:
 *
 *   for i = 0 .. s-1:
 *       C := 0
 *       for j = 0 .. s-1:
 *           (C, S) := t[j] + a[j]*b[i] + C
 *           t[j]   := S
 *       (C, S) := t[s] + C
 *       t[s]   := S
 *       m_i    := t[0] * n0' mod 2^32
 *       (C, S) := t[0] + m_i*m[0]
 *       -- low word S discarded (it is zero by construction of n0')
 *       for j = 1 .. s-1:
 *           (C, S) := t[j] + m_i*m[j] + C
 *           t[j-1] := S
 *       (C, S) := t[s] + C
 *       t[s-1] := S
 *       t[s]   := C
 *   if t >= m: t -= m
 *
 * t has s+1 words; t never exceeds its capacity (Koec et al. lemma).
 * Result: a*b*R^-1 mod m with a, b < m.
 */
static void mont_mul(u256 *r, const u256 *a, const u256 *b,
                     const mont_ctx *ctx)
{
    uint32_t t[9]; /* t[0..8], plus implicit t[8+1] carry below */
    memset(t, 0, sizeof(t));

    for (int i = 0; i < 8; i++) {
        /* Row product: t += a * b[i] */
        uint64_t carry = 0;
        for (int j = 0; j < 8; j++) {
            carry += (uint64_t)t[j] + (uint64_t)a->w[j] * b->w[i];
            t[j] = (uint32_t)carry;
            carry >>= 32;
        }
        carry += t[8];
        t[8] = (uint32_t)carry; /* carry-out of t[8] is provably zero */

        /* Reduction row: t += m_i * m, shifted one word right */
        const uint32_t mi = t[0] * ctx->n0inv;
        uint64_t sum = (uint64_t)t[0] + (uint64_t)mi * ctx->m.w[0];
        carry = sum >> 32; /* low 32 bits are zero by construction */

        for (int j = 1; j < 8; j++) {
            carry += (uint64_t)t[j] + (uint64_t)mi * ctx->m.w[j];
            t[j - 1] = (uint32_t)carry;
            carry >>= 32;
        }
        carry += t[8];
        t[7] = (uint32_t)carry;
        t[8] = (uint32_t)(carry >> 32); /* preserve carry per spec */
    }

    u256 out;
    for (int j = 0; j < 8; j++) {
        out.w[j] = t[j];
    }
    /* t[8] must be zero for inputs < m; keep the final compare on the
     * low 256 bits and the standard single conditional subtract. */
    if (t[8] != 0 || u256_cmp(&out, &ctx->m) >= 0) {
        u256 tmp;
        u256_sub_raw(&tmp, &out, &ctx->m);
        out = tmp;
    }
    *r = out;
}

static void mont_sqr(u256 *r, const u256 *a, const mont_ctx *ctx)
{
    mont_mul(r, a, a, ctx);
}

/** Normal form -> Montgomery form: a * R mod m. */
static void to_mont(u256 *r, const u256 *a, const mont_ctx *ctx)
{
    mont_mul(r, a, &ctx->r2, ctx);
}

/** Montgomery form -> normal form: a * R^-1 mod m. */
static void from_mont(u256 *r, const u256 *a, const mont_ctx *ctx)
{
    u256 one = { { 1, 0, 0, 0, 0, 0, 0, 0 } };
    mont_mul(r, a, &one, ctx);
}

/** r = a + b mod m (normal form in/out). */
static void mont_add(u256 *r, const u256 *a, const u256 *b,
                     const mont_ctx *ctx)
{
    const uint32_t carry = u256_add_raw(r, a, b);
    if (carry != 0 || u256_cmp(r, &ctx->m) >= 0) {
        u256 t;
        u256_sub_raw(&t, r, &ctx->m);
        *r = t;
    }
}

/** r = a - b mod m (normal form in/out). */
static void mont_sub(u256 *r, const u256 *a, const u256 *b,
                     const mont_ctx *ctx)
{
    if (u256_cmp(a, b) >= 0) {
        u256_sub_raw(r, a, b);
    } else {
        u256 t;
        u256_sub_raw(&t, &ctx->m, b); /* m - b (b < m => valid) */
        u256_add_raw(r, a, &t);       /* a < b < m => no overflow */
    }
}

/** r = base^exp mod m (normal form in/out), left-to-right binary. */
static void mont_pow(u256 *r, const u256 *base, const u256 *exp,
                     const mont_ctx *ctx)
{
    u256 b;
    to_mont(&b, base, ctx);

    u256 result;
    memset(&result, 0, sizeof(result));
    result.w[0] = 1;
    to_mont(&result, &result, ctx); /* 1 in Montgomery form */

    for (int i = 255; i >= 0; i--) {
        mont_sqr(&result, &result, ctx);
        if ((exp->w[i / 32] >> (i % 32)) & 1u) {
            mont_mul(&result, &result, &b, ctx);
        }
    }
    from_mont(r, &result, ctx);
}

/** r = a^-1 mod m via Fermat: a^(m-2) mod m (m prime). */
static void mont_inv(u256 *r, const u256 *a, const mont_ctx *ctx)
{
    mont_pow(r, a, &ctx->m2, ctx);
}

/* Section 2: sm2p256v1 domain parameters (GB/T 32918.5-2016)          */

static const uint8_t SM2_P_BE[32] = {
    0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
};
static const uint8_t SM2_A_BE[32] = {
    0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFC
};
static const uint8_t SM2_B_BE[32] = {
    0x28, 0xE9, 0xFA, 0x9E, 0x9D, 0x9F, 0x5E, 0x34,
    0x4D, 0x5A, 0x9E, 0x4B, 0xCF, 0x65, 0x09, 0xA7,
    0xF3, 0x97, 0x89, 0xF5, 0x15, 0xAB, 0x8F, 0x92,
    0xDD, 0xBC, 0xBD, 0x41, 0x4D, 0x94, 0x0E, 0x93
};
static const uint8_t SM2_N_BE[32] = {
    0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0x72, 0x03, 0xDF, 0x6B, 0x21, 0xC6, 0x05, 0x2B,
    0x53, 0xBB, 0xF4, 0x09, 0x39, 0xD5, 0x41, 0x23
};
static const uint8_t SM2_GX_BE[32] = {
    0x32, 0xC4, 0xAE, 0x2C, 0x1F, 0x19, 0x81, 0x19,
    0x5F, 0x99, 0x04, 0x46, 0x6A, 0x39, 0xC9, 0x94,
    0x8F, 0xE3, 0x0B, 0xBF, 0xF2, 0x66, 0x0B, 0xE1,
    0x71, 0x5A, 0x45, 0x89, 0x33, 0x4C, 0x74, 0xC7
};
static const uint8_t SM2_GY_BE[32] = {
    0xBC, 0x37, 0x36, 0xA2, 0xF4, 0xF6, 0x77, 0x9C,
    0x59, 0xBD, 0xCE, 0xE3, 0x6B, 0x69, 0x21, 0x53,
    0xD0, 0xA9, 0x87, 0x7C, 0xC6, 0x2A, 0x47, 0x40,
    0x02, 0xDF, 0x32, 0xE5, 0x21, 0x39, 0xF0, 0xA0
};

static mont_ctx g_fp; /* GF(p) arithmetic context */
static mont_ctx g_fn; /* GF(n) arithmetic context  */

/*
 * Thread-safe one-time initialization of the two Montgomery contexts.
 * State values: 0 = uninitialized, 1 = some thread is computing,
 * 2 = ready. The computed constants are deterministic and idempotent;
 * the atomic dance only prevents torn reads of the contexts during
 * concurrent first use (Python/Java/Kotlin bindings are real callers).
 *
 * Preference order: C11 <stdatomic.h>, GCC/Clang __atomic builtins,
 * MSVC _InterlockedCompareExchange, plain volatile fallback (idempotent
 * writes of identical bytes -- benign on every supported target).
 */
#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L && \
    !defined(__STDC_NO_ATOMICS__)
#  include <stdatomic.h>
static atomic_int g_sm2_state;
static int sm2_state_load(void) { return atomic_load(&g_sm2_state); }
static int sm2_state_begin(void)
{
    int expected = 0;
    return atomic_compare_exchange_strong(&g_sm2_state, &expected, 1);
}
static void sm2_state_done(void) { atomic_store(&g_sm2_state, 2); }
#elif defined(__GNUC__)
static int g_sm2_state;
static int sm2_state_load(void) { return __atomic_load_n(&g_sm2_state, __ATOMIC_SEQ_CST); }
static int sm2_state_begin(void)
{
    int expected = 0;
    return __atomic_compare_exchange_n(&g_sm2_state, &expected, 1,
                                       0, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST);
}
static void sm2_state_done(void) { __atomic_store_n(&g_sm2_state, 2, __ATOMIC_SEQ_CST); }
#elif defined(_MSC_VER)
#  include <intrin.h>
static long g_sm2_state;
static int sm2_state_load(void)
{
    _ReadWriteBarrier();
    return (int)g_sm2_state;
}
static int sm2_state_begin(void)
{
    return _InterlockedCompareExchange(&g_sm2_state, 1, 0) == 0;
}
static void sm2_state_done(void)
{
    _InterlockedExchange(&g_sm2_state, 2);
}
#else
/* Fallback: plain volatile. Benign here -- every writer stores the same
 * deterministic bytes into disjoint static storage. */
static volatile int g_sm2_state;
static int sm2_state_load(void) { return g_sm2_state; }
static int sm2_state_begin(void)
{
    if (g_sm2_state != 0) { return 0; }
    g_sm2_state = 1;
    return 1;
}
static void sm2_state_done(void) { g_sm2_state = 2; }
#endif

static void sm2_init_ctx(void)
{
    if (sm2_state_load() == 2) {
        return; /* fast path: ready */
    }
    if (sm2_state_begin()) {
        u256 p, n;
        u256_from_be(&p, SM2_P_BE);
        u256_from_be(&n, SM2_N_BE);
        mont_init(&g_fp, &p);
        mont_init(&g_fn, &n);
        sm2_state_done();
        return;
    }
    while (sm2_state_load() != 2) {
        /* another thread is computing the constants; they are tiny
         * (two Montgomery contexts), so a bare spin beats a lock. */
    }
}

/* Section 3: Jacobian point arithmetic (Montgomery coordinates)       */

/** Jacobian projective point: (X : Y : Z) = (X/Z^2 : Y/Z^3 : 1). */
typedef struct {
    u256 x, y, z; /* z = 0 encodes the point at infinity */
} pt;

static void pt_set_inf(pt *p)
{
    memset(&p->x, 0, sizeof(u256));
    memset(&p->y, 0, sizeof(u256));
    p->y.w[0] = 1; /* conventional (1 : 1 : 0), any finite y works */
    memset(&p->z, 0, sizeof(u256));
}

/**
 * Doubling, dbl-2001-b (a = -3 specialization):
 *   delta = Z1^2, gamma = Y1^2, beta = X1*gamma
 *   alpha = 3*(X1-delta)*(X1+delta)
 *   X3 = alpha^2 - 8*beta
 *   Z3 = (Y1+Z1)^2 - gamma - delta
 *   Y3 = alpha*(4*beta - X3) - 8*gamma^2
 */
static void pt_double(pt *r, const pt *p)
{
    if (u256_is_zero(&p->z)) {
        *r = *p; /* O + O = O */
        return;
    }
    const mont_ctx *m = &g_fp;

    u256 delta, gamma, beta, alpha;
    mont_sqr(&delta, &p->z, m);
    mont_sqr(&gamma, &p->y, m);
    mont_mul(&beta, &p->x, &gamma, m);

    u256 xmd, xpd;
    mont_sub(&xmd, &p->x, &delta, m);
    mont_add(&xpd, &p->x, &delta, m);
    u256 xmd_xpd;
    mont_mul(&xmd_xpd, &xmd, &xpd, m);
    u256 three_xx;
    mont_add(&three_xx, &xmd_xpd, &xmd_xpd, m);
    mont_add(&alpha, &three_xx, &xmd_xpd, m); /* 3*(X-d)(X+d) */

    u256 beta2, beta4, beta8;
    mont_add(&beta2, &beta, &beta, m);
    mont_add(&beta4, &beta2, &beta2, m);
    mont_add(&beta8, &beta4, &beta4, m);

    mont_sqr(&r->x, &alpha, m);
    mont_sub(&r->x, &r->x, &beta8, m);

    u256 ypz;
    mont_add(&ypz, &p->y, &p->z, m);
    mont_sqr(&r->z, &ypz, m);
    mont_sub(&r->z, &r->z, &gamma, m);
    mont_sub(&r->z, &r->z, &delta, m);

    u256 gamma2, gamma2x2, gamma2x4, gamma2x8, b4mx;
    mont_sqr(&gamma2, &gamma, m);            /* gamma^2          */
    mont_add(&gamma2x2, &gamma2, &gamma2, m);   /* 2*gamma^2     */
    mont_add(&gamma2x4, &gamma2x2, &gamma2x2, m); /* 4*gamma^2   */
    mont_add(&gamma2x8, &gamma2x4, &gamma2x4, m); /* 8*gamma^2   */
    mont_sub(&b4mx, &beta4, &r->x, m);
    mont_mul(&r->y, &alpha, &b4mx, m);
    mont_sub(&r->y, &r->y, &gamma2x8, m);
}

/**
 * General addition, add-2007-bl:
 *   Z1Z1 = Z1^2, Z2Z2 = Z2^2
 *   U1 = X1*Z2Z2, U2 = X2*Z1Z1
 *   S1 = Y1*Z2Z2*Z2, S2 = Y2*Z1Z1*Z1
 *   H = U2-U1, R = S2-S1
 *   H = 0, R = 0  -> doubling
 *   H = 0, R != 0 -> point at infinity (P + (-P))
 *   I = (2H)^2, J = H*I, V = U1*I
 *   X3 = R^2 - J - 2V
 *   Y3 = R*(V - X3) - 2*S1*J
 *   Z3 = ((Z1+Z2)^2 - Z1Z1 - Z2Z2)*H
 * Infinity operands are handled by the Z = 0 checks first.
 */
static void pt_add(pt *r, const pt *p, const pt *q)
{
    if (u256_is_zero(&p->z)) {
        *r = *q;
        return;
    }
    if (u256_is_zero(&q->z)) {
        *r = *p;
        return;
    }
    const mont_ctx *m = &g_fp;

    u256 z1z1, z2z2;
    mont_sqr(&z1z1, &p->z, m);
    mont_sqr(&z2z2, &q->z, m);

    u256 u1, u2, s1, s2;
    u256 t;
    mont_mul(&u1, &p->x, &z2z2, m);
    mont_mul(&u2, &q->x, &z1z1, m);
    mont_mul(&t, &p->y, &z2z2, m);
    mont_mul(&s1, &t, &q->z, m);
    mont_mul(&t, &q->y, &z1z1, m);
    mont_mul(&s2, &t, &p->z, m);

    u256 h, rr, s2ms1;
    mont_sub(&h, &u2, &u1, m);
    mont_sub(&s2ms1, &s2, &s1, m);
    mont_add(&rr, &s2ms1, &s2ms1, m); /* r = 2*(S2 - S1) per add-2007-bl */

    if (u256_is_zero(&h)) {
        if (u256_is_zero(&rr)) {
            pt_double(r, p);
        } else {
            pt_set_inf(r);
        }
        return;
    }

    u256 twoh, i, j, v;
    mont_add(&twoh, &h, &h, m);
    mont_sqr(&i, &twoh, m);
    mont_mul(&j, &h, &i, m);
    mont_mul(&v, &u1, &i, m);

    mont_sqr(&r->x, &rr, m);
    mont_sub(&r->x, &r->x, &j, m);
    u256 v2;
    mont_add(&v2, &v, &v, m);
    mont_sub(&r->x, &r->x, &v2, m);

    u256 v_m_x3, s1j, s1j2;
    mont_sub(&v_m_x3, &v, &r->x, m);
    mont_mul(&r->y, &rr, &v_m_x3, m);
    mont_mul(&s1j, &s1, &j, m);
    mont_add(&s1j2, &s1j, &s1j, m);
    mont_sub(&r->y, &r->y, &s1j2, m);

    u256 zpz, zsq;
    mont_add(&zpz, &p->z, &q->z, m);
    mont_sqr(&zsq, &zpz, m);
    mont_sub(&zsq, &zsq, &z1z1, m);
    mont_sub(&zsq, &zsq, &z2z2, m);
    mont_mul(&r->z, &zsq, &h, m);
}

/** Branch-free conditional swap over all three coordinates. */
static void pt_cswap(pt *a, pt *b, uint32_t swap)
{
    const uint32_t mask = 0u - swap; /* 0xFFFFFFFF when swap == 1 */
    for (int i = 0; i < 8; i++) {
        uint32_t t;
        t = mask & (a->x.w[i] ^ b->x.w[i]);
        a->x.w[i] ^= t;
        b->x.w[i] ^= t;
        t = mask & (a->y.w[i] ^ b->y.w[i]);
        a->y.w[i] ^= t;
        b->y.w[i] ^= t;
        t = mask & (a->z.w[i] ^ b->z.w[i]);
        a->z.w[i] ^= t;
        b->z.w[i] ^= t;
    }
}

/** Affine bytes (big-endian x||y) -> Jacobian (Z = 1). */
static void pt_from_affine(pt *r, const uint8_t x[32], const uint8_t y[32])
{
    u256 tx, ty, one;
    u256_from_be(&tx, x);
    u256_from_be(&ty, y);
    to_mont(&r->x, &tx, &g_fp);
    to_mont(&r->y, &ty, &g_fp);
    memset(&one, 0, sizeof(one));
    one.w[0] = 1;
    to_mont(&r->z, &one, &g_fp);
}

/** Jacobian -> affine bytes; returns 0 for infinity, 1 otherwise. */
static int pt_to_affine(uint8_t x[32], uint8_t y[32], const pt *p)
{
    if (u256_is_zero(&p->z)) {
        return 0;
    }
    /* Z is stored in Montgomery form; mont_inv works in normal form,
     * so convert first and re-convert the inverse afterwards. */
    u256 z_norm, zinv_norm, zinv, zinv2, zinv3, ax, ay, tx, ty;
    from_mont(&z_norm, &p->z, &g_fp);
    mont_inv(&zinv_norm, &z_norm, &g_fp);
    to_mont(&zinv, &zinv_norm, &g_fp);
    mont_sqr(&zinv2, &zinv, &g_fp);
    mont_mul(&zinv3, &zinv2, &zinv, &g_fp);
    mont_mul(&ax, &p->x, &zinv2, &g_fp);
    mont_mul(&ay, &p->y, &zinv3, &g_fp);
    from_mont(&tx, &ax, &g_fp);
    from_mont(&ty, &ay, &g_fp);
    u256_to_be(x, &tx);
    u256_to_be(y, &ty);
    return 1;
}

/**
 * Constant-time ladder scalar multiplication, 256 fixed iterations:
 *   invariant: (acc, work) = (R, R + P)
 *   per bit: cswap by bit; work += acc; acc  = 2*acc; cswap back.
 * Memory access pattern and operation count are scalar-independent.
 * The scalar is 32 BIG-ENDIAN bytes (MSB first, k[0] bit 7 = value 2^255).
 */
static void pt_scalar_mul(pt *r, const pt *p, const uint8_t k[32])
{
    pt acc, work, tmp;
    pt_set_inf(&acc);
    work = *p;

    for (int i = 255; i >= 0; i--) {
        const uint32_t bit = (k[31 - i / 8] >> (i % 8)) & 1u;
        pt_cswap(&acc, &work, bit);
        pt_add(&tmp, &work, &acc);
        work = tmp;
        pt_double(&acc, &acc);
        pt_cswap(&acc, &work, bit);
    }
    *r = acc;
}

/** Affine in/out scalar multiplication: (x, y) = [k] * (px, py). */
static void scalar_mul_affine(uint8_t x[32], uint8_t y[32],
                              const uint8_t k[32],
                              const uint8_t px[32], const uint8_t py[32])
{
    pt base, out;
    pt_from_affine(&base, px, py);
    pt_scalar_mul(&out, &base, k);
    if (!pt_to_affine(x, y, &out)) {
        memset(x, 0, 32); /* infinity -> (0, 0), callers must range check */
        memset(y, 0, 32);
    }
}

/** Full curve-membership test: y^2 == x^3 + a*x + b (mod p). */
static int pt_affine_on_curve(const uint8_t x[32], const uint8_t y[32])
{
    u256 tx, ty, a, b, ax, lhs, rhs;
    u256_from_be(&tx, x);
    u256_from_be(&ty, y);
    u256_from_be(&a, SM2_A_BE);
    u256_from_be(&b, SM2_B_BE);

    to_mont(&tx, &tx, &g_fp);
    to_mont(&ty, &ty, &g_fp);
    to_mont(&a, &a, &g_fp);
    to_mont(&b, &b, &g_fp);

    mont_sqr(&lhs, &ty, &g_fp);          /* y^2 */
    mont_sqr(&ax, &tx, &g_fp);           /* x^2 */
    mont_mul(&rhs, &ax, &tx, &g_fp);     /* x^3 */
    mont_mul(&ax, &a, &tx, &g_fp);       /* a*x */
    mont_add(&rhs, &rhs, &ax, &g_fp);
    mont_add(&rhs, &rhs, &b, &g_fp);
    return u256_cmp(&lhs, &rhs) == 0;
}

/* Section 4: SM3-based constructions (Z_A, e, KDF)                    */

/** Z_A = SM3(ENTL_A || ID_A || a || b || x_G || y_G || x_A || y_A). */
static void compute_za(uint8_t za[32], const uint8_t pub[64], const char *id)
{
    const char *id_str = (id != NULL) ? id : ACT_SM2_DEFAULT_ID;
    const size_t id_len = strlen(id_str);
    const uint16_t entl = (uint16_t)(id_len * 8u);

    const uint8_t entl_be[2] = { (uint8_t)(entl >> 8), (uint8_t)entl };

    act_sm3_ctx ctx;
    act_sm3_init(&ctx);
    act_sm3_update(&ctx, entl_be, 2);
    act_sm3_update(&ctx, id_str, id_len);
    act_sm3_update(&ctx, SM2_A_BE, 32);
    act_sm3_update(&ctx, SM2_B_BE, 32);
    act_sm3_update(&ctx, SM2_GX_BE, 32);
    act_sm3_update(&ctx, SM2_GY_BE, 32);
    act_sm3_update(&ctx, pub, 64);
    act_sm3_final(&ctx, za);
}

/** e = integer value of SM3(Z_A || M). */
static void compute_e(u256 *e, const uint8_t za[32],
                      const uint8_t *msg, size_t len)
{
    uint8_t digest[32];
    act_sm3_ctx ctx;
    act_sm3_init(&ctx);
    act_sm3_update(&ctx, za, 32);
    act_sm3_update(&ctx, msg, len);
    act_sm3_final(&ctx, digest);
    u256_from_be(e, digest);
}

/**
 * KDF per GB/T 32918.4-2016 section 5.4.3:
 *   ct = 1; Ha_i = SM3(Z || ct_be32); K = first klen bits.
 * Returns ACT_ERR_ARG when the derived stream is all zeros (caller
 * must retry with a fresh ephemeral, per the standard).
 */
static act_status sm2_kdf(uint8_t *out, size_t out_len, const uint8_t z[64])
{
    uint32_t ct = 1;
    size_t done = 0;
    while (done < out_len) {
        uint8_t in[68];
        uint8_t digest[32];
        memcpy(in, z, 64);
        in[64] = (uint8_t)(ct >> 24);
        in[65] = (uint8_t)(ct >> 16);
        in[66] = (uint8_t)(ct >> 8);
        in[67] = (uint8_t)ct;
        act_sm3(in, sizeof(in), digest);
        const size_t take = (out_len - done < 32) ? (out_len - done) : 32;
        memcpy(out + done, digest, take);
        done += take;
        ct++;
    }
    uint8_t acc = 0;
    for (size_t i = 0; i < out_len; i++) {
        acc |= out[i];
    }
    return (acc == 0) ? ACT_ERR_ARG : ACT_OK;
}

/** Cryptographically random scalar in [1, n-1] via rejection. */
static int random_scalar(uint8_t k[32])
{
    u256 n, kv;
    u256_from_be(&n, SM2_N_BE);
    for (int tries = 0; tries < 64; tries++) {
        act_random_bytes(k, 32);
        k[0] &= 0x7F; /* bias towards < n; rejection below is exact */
        u256_from_be(&kv, k);
        if (!u256_is_zero(&kv) && u256_cmp(&kv, &n) < 0) {
            return 1;
        }
    }
    return 0;
}

/* Section 5: public API                                               */

void act_sm2_keypair_from_ed25519_seed(const uint8_t ed_seed[32],
                                       const char *info,
                                       uint8_t pub[ACT_SM2_PUB_SIZE],
                                       uint8_t priv[ACT_SM2_PRIV_SIZE])
{
    sm2_init_ctx();
    u256 d, n;
    u256_from_be(&n, SM2_N_BE);

    /* d = SHA512(ed_seed || info || "act-dual/sm2/v1")[0..31] mod n */
    act_sha512_ctx ctx;
    act_sha512_init(&ctx);
    act_sha512_update(&ctx, ed_seed, 32);
    if (info != NULL) {
        act_sha512_update(&ctx, info, strlen(info));
    }
    act_sha512_update(&ctx, "act-dual/sm2/v1", 15);
    uint8_t digest[ACT_SHA512_DIGEST_SIZE];
    act_sha512_final(&ctx, digest);

    u256_from_be(&d, digest);
    while (u256_is_zero(&d) || u256_cmp(&d, &n) >= 0) {
        /* extremely unlikely; re-hash to stay in range */
        act_sha512(digest, ACT_SHA512_DIGEST_SIZE, digest);
        u256_from_be(&d, digest);
    }
    u256_to_be(priv, &d);
    scalar_mul_affine(pub, pub + 32, priv, SM2_GX_BE, SM2_GY_BE);
    act_secure_wipe(digest, sizeof(digest));
}

void act_sm2_keypair(uint8_t seed[ACT_SM2_PRIV_SIZE],
                     uint8_t pub[ACT_SM2_PUB_SIZE],
                     uint8_t priv[ACT_SM2_PRIV_SIZE])
{
    sm2_init_ctx();

    uint8_t local[ACT_SM2_PRIV_SIZE];
    if (seed == NULL) {
        u256 n, kv;
        u256_from_be(&n, SM2_N_BE);
        do {
            act_random_bytes(local, ACT_SM2_PRIV_SIZE);
            local[0] &= 0x7F;
            u256_from_be(&kv, local);
        } while (u256_is_zero(&kv) || u256_cmp(&kv, &n) >= 0);
        seed = local;
    }

    memcpy(priv, seed, ACT_SM2_PRIV_SIZE);
    scalar_mul_affine(pub, pub + 32, priv, SM2_GX_BE, SM2_GY_BE);
    act_secure_wipe(local, sizeof(local));
}

act_status act_sm2_sign(uint8_t sig[ACT_SM2_SIG_SIZE],
                        const uint8_t *msg, size_t len,
                        const uint8_t priv[ACT_SM2_PRIV_SIZE],
                        const char *id)
{
    sm2_init_ctx();
    if (sig == NULL || priv == NULL || (msg == NULL && len > 0)) {
        return ACT_ERR_ARG;
    }

    /* A = dA * G (needed for Z_A). */
    uint8_t pub[ACT_SM2_PUB_SIZE];
    scalar_mul_affine(pub, pub + 32, priv, SM2_GX_BE, SM2_GY_BE);

    uint8_t za[32];
    compute_za(za, pub, id);
    u256 e;
    compute_e(&e, za, msg, len);

    u256 d;
    u256_from_be(&d, priv);
    u256 n;
    u256_from_be(&n, SM2_N_BE);

    u256 r, s;
    uint8_t k[32];
    uint8_t pxy[64];

    for (int attempt = 0; attempt < 64; attempt++) {
        if (!random_scalar(k)) {
            return (act_status)ACT_ERR_ENTROPY; /* system CSPRNG failed */
        }
        u256 k_v;
        u256_from_be(&k_v, k);

        /* (x1, y1) = [k]G */
        scalar_mul_affine(pxy, pxy + 32, k, SM2_GX_BE, SM2_GY_BE);
        u256 x1;
        u256_from_be(&x1, pxy);

        /* r = (e + x1) mod n; retry on r == 0 or r + k == n */
        mont_add(&r, &e, &x1, &g_fn);
        if (u256_is_zero(&r)) {
            continue;
        }
        u256 rpk;
        mont_add(&rpk, &r, &k_v, &g_fn);
        if (u256_is_zero(&rpk)) {
            continue;
        }

        u256 one_p_d;
        u256 one = { { 1, 0, 0, 0, 0, 0, 0, 0 } };
        mont_add(&one_p_d, &one, &d, &g_fn);
        u256 one_p_d_inv;
        mont_inv(&one_p_d_inv, &one_p_d, &g_fn);

        u256 r_mont, d_mont, rd_mont, rd;
        to_mont(&r_mont, &r, &g_fn);
        to_mont(&d_mont, &d, &g_fn);
        mont_mul(&rd_mont, &r_mont, &d_mont, &g_fn);
        from_mont(&rd, &rd_mont, &g_fn);

        u256 k_m_rd;
        mont_sub(&k_m_rd, &k_v, &rd, &g_fn);

        u256 k_m_rd_mont, inv_mont, s_mont;
        to_mont(&k_m_rd_mont, &k_m_rd, &g_fn);
        to_mont(&inv_mont, &one_p_d_inv, &g_fn);
        mont_mul(&s_mont, &k_m_rd_mont, &inv_mont, &g_fn);
        from_mont(&s, &s_mont, &g_fn);

        if (u256_is_zero(&s)) {
            continue;
        }

        u256_to_be(sig, &r);
        u256_to_be(sig + 32, &s);
        act_secure_wipe(k, sizeof(k));
        act_secure_wipe(pxy, sizeof(pxy));
        return ACT_OK;
    }
    /* 64 consecutive rejected draws: the randomness is not healthy. */
    return (act_status)ACT_ERR_ENTROPY;
}

act_status act_sm2_verify(const uint8_t sig[ACT_SM2_SIG_SIZE],
                          const uint8_t *msg, size_t len,
                          const uint8_t pub[ACT_SM2_PUB_SIZE],
                          const char *id)
{
    sm2_init_ctx();
    if (sig == NULL || pub == NULL || (msg == NULL && len > 0)) {
        return ACT_ERR_ARG;
    }

    u256 n;
    u256_from_be(&n, SM2_N_BE);

    u256 r, s;
    u256_from_be(&r, sig);
    u256_from_be(&s, sig + 32);
    if (u256_is_zero(&r) || u256_is_zero(&s) ||
        u256_cmp(&r, &n) >= 0 || u256_cmp(&s, &n) >= 0) {
        return (act_status)ACT_ERR_SIGNATURE;
    }

    /* Public key must be a point on the curve. */
    if (!pt_affine_on_curve(pub, pub + 32)) {
        return (act_status)ACT_ERR_SIGNATURE;
    }

    uint8_t za[32];
    compute_za(za, pub, id);
    u256 e;
    compute_e(&e, za, msg, len);

    /* t = (r + s) mod n, t != 0 */
    u256 t;
    mont_add(&t, &r, &s, &g_fn);
    if (u256_is_zero(&t)) {
        return (act_status)ACT_ERR_SIGNATURE;
    }

    /* (x1', y1') = [s]G + [t]PA */
    uint8_t s_be[32], t_be[32];
    u256_to_be(s_be, &s);
    u256_to_be(t_be, &t);

    uint8_t sgx[32], sgy[32], tpx[32], tpy[32];
    scalar_mul_affine(sgx, sgy, s_be, SM2_GX_BE, SM2_GY_BE);
    scalar_mul_affine(tpx, tpy, t_be, pub, pub + 32);

    pt p1, p2, sum;
    pt_from_affine(&p1, sgx, sgy);
    pt_from_affine(&p2, tpx, tpy);
    pt_add(&sum, &p1, &p2);

    uint8_t x1b[32], y1b[32];
    if (!pt_to_affine(x1b, y1b, &sum)) {
        return (act_status)ACT_ERR_SIGNATURE; /* infinity */
    }

    /* R = (e + x1') mod n; accept iff R == r */
    u256 x1, rr;
    u256_from_be(&x1, x1b);
    mont_add(&rr, &e, &x1, &g_fn);
    if (u256_cmp(&rr, &r) != 0) {
        return (act_status)ACT_ERR_SIGNATURE;
    }
    return ACT_OK;
}

act_status act_sm2_encrypt(const uint8_t pub[ACT_SM2_PUB_SIZE],
                           const uint8_t *msg, size_t len,
                           uint8_t *out, size_t out_cap, size_t *out_len)
{
    sm2_init_ctx();
    if (pub == NULL || out == NULL || (msg == NULL && len > 0) ||
        out_cap < len + 97) {
        return ACT_ERR_ARG;
    }
    if (!pt_affine_on_curve(pub, pub + 32)) {
        return ACT_ERR_ARG; /* refuse to encrypt to an off-curve key */
    }

    uint8_t k[32];
    uint8_t *stream = NULL;

    for (int attempt = 0; attempt < 64; attempt++) {
        if (!random_scalar(k)) {
            return (act_status)ACT_ERR_ENTROPY; /* system CSPRNG failed */
        }

        /* C1 = [k]G */
        uint8_t c1x[32], c1y[32];
        scalar_mul_affine(c1x, c1y, k, SM2_GX_BE, SM2_GY_BE);

        /* (x2, y2) = [k]PB */
        uint8_t x2[32], y2[32];
        scalar_mul_affine(x2, y2, k, pub, pub + 32);

        uint8_t z[64];
        memcpy(z, x2, 32);
        memcpy(z + 32, y2, 32);

        stream = (uint8_t *)malloc(len > 0 ? len : 1);
        if (stream == NULL) {
            return (act_status)ACT_ERR_STATE_IO;
        }
        if (sm2_kdf(stream, len, z) != ACT_OK) {
            act_secure_wipe(stream, len);
            free(stream);
            stream = NULL;
            continue; /* all-zero stream: standard-mandated retry */
        }

        /* out = C1 || C3 || C2 */
        out[0] = 0x04;
        memcpy(out + 1, c1x, 32);
        memcpy(out + 33, c1y, 32);

        act_sm3_ctx ctx;
        act_sm3_init(&ctx);
        act_sm3_update(&ctx, x2, 32);
        act_sm3_update(&ctx, msg, len);
        act_sm3_update(&ctx, y2, 32);
        act_sm3_final(&ctx, out + 65); /* C3 */

        for (size_t i = 0; i < len; i++) {
            out[97 + i] = msg[i] ^ stream[i]; /* C2 */
        }

        act_secure_wipe(stream, len);
        free(stream);
        act_secure_wipe(z, sizeof(z));
        act_secure_wipe(k, sizeof(k));

        if (out_len != NULL) {
            *out_len = len + 97;
        }
        return ACT_OK;
    }
    /* 64 consecutive rejected draws: the randomness is not healthy. */
    return (act_status)ACT_ERR_ENTROPY;
}

act_status act_sm2_decrypt(const uint8_t *in, size_t in_len,
                           const uint8_t priv[ACT_SM2_PRIV_SIZE],
                           uint8_t *out, size_t out_cap, size_t *out_len)
{
    sm2_init_ctx();
    if (in == NULL || priv == NULL || out == NULL || in_len < 98 ||
        in[0] != 0x04 || out_cap < in_len - 97) {
        return ACT_ERR_FORMAT;
    }
    const size_t klen = in_len - 97;

    /* C1 must be a valid curve point before any scalar multiplication
     * (GB/T 32918.4 input validation; also keeps the ladder off invalid
     * coordinates). */
    if (!pt_affine_on_curve(in + 1, in + 33)) {
        return (act_status)ACT_ERR_FORMAT;
    }

    /* (x2, y2) = dB * C1 */
    uint8_t x2[32], y2[32];
    scalar_mul_affine(x2, y2, priv, in + 1, in + 33);

    uint8_t z[64];
    memcpy(z, x2, 32);
    memcpy(z + 32, y2, 32);

    uint8_t *stream = (uint8_t *)malloc(klen > 0 ? klen : 1);
    if (stream == NULL) {
        return (act_status)ACT_ERR_STATE_IO;
    }
    if (sm2_kdf(stream, klen, z) != ACT_OK) {
        act_secure_wipe(stream, klen);
        free(stream);
        act_secure_wipe(z, sizeof(z));
        return (act_status)ACT_ERR_SIGNATURE;
    }

    for (size_t i = 0; i < klen; i++) {
        out[i] = in[97 + i] ^ stream[i];
    }

    /* C3 check: SM3(x2 || M' || y2) */
    uint8_t c3[32];
    act_sm3_ctx ctx;
    act_sm3_init(&ctx);
    act_sm3_update(&ctx, x2, 32);
    act_sm3_update(&ctx, out, klen);
    act_sm3_update(&ctx, y2, 32);
    act_sm3_final(&ctx, c3);

    const int ok = (act_secure_memcmp(c3, in + 65, 32) == 0);

    act_secure_wipe(stream, klen);
    free(stream);
    act_secure_wipe(z, sizeof(z));

    if (!ok) {
        return (act_status)ACT_ERR_SIGNATURE;
    }
    if (out_len != NULL) {
        *out_len = klen;
    }
    return ACT_OK;
}
