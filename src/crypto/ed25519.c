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
 * @file  ed25519.c
 * @brief Ed25519 (RFC 8032) over Curve25519 / GF(2^255-19).
 *
 * Provenance: the field/scalar arithmetic (car25519, sel25519,
 * pack25519, fmul/fadd/fsub/modL, unpackneg and the cswap ladder
 * structure) is a port of TweetNaCl (public domain, Bernstein et al.),
 * restructured for readability and hardened on top:
 * - signature scalar `s` canonical-range check before acceptance,
 * - constant-time comparison finish (no early-exit memcmp),
 * - secret material wiped after use.
 * All other primitives in this library (SHA-512, HMAC, ChaCha20, HKDF,
 * PBKDF2, SM3, SM2) are independent implementations.
 *
 * Implementation notes
 * - Field elements ("gf") are arrays of 16 x int64 limbs, each holding a
 *   16-bit value with lazy carrying. This shape avoids any 128-bit type and
 *   therefore compiles safely on 32-bit and 64-bit targets alike.
 * - Points are represented in extended twisted-Edwards coordinates (X, Y, Z, T)
 *   with x = X/Z, y = Y/Z, T = XY/Z.
 * - Scalar multiplication uses a constant-time Montgomery-style ladder
 *   (double-and-add with conditional swap), which does not leak the scalar
 *   through memory-access timing.
 * - Signature scheme is deterministic Ed25519 per RFC 8032 (the nonce derives
 *   from the private key prefix + message, so signing never needs fresh
 *   randomness and never repeats a nonce even with a broken RNG).
 *
 * The curve/group constants below are the standard ones for Curve25519
 * (order L, base point (X, Y), sqrt(-1) = I, curve parameter D).
 */

#include "activation/ed25519.h"
#include "activation/sha512.h"
#include "activation/random.h"

#include <string.h>

/* Small helpers                                                       */

typedef int64_t gf[16];   /**< field element, 16 limbs of ~16 bits */

#define FOR(i, n) for (i = 0; i < (n); ++i)

/** Copy field element @p a into @p r. */
static void set25519(gf r, const gf a)
{
    int i;
    FOR(i, 16) r[i] = a[i];
}

/* Curve constants (little-endian 16-bit limbs)                        */

static const gf gf0 = { 0 };                           /* 0                */
static const gf gf1 = { 1 };                           /* 1                */
/** sqrt(-1) mod p = 2^((p-1)/4) */
static const gf D_I = {
    0xa0b0, 0x4a0e, 0x1b27, 0xc4ee, 0xe478, 0xad2f, 0x1806, 0x2f43,
    0xd7a7, 0x3dfb, 0x0099, 0x2b4d, 0xdf0b, 0x4fc1, 0x2480, 0x2b83
};
/** D = -121665/121666 mod p (twisted Edwards curve parameter) */
static const gf D = {
    0x78a3, 0x1359, 0x4dca, 0x75eb, 0xd8ab, 0x4141, 0x0a4d, 0x0070,
    0xe898, 0x7779, 0x4079, 0x8cc7, 0xfe73, 0x2b6f, 0x6cee, 0x5203
};
/** 2 * D mod p (= 0x2406d9dc56dffce7198e80f2eef3d13000e0149a8283b156ebd69b9426b2f159) */
static const gf D2 = {
    0xf159, 0x26b2, 0x9b94, 0xebd6, 0xb156, 0x8283, 0x149a, 0x00e0,
    0xd130, 0xeef3, 0x80f2, 0x198e, 0xfce7, 0x56df, 0xd9dc, 0x2406
};
/** Base point x coordinate */
static const gf BX = {
    0xd51a, 0x8f25, 0x2d60, 0xc956, 0xa7b2, 0x9525, 0xc760, 0x692c,
    0xdc5c, 0xfdd6, 0xe231, 0xc0a4, 0x53fe, 0xcd6e, 0x36d3, 0x2169
};
/** Base point y coordinate = 4/5 */
static const gf BY = {
    0x6658, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666,
    0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666
};

/** Group order L = 2^252 + 27742317777372353535851937790883648493 (LE bytes) */
static const uint8_t ORDER_L[32] = {
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
    0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10
};

/* Field arithmetic mod 2^255 - 19                                     */

/** Carry propagation, reducing limbs back into the 16-bit range. */
static void car25519(gf o)
{
    int i;
    for (i = 0; i < 16; i++) {
        o[i] += 1LL << 16;
        const int64_t c = o[i] >> 16;
        o[(i + 1) * (i < 15)] += c - 1 + 37 * (c - 1) * (i == 15);
        o[i] -= c << 16;
    }
}

/** Conditional swap of two field elements (branch-free, constant time). */
static void sel25519(gf p, gf q, int64_t b)
{
    int64_t t, c = ~(b - 1);
    int i;
    FOR(i, 16) {
        t = c & (p[i] ^ q[i]);
        p[i] ^= t;
        q[i] ^= t;
    }
}

/** Pack field element into 32 little-endian bytes (fully reduced). */
static void pack25519(uint8_t *o, const gf n)
{
    int i, j, b;
    gf t, m;
    set25519(t, n);
    car25519(t);
    car25519(t);
    car25519(t);
    for (j = 0; j < 2; j++) {
        m[0] = t[0] - 0xffed;
        for (i = 1; i < 15; i++) {
            m[i] = t[i] - 0xffff - ((m[i - 1] >> 16) & 1);
            m[i - 1] &= 0xffff;
        }
        m[15] = t[15] - 0x7fff - ((m[14] >> 16) & 1);
        b = (int)((m[15] >> 16) & 1);
        m[14] &= 0xffff;
        sel25519(t, m, 1 - b);
    }
    FOR(i, 16) {
        o[2 * i] = (uint8_t)(t[i] & 0xff);
        o[2 * i + 1] = (uint8_t)(t[i] >> 8);
    }
}

/** Parity (low bit) of the canonical encoding of a field element. */
static int par25519(const gf a)
{
    uint8_t d[32];
    pack25519(d, a);
    return d[0] & 1;
}

/** Load field element from 32 little-endian bytes (masking the top bit). */
static void unpack25519(gf o, const uint8_t *n)
{
    int i;
    FOR(i, 16) o[i] = n[2 * i] + ((int64_t)n[2 * i + 1] << 8);
    o[15] &= 0x7fff;
}

/** Compare canonical encodings of two field elements. */
static int neq25519(const gf a, const gf b)
{
    uint8_t c[32], d[32];
    pack25519(c, a);
    pack25519(d, b);
    return act_secure_memcmp(c, d, 32);
}

/** o = a + b (no carrying; input limbs stay small). */
static void fadd(gf o, const gf a, const gf b)
{
    int i;
    FOR(i, 16) o[i] = a[i] + b[i];
}

/** o = a - b (no carrying). */
static void fsub(gf o, const gf a, const gf b)
{
    int i;
    FOR(i, 16) o[i] = a[i] - b[i];
}

/** o = a * b mod p (schoolbook 16x16 with delayed reduction). */
static void fmul(gf o, const gf a, const gf b)
{
    int64_t t[31];
    int i, j;
    FOR(i, 31) t[i] = 0;
    FOR(i, 16) FOR(j, 16) t[i + j] += a[i] * b[j];
    FOR(i, 15) t[i] += 38 * t[i + 16]; /* 2^256 ≡ 38 (mod p) */
    FOR(i, 16) o[i] = t[i];
    car25519(o);
    car25519(o);
}

/** o = a^2 mod p. */
static void fsqr(gf o, const gf a)
{
    fmul(o, a, a);
}

/** o = a^-1 mod p via Fermat: a^(p-2). */
static void inv25519(gf o, const gf i)
{
    gf c;
    int a;
    set25519(c, i);
    for (a = 253; a >= 0; a--) {
        fsqr(c, c);
        if (a != 2 && a != 4) {
            fmul(c, c, i);
        }
    }
    set25519(o, c);
}

/** o = i^(p+1)/8 - 2^252 (used for the square-root computation). */
static void pow2523(gf o, const gf i)
{
    gf c;
    int a;
    set25519(c, i);
    for (a = 250; a >= 0; a--) {
        fsqr(c, c);
        if (a != 1) {
            fmul(c, c, i);
        }
    }
    set25519(o, c);
}

/* Group arithmetic (extended twisted-Edwards coordinates)             */

/** Extended point: (X, Y, Z, T) with x = X/Z, y = Y/Z, T = XY/Z. */
typedef struct {
    gf coord[4];
} act_ge_point;

/** Conditional swap of two points (constant time). */
static void cswap_pt(act_ge_point *p, act_ge_point *q, uint8_t b)
{
    int i;
    FOR(i, 4) sel25519(p->coord[i], q->coord[i], b);
}

/**
 * @brief Twisted Edwards addition: p += q (mixed-affine-free, unified).
 *
 * Unified formula -- works for doubling as well, so callers never need
 * special cases.
 */
static void ge_add(act_ge_point *p, const act_ge_point *q)
{
    gf a, b, c, d, t, e, f, g, h;

    fsub(a, p->coord[1], p->coord[0]);
    fsub(t, q->coord[1], q->coord[0]);
    fmul(a, a, t);
    fadd(b, p->coord[0], p->coord[1]);
    fadd(t, q->coord[0], q->coord[1]);
    fmul(b, b, t);
    fmul(c, p->coord[3], q->coord[3]);
    fmul(c, c, D2);
    fmul(d, p->coord[2], q->coord[2]);
    fadd(d, d, d);
    fsub(e, b, a);
    fsub(f, d, c);
    fadd(g, d, c);
    fadd(h, b, a);

    fmul(p->coord[0], e, f);
    fmul(p->coord[1], h, g);
    fmul(p->coord[2], g, f);
    fmul(p->coord[3], e, h);
}

/**
 * @brief Constant-time scalar multiplication: p = [s] * q.
 *
 * Montgomery-ladder style double-and-add over all 256 scalar bits with a
 * conditional swap per bit; no data-dependent branches or memory accesses.
 *
 * @param[out] p result point.
 * @param[in]  q input point (must be a valid group element).
 * @param[in]  s 32-byte little-endian scalar.
 */
static void scalarmult(act_ge_point *p, const act_ge_point *q, const uint8_t *s)
{
    act_ge_point acc, work;
    int i;

    set25519(acc.coord[0], gf0);
    set25519(acc.coord[1], gf1);
    set25519(acc.coord[2], gf1);
    set25519(acc.coord[3], gf0); /* identity */
    set25519(work.coord[0], q->coord[0]);
    set25519(work.coord[1], q->coord[1]);
    set25519(work.coord[2], q->coord[2]);
    set25519(work.coord[3], q->coord[3]);

    for (i = 255; i >= 0; i--) {
        const uint8_t b = (uint8_t)((s[i / 8] >> (i & 7)) & 1);
        cswap_pt(&acc, &work, b);
        ge_add(&work, &acc);
        ge_add(&acc, &acc);
        cswap_pt(&acc, &work, b);
    }

    set25519(p->coord[0], acc.coord[0]);
    set25519(p->coord[1], acc.coord[1]);
    set25519(p->coord[2], acc.coord[2]);
    set25519(p->coord[3], acc.coord[3]);
}

/** p = [s] * basepoint. */
static void scalarbase(act_ge_point *p, const uint8_t *s)
{
    act_ge_point base;
    set25519(base.coord[0], BX);
    set25519(base.coord[1], BY);
    set25519(base.coord[2], gf1);
    fmul(base.coord[3], BX, BY); /* T = X*Y */
    scalarmult(p, &base, s);
}

/** Serialize point to 32-byte compressed form: y || sign(x)<<7. */
static void ge_pack(uint8_t *r, const act_ge_point *p)
{
    gf tx, ty, zi;
    inv25519(zi, p->coord[2]);
    fmul(tx, p->coord[0], zi);
    fmul(ty, p->coord[1], zi);
    pack25519(r, ty);
    r[31] ^= (uint8_t)(par25519(tx) << 7);
}

/**
 * @brief Decode 32-byte public key into the point -A (negated).
 *
 * Performs full curve membership validation (y^2 = x^3 - x + x*y^2 ... i.e.
 * the Edwards curve equation check) plus sign recovery of x.
 *
 * @param[out] r recovered point (-A).
 * @param[in]  p encoded public key.
 * @return 0 on success, -1 if @p p is not a valid curve point.
 */
static int unpackneg(act_ge_point *r, const uint8_t p[32])
{
    gf t, chk, num, den, den2, den4, den6;

    set25519(r->coord[2], gf1);
    unpack25519(r->coord[1], p);
    fsqr(num, r->coord[1]);
    fmul(den, num, D);
    fsub(num, num, r->coord[2]);
    fadd(den, r->coord[2], den);

    fsqr(den2, den);
    fsqr(den4, den2);
    fmul(den6, den4, den2);
    fmul(t, den6, num);
    fmul(t, t, den);

    pow2523(t, t);
    fmul(t, t, num);
    fmul(t, t, den);
    fmul(t, t, den);
    fmul(r->coord[0], t, den);

    fsqr(chk, r->coord[0]);
    fmul(chk, chk, den);
    if (neq25519(chk, num)) {
        fmul(r->coord[0], r->coord[0], D_I);
    }

    fsqr(chk, r->coord[0]);
    fmul(chk, chk, den);
    if (neq25519(chk, num)) {
        return -1; /* not on the curve */
    }

    /* We want -A: flip x if it matches the encoded sign bit. */
    if (par25519(r->coord[0]) == (int)((p[31] >> 7) & 1)) {
        fsub(r->coord[0], gf0, r->coord[0]);
    }

    fmul(r->coord[3], r->coord[0], r->coord[1]);
    return 0;
}

/* Scalar reduction mod L                                              */

/**
 * @brief Barrett-style reduction of a 64-byte little-endian scalar mod L.
 * @param r output, 32 canonical bytes.
 * @param x working array of 64 limbs (consumed).
 */
static void modL(uint8_t *r, int64_t x[64])
{
    int64_t carry;
    int i, j;

    for (i = 63; i >= 32; i--) {
        carry = 0;
        for (j = i - 32; j < i - 12; j++) {
            x[j] += carry - 16 * x[i] * ORDER_L[j - (i - 32)];
            carry = (x[j] + 128) >> 8;
            x[j] -= carry * 256;
        }
        x[j] += carry;
        x[i] = 0;
    }
    carry = 0;
    for (j = 0; j < 32; j++) {
        x[j] += carry - (x[31] >> 4) * ORDER_L[j];
        carry = x[j] >> 8;
        x[j] &= 255;
    }
    for (j = 0; j < 32; j++) {
        x[j] -= carry * ORDER_L[j];
    }
    for (i = 0; i < 32; i++) {
        x[i + 1] += x[i] >> 8;
        r[i] = (uint8_t)(x[i] & 255);
    }
}

/** Reduce a 64-byte hash digest to 32 canonical bytes mod L. */
static void reduce(uint8_t *r)
{
    int64_t x[64];
    int i;
    FOR(i, 64) x[i] = (uint64_t)r[i];
    FOR(i, 64) r[i] = 0;
    modL(r, x);
}

/* Public API                                                          */

void act_ed25519_keypair(uint8_t seed[ACT_ED25519_SEED_SIZE],
                         uint8_t pk[ACT_ED25519_PUBKEY_SIZE],
                         uint8_t sk[ACT_ED25519_PRIVKEY_SIZE])
{
    uint8_t local_seed[ACT_ED25519_SEED_SIZE];
    uint8_t hash[ACT_SHA512_DIGEST_SIZE];
    act_ge_point A;

    if (seed == NULL) {
        act_random_bytes(local_seed, sizeof(local_seed));
        seed = local_seed;
    }

    /* a = clamp(SHA512(seed)[0..31]) -- the actual signing scalar. */
    act_sha512(seed, ACT_ED25519_SEED_SIZE, hash);
    hash[0] &= 248;
    hash[31] &= 127;
    hash[31] |= 64;

    scalarbase(&A, hash);
    ge_pack(pk, &A);

    /* Private key layout: [0..31] = seed, [32..63] = public key copy. */
    if (sk != seed) {
        memcpy(sk, seed, ACT_ED25519_SEED_SIZE);
    }
    memcpy(sk + 32, pk, ACT_ED25519_PUBKEY_SIZE);

    act_secure_wipe(local_seed, sizeof(local_seed));
    act_secure_wipe(hash, sizeof(hash));
}

void act_ed25519_sign(uint8_t sig[ACT_ED25519_SIG_SIZE],
                      const uint8_t *msg, size_t mlen,
                      const uint8_t sk[ACT_ED25519_PRIVKEY_SIZE])
{
    uint8_t scalar[ACT_SHA512_DIGEST_SIZE];  /* clamped signing scalar */
    uint8_t mh[ACT_SHA512_DIGEST_SIZE];      /* challenge hash h       */
    uint8_t nonce[ACT_SHA512_DIGEST_SIZE];
    int64_t x[64];
    act_ge_point R;
    size_t i;
    int j;

    /* a = clamp(SHA512(seed)[0..31]) -- must be recomputed, the buffer is
     * separate from the challenge hash below (they are NOT the same value). */
    act_sha512(sk, ACT_ED25519_SEED_SIZE, scalar);
    scalar[0] &= 248;
    scalar[31] &= 127;
    scalar[31] |= 64;

    /* Deterministic nonce: r = H(prefix || message). */
    act_sha512_ctx ctx;
    act_sha512_init(&ctx);
    act_sha512_update(&ctx, scalar + 32, 32); /* prefix = hash[32..63] */
    act_sha512_update(&ctx, msg, mlen);
    act_sha512_final(&ctx, nonce);
    reduce(nonce);

    scalarbase(&R, nonce);
    ge_pack(sig, &R); /* sig[0..31] = R */

    /* h = H(R || A || message), reduced mod L. */
    act_sha512_init(&ctx);
    act_sha512_update(&ctx, sig, 32);
    act_sha512_update(&ctx, sk + 32, 32); /* public key */
    act_sha512_update(&ctx, msg, mlen);
    act_sha512_final(&ctx, mh);
    reduce(mh);

    /* s = nonce + h * a (mod L), via 64-byte schoolbook product. */
    FOR(i, 64) x[i] = 0;
    FOR(i, 32) x[i] = (uint64_t)nonce[i];
    FOR(i, 32) FOR(j, 32) x[i + j] += (uint64_t)mh[i] * (uint64_t)scalar[j];
    modL(sig + 32, x);

    act_secure_wipe(scalar, sizeof(scalar));
    act_secure_wipe(mh, sizeof(mh));
    act_secure_wipe(nonce, sizeof(nonce));
}

int act_ed25519_verify(const uint8_t sig[ACT_ED25519_SIG_SIZE],
                       const uint8_t *msg, size_t mlen,
                       const uint8_t pk[ACT_ED25519_PUBKEY_SIZE])
{
    act_ge_point negA, S_pt, sum;
    uint8_t h[ACT_SHA512_DIGEST_SIZE];
    uint8_t s_reduced[ACT_ED25519_PUBKEY_SIZE];
    uint8_t packed[ACT_ED25519_PUBKEY_SIZE];
    int64_t x[64];
    size_t i;
    int j;

    /* 1. Reject non-canonical scalars: s must already be < L. */
    FOR(i, 64) x[i] = 0;
    FOR(i, 32) x[i] = (uint64_t)sig[32 + i];
    modL(s_reduced, x);
    if (act_secure_memcmp(s_reduced, sig + 32, 32) != 0) {
        return -1;
    }

    /* 2. Public key must decode to a valid curve point. */
    if (unpackneg(&negA, pk) != 0) {
        return -1;
    }

    /* 3. h = H(R || A || message), reduced mod L. */
    act_sha512_ctx ctx;
    act_sha512_init(&ctx);
    act_sha512_update(&ctx, sig, 32);
    act_sha512_update(&ctx, pk, ACT_ED25519_PUBKEY_SIZE);
    act_sha512_update(&ctx, msg, mlen);
    act_sha512_final(&ctx, h);
    reduce(h);

    /* 4. Check [s]B + [h](-A) == R (equivalent to RFC 8032 equation). */
    scalarbase(&S_pt, sig + 32);
    scalarmult(&sum, &negA, h);
    ge_add(&sum, &S_pt);
    ge_pack(packed, &sum);

    j = act_secure_memcmp(packed, sig, 32);
    act_secure_wipe(h, sizeof(h));
    return (j == 0) ? 0 : -1;
}
