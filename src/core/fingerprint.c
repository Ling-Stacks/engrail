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
 * @file  fingerprint.c
 * @brief Platform identifier collection + keyed derivation cascade.
 *        See fingerprint.h for the design notes.
 */

#include "activation/fingerprint.h"
#include "activation/kdf.h"
#include "activation/sha512.h"
#include "activation/hmac.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if !defined(_WIN32)
#  include <unistd.h>
#  include <sys/utsname.h>
#else
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  ifndef NOMINMAX
#    define NOMINMAX
#  endif
#  include <windows.h>
#endif

/* Domain separation strings -- public constants, never secrets. They
 * version the fingerprint algorithm (v2 = HKDF-derived cascade key). */
static const char DOMAIN_KEYS[] = "act-deploy/v1/keys";
static const char DOMAIN_R1[] = "act-fp/v2/round1";
static const char DOMAIN_R2[] = "act-fp/v2/round2";
static const char DOMAIN_R3[] = "act-fp/v2/final";

/* Platform collectors                                                 */

#if defined(_WIN32)

void act_fp_collect(act_fp_sources *out, char *scratch, size_t scratch_len)
{
    out->count = 0;
    size_t off = 0;

    /* Each helper appends "<name>=<value>" into scratch and registers it. */
    struct reg {
        const char *name;
        const char *fallback; /* env var to try if API fails */
    };
    static const struct reg winvars[] = {
        { "COMPUTERNAME", NULL },
        { "USERNAME", NULL },
        { "PROCESSOR_IDENTIFIER", NULL },
        { "PROCESSOR_LEVEL", NULL },
        { "PROCESSOR_REVISION", NULL },
        { "NUMBER_OF_PROCESSORS", NULL }
    };

    for (size_t k = 0; k < sizeof(winvars) / sizeof(winvars[0]); k++) {
        char buf[256];
        DWORD n = GetEnvironmentVariableA(winvars[k].name, buf, (DWORD)sizeof(buf));
        if (n > 0 && n < sizeof(buf) &&
            off + 64 + n < scratch_len && out->count < ACT_FP_MAX_SOURCES) {
            int w = sprintf(scratch + off, "%s=%s", winvars[k].name, buf);
            if (w > 0) {
                out->sources[out->count++] = scratch + off;
                off += (size_t)w + 1;
            }
        }
    }

    /* Volume serial number of the system drive -- coarse but stable. */
    DWORD serial = 0;
    if (GetVolumeInformationA("C:\\", NULL, 0, &serial, NULL, NULL, NULL, 0) &&
        off + 64 < scratch_len && out->count < ACT_FP_MAX_SOURCES) {
        int w = sprintf(scratch + off, "volserial=%08lx", (unsigned long)serial);
        if (w > 0) {
            out->sources[out->count++] = scratch + off;
            off += (size_t)w + 1;
        }
    }
    (void)scratch_len;
}

#else /* POSIX family */

void act_fp_collect(act_fp_sources *out, char *scratch, size_t scratch_len)
{
    out->count = 0;
    size_t off = 0;

    /* 1. uname: kernel, hostname, release, architecture. */
    {
        struct utsname un;
        if (uname(&un) == 0) {
            const char *fields[] = { un.sysname, un.nodename,
                                     un.release, un.version, un.machine };
            for (size_t k = 0; k < sizeof(fields) / sizeof(fields[0]); k++) {
                if (fields[k][0] == '\0') continue;
                int w = snprintf(scratch + off, scratch_len - off,
                                 "uname%zu=%s", k, fields[k]);
                if (w > 0 && (size_t)w < scratch_len - off &&
                    out->count < ACT_FP_MAX_SOURCES) {
                    out->sources[out->count++] = scratch + off;
                    off += (size_t)w + 1;
                }
            }
        }
    }

    /* 2. Login user (both spellings, first present wins). */
    {
        const char *u = getenv("USER");
        if (u == NULL) u = getenv("USERNAME");
        if (u == NULL) u = getlogin();
        if (u != NULL && off + 64 < scratch_len &&
            out->count < ACT_FP_MAX_SOURCES) {
            int w = snprintf(scratch + off, scratch_len - off, "user=%s", u);
            if (w > 0 && (size_t)w < scratch_len - off) {
                out->sources[out->count++] = scratch + off;
                off += (size_t)w + 1;
            }
        }
    }

    /* 3. Machine identifier, best effort, first hit wins:
     *    - /etc/machine-id        (systemd Linux)
     *    - /proc/sys/kernel/random/boot_id (Android & fallback Linux)
     *    - /etc/hostid            (FreeBSD) */
    {
        static const char *paths[] = {
            "/etc/machine-id",
            "/proc/sys/kernel/random/boot_id",
            "/etc/hostid",
            NULL
        };
        for (int k = 0; paths[k] != NULL && out->count < ACT_FP_MAX_SOURCES; k++) {
            char raw[64];
            FILE *f = fopen(paths[k], "rb");
            if (f == NULL) continue;
            size_t n = fread(raw, 1, sizeof(raw), f);
            fclose(f);
            if (n == 0) continue;
            /* Keep only alphanumerics so trailing newlines/whitespace in
             * these files cannot perturb the fingerprint. */
            int w = snprintf(scratch + off, scratch_len - off, "mid%d=", k);
            size_t pos = off + (size_t)w;
            for (size_t c = 0; c < n && pos + 1 < scratch_len; c++) {
                unsigned char ch = (unsigned char)raw[c];
                if ((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f') ||
                    (ch >= 'A' && ch <= 'F') || ch == '-') {
                    scratch[pos++] = (char)ch;
                }
            }
            if (pos > off + (size_t)w) {
                scratch[pos] = '\0';
                out->sources[out->count++] = scratch + off;
                off = pos + 1;
            }
            break; /* first available identifier wins */
        }
    }
}

#endif

/* Derivation cascade                                                  */

/**
 * @brief Length-prefixed fold of all sources into a SHA-512 context.
 *
 * Each string is framed as u32be(len) || bytes so that concatenated
 * inputs cannot collide ("ab","c" vs "a","bc").
 */
static void fold_sources(act_sha512_ctx *ctx, const act_fp_sources *src)
{
    for (int i = 0; i < src->count; i++) {
        const char *s = src->sources[i];
        size_t len = (s != NULL) ? strlen(s) : 0;
        uint8_t hdr[4];
        hdr[0] = (uint8_t)(len >> 24);
        hdr[1] = (uint8_t)(len >> 16);
        hdr[2] = (uint8_t)(len >> 8);
        hdr[3] = (uint8_t)(len);
        act_sha512_update(ctx, hdr, 4);
        act_sha512_update(ctx, s, len);
    }
}

void act_deployment_keys(const uint8_t pubkey[32],
                         const uint8_t dsalt[ACT_DSALT_SIZE],
                         uint8_t fp_key[32],
                         uint8_t token_key[32],
                         uint8_t session_key[32])
{
    /* One HKDF expansion, three purpose-separated slices. All inputs are
     * per-deployment; nothing here depends on code constants. */
    uint8_t okm[96];
    act_hkdf_sha512(dsalt, ACT_DSALT_SIZE, pubkey, 32,
                    (const uint8_t *)DOMAIN_KEYS, sizeof(DOMAIN_KEYS) - 1,
                    okm, sizeof(okm));
    if (fp_key != NULL) memcpy(fp_key, okm + 0, 32);
    if (token_key != NULL) memcpy(token_key, okm + 32, 32);
    if (session_key != NULL) memcpy(session_key, okm + 64, 32);
    act_secure_wipe(okm, sizeof(okm));
}

void act_fp_compute(const uint8_t fp_key[32], uint32_t product_id,
                    const uint8_t *salt, size_t salt_len,
                    const act_fp_sources *src,
                    uint8_t out16[ACT_MACHINE_CODE_SIZE])
{
    uint8_t h1[ACT_SHA512_DIGEST_SIZE];
    uint8_t h2[ACT_SHA512_DIGEST_SIZE];
    uint8_t h3[ACT_SHA512_DIGEST_SIZE];
    uint8_t pid_be[4];
    act_sha512_ctx ctx;

    pid_be[0] = (uint8_t)(product_id >> 24);
    pid_be[1] = (uint8_t)(product_id >> 16);
    pid_be[2] = (uint8_t)(product_id >> 8);
    pid_be[3] = (uint8_t)(product_id);

    /* Round 1: plain domain-separated hash of everything. The cascade
     * is keyed by fp_key (HKDF of pubkey+dsalt), NOT by the raw public
     * key, so fingerprints differ across deployments sharing a key and
     * the per-purpose key never travels with the code. */
    act_sha512_init(&ctx);
    act_sha512_update(&ctx, DOMAIN_R1, sizeof(DOMAIN_R1) - 1);
    act_sha512_update(&ctx, fp_key, 32);
    act_sha512_update(&ctx, pid_be, 4);
    if (salt != NULL && salt_len > 0) {
        uint8_t hdr[4] = {
            (uint8_t)(salt_len >> 24), (uint8_t)(salt_len >> 16),
            (uint8_t)(salt_len >> 8),  (uint8_t)(salt_len)
        };
        act_sha512_update(&ctx, hdr, 4);
        act_sha512_update(&ctx, salt, salt_len);
    }
    fold_sources(&ctx, src);
    act_sha512_final(&ctx, h1);

    /* Round 2: keyed with the first half of H1, over the second half. */
    act_hmac_sha512_2(h1, 32, h1 + 32, 32, DOMAIN_R2, sizeof(DOMAIN_R2) - 1, h2);
    /* (sources already mixed into H1; re-mixing salt+sources here would
     * double-count -- H2 binds the two H1 halves together instead). */

    /* Round 3: keyed with the HKDF-derived fingerprint key. */
    {
        act_sha512_ctx c3;
        act_sha512_init(&c3);
        act_sha512_update(&c3, h2, ACT_SHA512_DIGEST_SIZE);
        act_sha512_update(&c3, DOMAIN_R3, sizeof(DOMAIN_R3) - 1);
        act_sha512_update(&c3, h1, 16);
        uint8_t buf[ACT_SHA512_DIGEST_SIZE];
        act_sha512_final(&c3, buf);
        act_hmac_sha512(fp_key, 32, buf, ACT_SHA512_DIGEST_SIZE, h3);
        act_secure_wipe(buf, sizeof(buf));
    }

    memcpy(out16, h3, ACT_MACHINE_CODE_SIZE);
    act_secure_wipe(h1, sizeof(h1));
    act_secure_wipe(h2, sizeof(h2));
    act_secure_wipe(h3, sizeof(h3));
}

void act_fingerprint(const uint8_t pubkey[32],
                     const uint8_t dsalt[ACT_DSALT_SIZE],
                     uint32_t product_id,
                     const uint8_t *salt, size_t salt_len,
                     uint8_t out16[ACT_MACHINE_CODE_SIZE])
{
    uint8_t fp_key[32], tk[32], sk[32];
    act_deployment_keys(pubkey, dsalt, fp_key, tk, sk);
    act_secure_wipe(tk, sizeof(tk));
    act_secure_wipe(sk, sizeof(sk));

    char scratch[4096];
    act_fp_sources src;
    act_fp_collect(&src, scratch, sizeof(scratch));
    act_fp_compute(fp_key, product_id, salt, salt_len, &src, out16);
    act_secure_wipe(fp_key, sizeof(fp_key));
    act_secure_wipe(scratch, sizeof(scratch));
}

void act_fp_to_string(const uint8_t code16[ACT_MACHINE_CODE_SIZE],
                      char buf[ACT_MACHINE_CODE_STR_SIZE])
{
    static const char hexd[] = "0123456789ABCDEF";
    /* 16 bytes -> 32 uppercase hex chars, grouped with a dash in the
     * middle: "XXXXXXXXXXXXXXXX-XXXXXXXXXXXXXXXX" (33 chars + NUL). */
    for (int i = 0; i < ACT_MACHINE_CODE_SIZE; i++) {
        if (i == 8) {
            *buf++ = '-';
        }
        *buf++ = hexd[code16[i] >> 4];
        *buf++ = hexd[code16[i] & 15];
    }
    *buf = '\0';
}
