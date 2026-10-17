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
 * @file  audit.c
 * @brief Chained HMAC audit log. See audit.h for the wire format.
 */

#include "activation/audit.h"
#include "activation/hmac.h"
#include "activation/random.h"
#include "activation/sha512.h"
#include <time.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char AUDIT_MAGIC[9] = { 'A', 'C', 'T', 'A', 'U', 'D', 'I', 'T', '1' };

/** Entry header: type(1) + ts(8) + len(2) = 11 bytes. */
#define ENTRY_HDR 11

static void hmac_entry(uint8_t out[32], const uint8_t key[32],
                       const uint8_t header[ENTRY_HDR], const uint8_t *detail,
                       size_t len, const uint8_t prev[32])
{
    uint8_t full[ACT_HMAC_SHA512_SIZE];
    /* standard HMAC pads: key zero-extended to the block size */
    uint8_t kblock[128];
    memset(kblock, 0, sizeof(kblock));
    memcpy(kblock, key, 32);
    act_sha512_ctx ctx;
    uint8_t pad[128];
    for (int i = 0; i < 128; i++) {
        pad[i] = (uint8_t)(kblock[i] ^ 0x36);
    }
    act_sha512_init(&ctx);
    act_sha512_update(&ctx, pad, 128);
    act_sha512_update(&ctx, header, ENTRY_HDR);
    if (detail != NULL && len > 0) {
        act_sha512_update(&ctx, detail, len);
    }
    act_sha512_update(&ctx, prev, 32);
    act_sha512_final(&ctx, full);
    for (int i = 0; i < 128; i++) {
        pad[i] = (uint8_t)(kblock[i] ^ 0x5c);
    }
    act_sha512_init(&ctx);
    act_sha512_update(&ctx, pad, 128);
    act_sha512_update(&ctx, full, 64);
    act_sha512_final(&ctx, full);
    act_secure_wipe(kblock, sizeof(kblock));
    act_secure_wipe(pad, sizeof(pad));
    memcpy(out, full, 32);
    act_secure_wipe(full, sizeof(full));
}

act_status act_audit_init(const char *path, const uint8_t key[32])
{
    if (path == NULL || key == NULL) {
        return ACT_ERR_ARG;
    }

    FILE *f = fopen(path, "rb");
    if (f != NULL) {
        fclose(f);
        return act_audit_verify(path, key, NULL, NULL);
    }

    /* Genesis: magic || nonce(16) || HMAC(magic||nonce) */
    uint8_t genesis[ACT_AUDIT_GENESIS_SIZE];
    memcpy(genesis, AUDIT_MAGIC, 9);
    act_random_bytes(genesis + 9, 16);

    uint8_t full[ACT_HMAC_SHA512_SIZE];
    act_hmac_sha512(key, 32, genesis, 25, full);
    memcpy(genesis + 25, full, 32);

    f = fopen(path, "wb");
    if (f == NULL) {
        return ACT_ERR_STATE_IO;
    }
    const size_t w = fwrite(genesis, 1, sizeof(genesis), f);
    fclose(f);
    act_secure_wipe(full, sizeof(full));
    return (w == sizeof(genesis)) ? ACT_OK : ACT_ERR_STATE_IO;
}

act_status act_audit_append(const char *path, const uint8_t key[32],
                            uint8_t type, const void *detail, size_t len)
{
    if (path == NULL || key == NULL || len > 0xFFFF ||
        (detail == NULL && len > 0)) {
        return ACT_ERR_ARG;
    }

    /* Walk the chain to get the last HMAC (linear; logs are short). */
    uint8_t prev[32];
    {
        act_status st = act_audit_verify(path, key, NULL, prev);
        if (st != ACT_OK) {
            return st;
        }
    }

    uint8_t header[ENTRY_HDR];
    header[0] = type;
    const int64_t now = (int64_t)time(NULL);
    for (int i = 0; i < 8; i++) {
        header[1 + i] = (uint8_t)((uint64_t)now >> (56 - 8 * i));
    }
    header[9] = (uint8_t)(len >> 8);
    header[10] = (uint8_t)(len);

    uint8_t hmac[32];
    hmac_entry(hmac, key, header, (const uint8_t *)detail, len, prev);

    FILE *f = fopen(path, "ab");
    if (f == NULL) {
        return ACT_ERR_STATE_IO;
    }
    int ok = fwrite(header, 1, ENTRY_HDR, f) == ENTRY_HDR &&
             (len == 0 || fwrite(detail, 1, len, f) == len) &&
             fwrite(prev, 1, 32, f) == 32 &&
             fwrite(hmac, 1, 32, f) == 32;
    const int err = ferror(f);
    fclose(f);
    act_secure_wipe(hmac, sizeof(hmac));
    act_secure_wipe(prev, sizeof(prev));
    return (ok && !err) ? ACT_OK : ACT_ERR_STATE_IO;
}

act_status act_audit_verify(const char *path, const uint8_t key[32],
                            uint32_t *count_out, uint8_t tail_out[32])
{
    if (path == NULL || key == NULL) {
        return ACT_ERR_ARG;
    }

    FILE *f = fopen(path, "rb");
    if (f == NULL) {
        return ACT_ERR_STATE_MISSING;
    }

    /* Genesis */
    uint8_t genesis[ACT_AUDIT_GENESIS_SIZE];
    if (fread(genesis, 1, sizeof(genesis), f) != sizeof(genesis) ||
        memcmp(genesis, AUDIT_MAGIC, 9) != 0) {
        fclose(f);
        return ACT_ERR_STATE_CORRUPT;
    }
    uint8_t full[ACT_HMAC_SHA512_SIZE];
    act_hmac_sha512(key, 32, genesis, 25, full);
    if (act_secure_memcmp(full, genesis + 25, 32) != 0) {
        fclose(f);
        act_secure_wipe(full, sizeof(full));
        return ACT_ERR_SIGNATURE;
    }

    /* Chain */
    uint8_t prev[32], expect[32];
    memcpy(prev, genesis + 25, 32);
    uint32_t count = 0;
    for (;;) {
        uint8_t header[ENTRY_HDR];
        size_t got = fread(header, 1, ENTRY_HDR, f);
        if (got == 0) {
            break; /* clean EOF */
        }
        if (got != ENTRY_HDR) {
            fclose(f);
            act_secure_wipe(full, sizeof(full));
            return ACT_ERR_SIGNATURE; /* truncated entry */
        }
        const size_t len = ((size_t)header[9] << 8) | header[10];
        uint8_t detail_stack[256];
        uint8_t *detail = NULL;
        if (len > 0) {
            detail = len <= sizeof(detail_stack)
                         ? detail_stack
                         : (uint8_t *)malloc(len);
            if (detail == NULL ||
                fread(detail, 1, len, f) != len) {
                free(detail == detail_stack ? NULL : detail);
                fclose(f);
                act_secure_wipe(full, sizeof(full));
                return ACT_ERR_SIGNATURE;
            }
        }
        uint8_t stored_prev[32], stored_hmac[32];
        if (fread(stored_prev, 1, 32, f) != 32 ||
            fread(stored_hmac, 1, 32, f) != 32) {
            free(detail == detail_stack ? NULL : detail);
            fclose(f);
            act_secure_wipe(full, sizeof(full));
            return ACT_ERR_SIGNATURE;
        }
        /* prev-link must match the running chain */
        if (act_secure_memcmp(stored_prev, prev, 32) != 0) {
            free(detail == detail_stack ? NULL : detail);
            fclose(f);
            act_secure_wipe(full, sizeof(full));
            return ACT_ERR_SIGNATURE;
        }
        hmac_entry(expect, key, header, detail, len, stored_prev);
        if (act_secure_memcmp(expect, stored_hmac, 32) != 0) {
            free(detail == detail_stack ? NULL : detail);
            fclose(f);
            act_secure_wipe(full, sizeof(full));
            return ACT_ERR_SIGNATURE;
        }
        memcpy(prev, stored_hmac, 32);
        count++;
        if (detail != detail_stack) {
            free(detail);
        }
    }
    fclose(f);
    act_secure_wipe(full, sizeof(full));

    if (count_out != NULL) {
        *count_out = count;
    }
    if (tail_out != NULL) {
        memcpy(tail_out, prev, 32);
    }
    act_secure_wipe(prev, sizeof(prev));
    return ACT_OK;
}
