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
 * @file  revoke.c
 * @brief Signed revocation lists. See revoke.h for the on-disk format.
 */

#include "activation/revoke.h"
#include "activation/ed25519.h"
#include "activation/random.h"
#include "activation/sha512.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char REVOKE_MAGIC[4] = { 'A', 'C', 'T', 'R' };
#define REVOKE_FORMAT_VERSION 0x01

/** Header size: magic + version + count. */
#define REVOKE_HEADER_SIZE 9

act_status act_revoke_save(const char *path, const uint8_t sk[64],
                           const uint8_t *serials_flat, uint32_t count)
{
    if (path == NULL || sk == NULL ||
        (serials_flat == NULL && count > 0)) {
        return ACT_ERR_ARG;
    }
    if (count > 0xFFFFF0u) { /* sanity bound, keeps arithmetic safe */
        return ACT_ERR_ARG;
    }

    const size_t body = REVOKE_HEADER_SIZE + (size_t)count * ACT_SERIAL_SIZE;
    const size_t total = body + ACT_SIG_SIZE;
    uint8_t *blob = (uint8_t *)malloc(total);
    if (blob == NULL) {
        return ACT_ERR_STATE_IO;
    }

    memcpy(blob, REVOKE_MAGIC, 4);
    blob[4] = REVOKE_FORMAT_VERSION;
    blob[5] = (uint8_t)(count >> 24);
    blob[6] = (uint8_t)(count >> 16);
    blob[7] = (uint8_t)(count >> 8);
    blob[8] = (uint8_t)(count);
    if (count > 0) {
        memcpy(blob + REVOKE_HEADER_SIZE, serials_flat,
               (size_t)count * ACT_SERIAL_SIZE);
    }
    act_ed25519_sign(blob + body, blob, body, sk);

    FILE *f = fopen(path, "wb");
    if (f == NULL) {
        free(blob);
        return ACT_ERR_STATE_IO;
    }
    const size_t wrote = fwrite(blob, 1, total, f);
    const int io_err = ferror(f);
    fclose(f);
    act_secure_wipe(blob, total);
    free(blob);

    return (wrote == total && !io_err) ? ACT_OK : ACT_ERR_STATE_IO;
}

act_status act_revoke_load(const char *path, const uint8_t pk[32],
                           uint8_t *out_flat, uint32_t cap,
                           uint32_t *count_out)
{
    if (path == NULL || pk == NULL) {
        return ACT_ERR_ARG;
    }

    uint8_t hdr[REVOKE_HEADER_SIZE];
    FILE *f = fopen(path, "rb");
    if (f == NULL) {
        return ACT_ERR_STATE_MISSING;
    }
    if (fread(hdr, 1, sizeof(hdr), f) != sizeof(hdr) ||
        memcmp(hdr, REVOKE_MAGIC, 4) != 0 ||
        hdr[4] != REVOKE_FORMAT_VERSION) {
        fclose(f);
        return ACT_ERR_STATE_CORRUPT;
    }
    const uint32_t count = ((uint32_t)hdr[5] << 24) | ((uint32_t)hdr[6] << 16) |
                           ((uint32_t)hdr[7] << 8) | (uint32_t)hdr[8];
    if (count > 0xFFFFF0u) {
        fclose(f);
        return ACT_ERR_STATE_CORRUPT;
    }

    const size_t body = REVOKE_HEADER_SIZE + (size_t)count * ACT_SERIAL_SIZE;
    uint8_t *blob = (uint8_t *)malloc(body + ACT_SIG_SIZE);
    if (blob == NULL) {
        fclose(f);
        return ACT_ERR_STATE_IO;
    }
    memcpy(blob, hdr, sizeof(hdr));
    const size_t rest = body - REVOKE_HEADER_SIZE + ACT_SIG_SIZE;
    if (fread(blob + REVOKE_HEADER_SIZE, 1, rest, f) != rest) {
        fclose(f);
        act_secure_wipe(blob, body + ACT_SIG_SIZE);
        free(blob);
        return ACT_ERR_STATE_CORRUPT;
    }
    fclose(f);

    /* Signature over the header+serials must verify with the vendor key. */
    if (act_ed25519_verify(blob + body, blob, body, pk) != 0) {
        act_secure_wipe(blob, body + ACT_SIG_SIZE);
        free(blob);
        return ACT_ERR_SIGNATURE;
    }

    if (count_out != NULL) {
        *count_out = count;
    }
    if (out_flat != NULL) {
        if (cap < count) {
            act_secure_wipe(blob, body + ACT_SIG_SIZE);
            free(blob);
            return ACT_ERR_ARG; /* buffer too small */
        }
        memcpy(out_flat, blob + REVOKE_HEADER_SIZE,
               (size_t)count * ACT_SERIAL_SIZE);
    }

    act_secure_wipe(blob, body + ACT_SIG_SIZE);
    free(blob);
    return ACT_OK;
}

act_status act_revoke_add(const char *path, const uint8_t sk[64],
                          const uint8_t serial[ACT_SERIAL_SIZE])
{
    if (path == NULL || sk == NULL || serial == NULL) {
        return ACT_ERR_ARG;
    }

    /* Try to load the existing list first (if any). */
    uint32_t count = 0;
    uint8_t *flat = NULL;
    act_status st = act_revoke_load(path, sk + 32, NULL, 0, &count);
    if (st == ACT_OK && count > 0) {
        flat = (uint8_t *)malloc((size_t)(count + 1) * ACT_SERIAL_SIZE);
        if (flat == NULL) {
            return ACT_ERR_STATE_IO;
        }
        st = act_revoke_load(path, sk + 32, flat, count, &count);
        if (st != ACT_OK) {
            free(flat);
            return st;
        }
    } else if (st == ACT_ERR_STATE_MISSING) {
        flat = (uint8_t *)malloc(ACT_SERIAL_SIZE);
        if (flat == NULL) {
            return ACT_ERR_STATE_IO;
        }
        count = 0;
    } else if (st != ACT_OK) {
        return st;
    }

    memcpy(flat + (size_t)count * ACT_SERIAL_SIZE, serial, ACT_SERIAL_SIZE);
    st = act_revoke_save(path, sk, flat, count + 1);
    act_secure_wipe(flat, (size_t)(count + 1) * ACT_SERIAL_SIZE);
    free(flat);
    return st;
}

int act_revoke_contains(const uint8_t *serials_flat, uint32_t count,
                        const uint8_t serial[ACT_SERIAL_SIZE])
{
    if (serials_flat == NULL || serial == NULL) {
        return 0;
    }
    /* Per-entry difference so a match is not masked by mismatched
     * neighbours; the loop shape stays data-independent. */
    uint8_t found = 0;
    for (uint32_t i = 0; i < count; i++) {
        uint8_t diff = 0;
        for (size_t j = 0; j < ACT_SERIAL_SIZE; j++) {
            diff |= (uint8_t)(serials_flat[(size_t)i * ACT_SERIAL_SIZE + j] ^
                              serial[j]);
        }
        /* ((int)diff - 1) >> 8 is -1 (all ones) iff diff == 0, else 0. */
        found |= (uint8_t)((((int)diff - 1) >> 8) & 1);
    }
    return found;
}

int act_revoke_check(const char *path, const uint8_t pk[32],
                     const act_license_info *info)
{
    if (path == NULL || pk == NULL || info == NULL) {
        return ACT_ERR_ARG;
    }
    uint32_t count = 0;
    const act_status st = act_revoke_load(path, pk, NULL, 0, &count);
    if (st != ACT_OK) {
        return (int)st;
    }
    if (count == 0) {
        return 0;
    }
    uint8_t *flat = (uint8_t *)malloc((size_t)count * ACT_SERIAL_SIZE);
    if (flat == NULL) {
        return ACT_ERR_STATE_IO;
    }
    const act_status st2 = act_revoke_load(path, pk, flat, count, &count);
    if (st2 != ACT_OK) {
        free(flat);
        return (int)st2;
    }
    const int revoked = act_revoke_contains(flat, count, info->serial);
    act_secure_wipe(flat, (size_t)count * ACT_SERIAL_SIZE);
    free(flat);
    return revoked;
}
