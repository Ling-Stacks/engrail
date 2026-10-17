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
 * @file  keyfile.c
 * @brief Passphrase-encrypted vendor seed storage. See keyfile.h.
 */

/*
 * Feature-macro prelude (must precede every system include): this unit
 * uses POSIX extensions (readlink / getpid / sysctl / fchmod / fileno).
 * Strict -std=c99 defines __STRICT_ANSI__ and hides them; unlock per
 * platform so the code compiles in every build mode.
 */
#if !defined(_GNU_SOURCE) && !defined(_DARWIN_C_SOURCE) && \
    !defined(_DEFAULT_SOURCE)
#  if defined(__APPLE__)
#    define _DARWIN_C_SOURCE 1
#  elif defined(__linux__) || defined(__ANDROID__)
#    define _GNU_SOURCE 1
#  else
#    define _DEFAULT_SOURCE 1
#  endif
#endif

#include "activation/keyfile.h"
#include "activation/chacha20.h"
#include "activation/hmac.h"
#include "activation/kdf.h"
#include "activation/random.h"
#include "activation/sha512.h"

#include <stdio.h>
#include <string.h>

#if !defined(_WIN32)
#  include <sys/stat.h>
#endif

static const char KEYFILE_MAGIC[7] = { 'A', 'C', 'T', 'K', 'E', 'Y', '2' };
#define KEYFILE_VERSION 0x02

/** Write helper: full write or nothing. */
static act_status write_all(const char *path, const uint8_t *blob, size_t len)
{
    FILE *f = fopen(path, "wb");
    if (f == NULL) {
        return ACT_ERR_STATE_IO;
    }
#if !defined(_WIN32)
    /* The umask at creation time is out of our control; drop permissions
     * explicitly so the key file is never group/world readable. */
    (void)fchmod(fileno(f), 0600);
#endif
    const size_t w = fwrite(blob, 1, len, f);
    const int err = ferror(f);
    fclose(f);
    return (w == len && !err) ? ACT_OK : ACT_ERR_STATE_IO;
}

act_status act_keyfile_save(const char *path,
                            const uint8_t seed[32],
                            const uint8_t dsalt[ACT_DSALT_SIZE],
                            const char *passphrase,
                            uint32_t iterations)
{
    if (path == NULL || seed == NULL || dsalt == NULL) {
        return ACT_ERR_ARG;
    }
    if (iterations == 0) {
        iterations = ACT_KEYFILE_KDF_ITERS;
    }

    uint8_t blob[ACT_KEYFILE_SIZE];
    memcpy(blob, KEYFILE_MAGIC, 7);
    blob[7] = KEYFILE_VERSION;

    uint8_t kdf_salt[16];
    uint8_t nonce[12];
    act_random_bytes(kdf_salt, sizeof(kdf_salt));
    act_random_bytes(nonce, sizeof(nonce));
    memcpy(blob + 8, kdf_salt, 16);
    blob[24] = (uint8_t)(iterations >> 24);
    blob[25] = (uint8_t)(iterations >> 16);
    blob[26] = (uint8_t)(iterations >> 8);
    blob[27] = (uint8_t)(iterations);
    memcpy(blob + 28, dsalt, ACT_DSALT_SIZE);
    memcpy(blob + 60, nonce, 12);

    /* PBKDF2 -> (enc_key || mac_key) */
    uint8_t dk[64];
    const size_t pass_len = passphrase ? strlen(passphrase) : 0;
    act_pbkdf2_hmac_sha512((const uint8_t *)passphrase, pass_len,
                           kdf_salt, 16, iterations, dk, 64);

    /* Encrypt-then-MAC */
    memcpy(blob + 72, seed, 32);
    act_chacha20_xor(dk, nonce, 0, blob + 72, 32);
    uint8_t mac[ACT_HMAC_SHA512_SIZE];
    act_hmac_sha512(dk + 32, 32, blob, 72 + 32, mac);
    memcpy(blob + 104, mac, 8); /* 64-bit tag: forgery 2^-64 per attempt,
                                 * amplified by PBKDF2 cost per guess */

    act_secure_wipe(dk, sizeof(dk));
    act_secure_wipe(mac, sizeof(mac));
    const act_status st = write_all(path, blob, sizeof(blob));
    act_secure_wipe(blob, sizeof(blob));
    return st;
}

act_status act_keyfile_load(const char *path, const char *passphrase,
                            uint8_t out_seed[32],
                            uint8_t out_dsalt[ACT_DSALT_SIZE])
{
    if (path == NULL || out_seed == NULL) {
        return ACT_ERR_ARG;
    }

    uint8_t blob[ACT_KEYFILE_SIZE];
    FILE *f = fopen(path, "rb");
    if (f == NULL) {
        return ACT_ERR_STATE_MISSING;
    }
    const size_t got = fread(blob, 1, sizeof(blob), f);
    const int extra = (fgetc(f) != EOF);
    fclose(f);
    if (got != sizeof(blob) || extra) {
        return ACT_ERR_STATE_CORRUPT;
    }
    if (memcmp(blob, KEYFILE_MAGIC, 7) != 0 || blob[7] != KEYFILE_VERSION) {
        return ACT_ERR_STATE_CORRUPT;
    }

    const uint32_t iterations = ((uint32_t)blob[24] << 24) |
                                ((uint32_t)blob[25] << 16) |
                                ((uint32_t)blob[26] << 8) |
                                (uint32_t)blob[27];
    if (iterations == 0 || iterations > (10u * 1000 * 1000)) {
        return ACT_ERR_STATE_CORRUPT; /* refuse absurd work factors */
    }

    uint8_t dk[64];
    const size_t pass_len = passphrase ? strlen(passphrase) : 0;
    act_pbkdf2_hmac_sha512((const uint8_t *)passphrase, pass_len,
                           blob + 8, 16, iterations, dk, 64);

    /* MAC first (EtM): covers header + ciphertext. */
    uint8_t mac[ACT_HMAC_SHA512_SIZE];
    act_hmac_sha512(dk + 32, 32, blob, 72 + 32, mac);
    const int mac_ok = (act_secure_memcmp(mac, blob + 104, 8) == 0);
    act_secure_wipe(mac, sizeof(mac));

    if (!mac_ok) {
        act_secure_wipe(dk, sizeof(dk));
        act_secure_wipe(blob, sizeof(blob));
        return ACT_ERR_SIGNATURE; /* wrong passphrase or tampered file */
    }

    memcpy(out_seed, blob + 72, 32);
    act_chacha20_xor(dk, blob + 60, 0, out_seed, 32);
    if (out_dsalt != NULL) {
        memcpy(out_dsalt, blob + 28, ACT_DSALT_SIZE);
    }

    act_secure_wipe(dk, sizeof(dk));
    act_secure_wipe(blob, sizeof(blob));
    return ACT_OK;
}
