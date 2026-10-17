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
 * @file  state.c
 * @brief Activation state persistence. See state.h for the format.
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

#include "activation/state.h"

#include <stdio.h>
#include <string.h>

#if !defined(_WIN32)
#  include <sys/stat.h>
#endif

static const char STATE_MAGIC[4] = { 'A', 'C', 'T', '1' };
#define STATE_FORMAT_VERSION 0x01

act_status act_state_save(const char *path,
                          const uint8_t payload[ACT_PAYLOAD_SIZE],
                          const uint8_t sig[ACT_SIG_SIZE])
{
    if (path == NULL || payload == NULL || sig == NULL) {
        return ACT_ERR_ARG;
    }

    uint8_t blob[ACT_STATE_FILE_SIZE];
    blob[0] = STATE_MAGIC[0];
    blob[1] = STATE_MAGIC[1];
    blob[2] = STATE_MAGIC[2];
    blob[3] = STATE_MAGIC[3];
    blob[4] = STATE_FORMAT_VERSION;
    memcpy(blob + 5, payload, ACT_PAYLOAD_SIZE);
    memcpy(blob + 5 + ACT_PAYLOAD_SIZE, sig, ACT_SIG_SIZE);

    FILE *f = fopen(path, "wb");
    if (f == NULL) {
        return ACT_ERR_STATE_IO;
    }
#if !defined(_WIN32)
    /* The umask at creation time is out of our control; drop permissions
     * explicitly so the state file is never group/world readable. */
    (void)fchmod(fileno(f), 0600);
#endif
    const size_t wrote = fwrite(blob, 1, sizeof(blob), f);
    const int io_err = ferror(f);
    fclose(f);
    if (wrote != sizeof(blob) || io_err) {
        return ACT_ERR_STATE_IO;
    }
    return ACT_OK;
}

act_status act_state_load(const char *path,
                          uint8_t payload[ACT_PAYLOAD_SIZE],
                          uint8_t sig[ACT_SIG_SIZE])
{
    if (path == NULL || payload == NULL || sig == NULL) {
        return ACT_ERR_ARG;
    }

    uint8_t blob[ACT_STATE_FILE_SIZE];
    FILE *f = fopen(path, "rb");
    if (f == NULL) {
        return ACT_ERR_STATE_MISSING;
    }
    const size_t got = fread(blob, 1, sizeof(blob), f);
    const int truncated = (fgetc(f) != EOF); /* anything left => wrong size */
    fclose(f);

    if (got != sizeof(blob) || truncated) {
        return ACT_ERR_STATE_CORRUPT;
    }
    if (memcmp(blob, STATE_MAGIC, 4) != 0 || blob[4] != STATE_FORMAT_VERSION) {
        return ACT_ERR_STATE_CORRUPT;
    }

    memcpy(payload, blob + 5, ACT_PAYLOAD_SIZE);
    memcpy(sig, blob + 5 + ACT_PAYLOAD_SIZE, ACT_SIG_SIZE);
    return ACT_OK;
}

act_status act_state_check(const char *path,
                           const uint8_t pubkey[32],
                           uint32_t product_id,
                           const uint8_t machine_code[16],
                           int64_t now_unix,
                           act_license_info *info)
{
    uint8_t payload[ACT_PAYLOAD_SIZE];
    uint8_t sig[ACT_SIG_SIZE];
    act_status st = act_state_load(path, payload, sig);
    if (st != ACT_OK) {
        return st;
    }
    return act_license_verify_payload(payload, sig, pubkey, product_id,
                                      machine_code, now_unix, info);
}
