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
 * @file  license.c
 * @brief Activation code codec + verification pipeline. See license.h.
 */

#include "activation/license.h"
#include "activation/ed25519.h"
#include "activation/random.h"
#include "activation/sha512.h"

#include <stdint.h>
#include <string.h>

/* Crockford Base32                                                    */

static const char B32_ALPHABET[] = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/** Map an ASCII char to its 5-bit value; -1 when invalid. */
static int b32_value(unsigned char c)
{
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c == 'O') {
        return 0; /* confusable with zero */
    }
    if (c == 'I' || c == 'L') {
        return 1; /* confusable with one */
    }
    if (c >= 'A' && c <= 'Z') {
        if (c == 'U') {
            return -1; /* excluded from the Crockford alphabet */
        }
        const char *pos = strchr(B32_ALPHABET, (char)c);
        return (pos != NULL) ? (int)(pos - B32_ALPHABET) : -1;
    }
    return -1;
}

/** True for characters ignored during decoding. */
static int b32_ignored(unsigned char c)
{
    return c == '-' || c == ' ' || c == '\t' || c == '\r' || c == '\n';
}

/* Payload construction                                                */

void act_license_make(uint8_t out_payload[ACT_PAYLOAD_SIZE],
                      uint8_t out_sig[ACT_SIG_SIZE],
                      uint32_t product_id,
                      const uint8_t machine_code[16],
                      uint32_t expiry_days,
                      unsigned flags,
                      const uint8_t serial[ACT_SERIAL_SIZE],
                      uint16_t features,
                      const uint8_t *sk)
{
    if (out_payload == NULL || out_sig == NULL || sk == NULL) {
        return;
    }
    memset(out_payload, 0, ACT_PAYLOAD_SIZE);
    out_payload[0] = ACT_LICENSE_VERSION;
    out_payload[1] = (uint8_t)(product_id >> 24);
    out_payload[2] = (uint8_t)(product_id >> 16);
    out_payload[3] = (uint8_t)(product_id >> 8);
    out_payload[4] = (uint8_t)(product_id);
    if (machine_code != NULL) {
        memcpy(out_payload + 5, machine_code, 16);
    }
    out_payload[21] = (uint8_t)(expiry_days >> 24);
    out_payload[22] = (uint8_t)(expiry_days >> 16);
    out_payload[23] = (uint8_t)(expiry_days >> 8);
    out_payload[24] = (uint8_t)(expiry_days);
    out_payload[25] = (uint8_t)(flags & (ACT_FLAG_PERPETUAL | ACT_FLAG_TRIAL));
    if (serial != NULL) {
        memcpy(out_payload + 26, serial, ACT_SERIAL_SIZE);
    } else {
        act_random_bytes(out_payload + 26, ACT_SERIAL_SIZE);
    }
    out_payload[34] = (uint8_t)(features >> 8);
    out_payload[35] = (uint8_t)(features);

    act_ed25519_sign(out_sig, out_payload, ACT_PAYLOAD_SIZE, sk);
}

/* Wire codec                                                          */

act_status act_license_encode(const uint8_t payload[ACT_PAYLOAD_SIZE],
                              const uint8_t sig[ACT_SIG_SIZE],
                              char *out, size_t out_cap)
{
    if (payload == NULL || sig == NULL || out == NULL) {
        return ACT_ERR_ARG;
    }

    /* 100 bytes = 800 bits = exactly 160 base32 chars, no padding. */
    uint8_t raw[ACT_CODE_RAW_SIZE];
    memcpy(raw, payload, ACT_PAYLOAD_SIZE);
    memcpy(raw + ACT_PAYLOAD_SIZE, sig, ACT_SIG_SIZE);

    const size_t chars = (ACT_CODE_RAW_SIZE * 8 + 4) / 5; /* 160 */
    if (out_cap < chars + chars / 5 + 1) { /* dashes + NUL */
        return ACT_ERR_ARG;
    }

    size_t o = 0;
    uint32_t acc = 0;
    int bits = 0;
    size_t produced = 0;
    for (size_t i = 0; i < ACT_CODE_RAW_SIZE; i++) {
        acc = (acc << 8) | raw[i];
        bits += 8;
        while (bits >= 5) {
            if (produced > 0 && produced % 5 == 0) {
                out[o++] = '-';
            }
            out[o++] = B32_ALPHABET[(acc >> (bits - 5)) & 31];
            bits -= 5;
            produced++;
        }
    }
    out[o] = '\0';
    return ACT_OK;
}

act_status act_license_decode(const char *code,
                              uint8_t payload[ACT_PAYLOAD_SIZE],
                              uint8_t sig[ACT_SIG_SIZE])
{
    if (code == NULL || payload == NULL || sig == NULL) {
        return ACT_ERR_ARG;
    }

    uint8_t raw[ACT_CODE_RAW_SIZE];
    memset(raw, 0, sizeof(raw));
    size_t bitpos = 0; /* next write position in bits */

    for (const unsigned char *p = (const unsigned char *)code; *p; p++) {
        unsigned char c = *p;
        if (b32_ignored(c)) {
            continue;
        }
        if (c >= 'a' && c <= 'z') {
            c = (unsigned char)(c - 'a' + 'A');
        }
        int v = b32_value(c);
        if (v < 0) {
            return ACT_ERR_FORMAT;
        }
        if (bitpos >= ACT_CODE_RAW_SIZE * 8) {
            return ACT_ERR_FORMAT; /* too long */
        }
        const size_t byte = bitpos / 8;
        const int off = (int)(bitpos % 8);
        /* Place the 5 bits MSB-first into the byte stream via a 16-bit
         * window (avoids negative-shift UB for offsets > 3). */
        const uint32_t slot = (uint32_t)v << (11 - off);
        raw[byte] |= (uint8_t)((slot >> 8) & 0xff);
        if (off > 3) {
            raw[byte + 1] |= (uint8_t)(slot & 0xff);
        }
        bitpos += 5;
    }

    if (bitpos != ACT_CODE_RAW_SIZE * 8) {
        return ACT_ERR_FORMAT; /* truncated */
    }

    memcpy(payload, raw, ACT_PAYLOAD_SIZE);
    memcpy(sig, raw + ACT_PAYLOAD_SIZE, ACT_SIG_SIZE);
    return ACT_OK;
}

/* Verification                                                        */

int64_t act_expiry_to_unix(uint32_t expiry_days)
{
    return ACT_EXPIRY_EPOCH + (int64_t)expiry_days * 86400LL;
}

int64_t act_days_remaining(const act_license_info *info, int64_t now_unix)
{
    if (info == NULL) {
        return 0;
    }
    if ((info->flags & ACT_FLAG_PERPETUAL) != 0) {
        return INT64_MAX; /* unlimited: any `days > 0` test stays true */
    }
    const int64_t exp = act_expiry_to_unix(info->expiry_days);
    if (now_unix >= exp) {
        return 0;
    }
    return (exp - now_unix + 86399) / 86400; /* ceil */
}

int act_has_feature(const act_license_info *info, int bit)
{
    if (info == NULL || bit < 0 || bit > 15) {
        return 0;
    }
    return (info->features >> bit) & 1;
}

act_status act_license_verify_payload(const uint8_t payload[ACT_PAYLOAD_SIZE],
                                      const uint8_t sig[ACT_SIG_SIZE],
                                      const uint8_t pubkey[32],
                                      uint32_t product_id,
                                      const uint8_t machine_code[16],
                                      int64_t now_unix,
                                      act_license_info *info)
{
    if (payload == NULL || sig == NULL || pubkey == NULL ||
        machine_code == NULL) {
        return ACT_ERR_ARG;
    }

    /* 1. Format version (needed to interpret the payload at all). */
    if (payload[0] != ACT_LICENSE_VERSION) {
        return ACT_ERR_VERSION;
    }

    /* 2. Signature -- before any other payload-field logic, so attackers
     *    learn nothing about *why* a forged payload fails beyond
     *    "bad signature" (product/machine/expiry stay unread). */
    if (act_ed25519_verify(sig, payload, ACT_PAYLOAD_SIZE, pubkey) != 0) {
        return ACT_ERR_SIGNATURE;
    }

    /* 3. Product binding. */
    const uint32_t pid = ((uint32_t)payload[1] << 24) |
                         ((uint32_t)payload[2] << 16) |
                         ((uint32_t)payload[3] << 8) |
                         (uint32_t)payload[4];
    if (pid != product_id) {
        return ACT_ERR_PRODUCT;
    }

    /* 4. Machine binding (constant-time compare). */
    if (act_secure_memcmp(payload + 5, machine_code, 16) != 0) {
        return ACT_ERR_MACHINE;
    }

    /* 5. Expiry. */
    const uint32_t expiry = ((uint32_t)payload[21] << 24) |
                            ((uint32_t)payload[22] << 16) |
                            ((uint32_t)payload[23] << 8) |
                            (uint32_t)payload[24];
    const int perpetual = (payload[25] & ACT_FLAG_PERPETUAL) != 0;
    if (!perpetual && now_unix >= act_expiry_to_unix(expiry)) {
        return ACT_ERR_EXPIRED;
    }

    if (info != NULL) {
        info->product_id = pid;
        memcpy(info->machine_code, payload + 5, 16);
        info->expiry_days = expiry;
        info->flags = payload[25];
        info->perpetual = (payload[25] & ACT_FLAG_PERPETUAL) != 0;
        info->trial = (payload[25] & ACT_FLAG_TRIAL) != 0;
        memcpy(info->serial, payload + 26, ACT_SERIAL_SIZE);
        info->features = ((uint16_t)payload[34] << 8) | (uint16_t)payload[35];
    }
    return ACT_OK;
}

act_status act_license_verify(const char *code,
                              const uint8_t pubkey[32],
                              uint32_t product_id,
                              const uint8_t machine_code[16],
                              int64_t now_unix,
                              act_license_info *info)
{
    uint8_t payload[ACT_PAYLOAD_SIZE];
    uint8_t sig[ACT_SIG_SIZE];
    act_status st = act_license_decode(code, payload, sig);
    if (st != ACT_OK) {
        return st;
    }
    return act_license_verify_payload(payload, sig, pubkey, product_id,
                                      machine_code, now_unix, info);
}
