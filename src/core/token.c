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
 * @file  token.c
 * @brief Offline auth tokens + challenge-response. See token.h.
 */

#include "activation/token.h"
#include "activation/ed25519.h"
#include "activation/random.h"
#include "activation/sha512.h"

#include <stdio.h>
#include <string.h>
#include <time.h>

/* Base64URL (RFC 4648 §5, unpadded)                                   */

static const char B64URL[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

static size_t b64url_encode(const uint8_t *in, size_t len,
                            char *out, size_t cap)
{
    const size_t need = ((len + 2) / 3) * 4;
    if (cap < need + 1) {
        return 0;
    }
    size_t o = 0, i = 0;
    while (i + 3 <= len) {
        const uint32_t v = ((uint32_t)in[i] << 16) |
                           ((uint32_t)in[i + 1] << 8) | in[i + 2];
        out[o++] = B64URL[(v >> 18) & 63];
        out[o++] = B64URL[(v >> 12) & 63];
        out[o++] = B64URL[(v >> 6) & 63];
        out[o++] = B64URL[v & 63];
        i += 3;
    }
    const size_t rem = len - i;
    if (rem == 1) {
        const uint32_t v = (uint32_t)in[i] << 16;
        out[o++] = B64URL[(v >> 18) & 63];
        out[o++] = B64URL[(v >> 12) & 63];
    } else if (rem == 2) {
        const uint32_t v = ((uint32_t)in[i] << 16) |
                           ((uint32_t)in[i + 1] << 8);
        out[o++] = B64URL[(v >> 18) & 63];
        out[o++] = B64URL[(v >> 12) & 63];
        out[o++] = B64URL[(v >> 6) & 63];
    }
    out[o] = '\0';
    return o;
}

static int b64url_val(unsigned char c)
{
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '-') return 62;
    if (c == '_') return 63;
    return -1;
}

static size_t b64url_decode(const char *in, uint8_t *out, size_t cap)
{
    uint32_t acc = 0;
    int bits = 0;
    size_t o = 0;
    for (const unsigned char *p = (const unsigned char *)in; *p; p++) {
        if (*p == '=') break;
        const int v = b64url_val(*p);
        if (v < 0) return 0; /* invalid char */
        acc = (acc << 6) | (uint32_t)v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            if (o >= cap) return 0;
            out[o++] = (uint8_t)(acc >> bits);
        }
    }
    return o;
}

/* Signed tokens                                                       */

/** Header size: magic(4)+ver(1)+product(4)+iat(8)+ttl(4)+len(4) = 25. */
#define TOKEN_HEADER_SIZE 25
#define TOKEN_MAGIC "ACTT"

act_status act_token_create(const uint8_t sk[64], uint32_t product_id,
                            const uint8_t *payload, size_t payload_len,
                            uint32_t ttl_seconds,
                            char *out, size_t out_cap)
{
    if (sk == NULL || (payload == NULL && payload_len > 0) || out == NULL) {
        return ACT_ERR_ARG;
    }
    if (payload_len > ACT_TOKEN_MAX_PAYLOAD) {
        return ACT_ERR_ARG;
    }

    uint8_t raw[TOKEN_HEADER_SIZE + ACT_TOKEN_MAX_PAYLOAD + ACT_SIG_SIZE];
    const size_t body = TOKEN_HEADER_SIZE + payload_len;

    memcpy(raw, TOKEN_MAGIC, 4);
    raw[4] = 0x01;
    raw[5] = (uint8_t)(product_id >> 24);
    raw[6] = (uint8_t)(product_id >> 16);
    raw[7] = (uint8_t)(product_id >> 8);
    raw[8] = (uint8_t)(product_id);
    const int64_t now = (int64_t)time(NULL);
    for (int i = 0; i < 8; i++) {
        raw[9 + i] = (uint8_t)((uint64_t)now >> (56 - 8 * i));
    }
    raw[17] = (uint8_t)(ttl_seconds >> 24);
    raw[18] = (uint8_t)(ttl_seconds >> 16);
    raw[19] = (uint8_t)(ttl_seconds >> 8);
    raw[20] = (uint8_t)(ttl_seconds);
    raw[21] = (uint8_t)(payload_len >> 24);
    raw[22] = (uint8_t)(payload_len >> 16);
    raw[23] = (uint8_t)(payload_len >> 8);
    raw[24] = (uint8_t)(payload_len);
    if (payload_len > 0) {
        memcpy(raw + TOKEN_HEADER_SIZE, payload, payload_len);
    }
    act_ed25519_sign(raw + body, raw, body, sk);

    const size_t n = b64url_encode(raw, body + ACT_SIG_SIZE, out, out_cap);
    act_secure_wipe(raw, sizeof(raw));
    return n ? ACT_OK : ACT_ERR_ARG;
}

act_status act_token_verify(const char *token, const uint8_t pk[32],
                            uint32_t product_id, int64_t now_unix,
                            uint8_t *payload_out, size_t cap,
                            size_t *len_out, act_token_info *info_out)
{
    if (token == NULL || pk == NULL) {
        return ACT_ERR_ARG;
    }

    uint8_t raw[TOKEN_HEADER_SIZE + ACT_TOKEN_MAX_PAYLOAD + ACT_SIG_SIZE];
    const size_t raw_len = b64url_decode(token, raw, sizeof(raw));
    if (raw_len < TOKEN_HEADER_SIZE + ACT_SIG_SIZE ||
        memcmp(raw, TOKEN_MAGIC, 4) != 0 || raw[4] != 0x01) {
        return ACT_ERR_FORMAT;
    }

    const uint32_t pid = ((uint32_t)raw[5] << 24) | ((uint32_t)raw[6] << 16) |
                         ((uint32_t)raw[7] << 8) | (uint32_t)raw[8];
    int64_t iat = 0;
    for (int i = 0; i < 8; i++) {
        iat = (iat << 8) | raw[9 + i];
    }
    const uint32_t ttl = ((uint32_t)raw[17] << 24) |
                         ((uint32_t)raw[18] << 16) |
                         ((uint32_t)raw[19] << 8) | (uint32_t)raw[20];
    const uint32_t plen = ((uint32_t)raw[21] << 24) |
                          ((uint32_t)raw[22] << 16) |
                          ((uint32_t)raw[23] << 8) | (uint32_t)raw[24];

    if (plen > ACT_TOKEN_MAX_PAYLOAD ||
        raw_len != TOKEN_HEADER_SIZE + (size_t)plen + ACT_SIG_SIZE) {
        return ACT_ERR_FORMAT;
    }
    if (pid != product_id) {
        return ACT_ERR_PRODUCT;
    }
    /* Signature over header+payload. */
    if (act_ed25519_verify(raw + TOKEN_HEADER_SIZE + plen, raw,
                           TOKEN_HEADER_SIZE + (size_t)plen, pk) != 0) {
        return ACT_ERR_SIGNATURE;
    }
    if (ttl != 0 && now_unix >= iat + (int64_t)ttl) {
        return ACT_ERR_EXPIRED;
    }

    if (payload_out != NULL) {
        if (cap < plen) {
            return ACT_ERR_ARG;
        }
        memcpy(payload_out, raw + TOKEN_HEADER_SIZE, plen);
    }
    if (len_out != NULL) {
        *len_out = plen;
    }
    if (info_out != NULL) {
        info_out->product_id = pid;
        info_out->issued_at = iat;
        info_out->ttl = ttl;
        info_out->payload_len = plen;
    }
    return ACT_OK;
}

/* Challenge-response                                                  */

#define CHAL_MAGIC "ACTC1"
#define CHAL_SIZE (5 + 4 + 16 + 16 + 8) /* 49 */
#define RESP_MAGIC "ACTR1"
#define RESP_SIZE (5 + 64) /* 69 */

act_status act_challenge_create(const uint8_t machine_code[16],
                                uint32_t product_id, int64_t now_unix,
                                char *out, size_t out_cap)
{
    if (machine_code == NULL || out == NULL) {
        return ACT_ERR_ARG;
    }
    uint8_t ch[CHAL_SIZE];
    uint8_t nonce[ACT_CHALLENGE_NONCE_SIZE];
    act_random_bytes(nonce, sizeof(nonce));

    memcpy(ch, CHAL_MAGIC, 5);
    ch[5] = (uint8_t)(product_id >> 24);
    ch[6] = (uint8_t)(product_id >> 16);
    ch[7] = (uint8_t)(product_id >> 8);
    ch[8] = (uint8_t)(product_id);
    memcpy(ch + 9, machine_code, 16);
    memcpy(ch + 25, nonce, 16);
    for (int i = 0; i < 8; i++) {
        ch[41 + i] = (uint8_t)((uint64_t)now_unix >> (56 - 8 * i));
    }
    act_secure_wipe(nonce, sizeof(nonce));

    const size_t n = b64url_encode(ch, CHAL_SIZE, out, out_cap);
    act_secure_wipe(ch, sizeof(ch));
    return n ? ACT_OK : ACT_ERR_ARG;
}

act_status act_challenge_respond(const char *challenge, const uint8_t sk[64],
                                 char *out, size_t out_cap)
{
    if (challenge == NULL || sk == NULL || out == NULL) {
        return ACT_ERR_ARG;
    }
    uint8_t ch[CHAL_SIZE];
    if (b64url_decode(challenge, ch, sizeof(ch)) != CHAL_SIZE ||
        memcmp(ch, CHAL_MAGIC, 5) != 0) {
        return ACT_ERR_FORMAT;
    }

    uint8_t resp[RESP_SIZE];
    memcpy(resp, RESP_MAGIC, 5);
    act_ed25519_sign(resp + 5, ch, CHAL_SIZE, sk);
    const size_t n = b64url_encode(resp, RESP_SIZE, out, out_cap);
    act_secure_wipe(ch, sizeof(ch));
    act_secure_wipe(resp, sizeof(resp));
    return n ? ACT_OK : ACT_ERR_ARG;
}

act_status act_challenge_verify(const char *challenge, const char *response,
                                const uint8_t pk[32], uint32_t product_id,
                                const uint8_t machine_code[16],
                                int64_t now_unix, int64_t max_age)
{
    if (challenge == NULL || response == NULL || pk == NULL ||
        machine_code == NULL) {
        return ACT_ERR_ARG;
    }
    if (max_age <= 0) {
        max_age = ACT_CHALLENGE_MAX_AGE;
    }

    uint8_t ch[CHAL_SIZE];
    if (b64url_decode(challenge, ch, sizeof(ch)) != CHAL_SIZE ||
        memcmp(ch, CHAL_MAGIC, 5) != 0) {
        return ACT_ERR_FORMAT;
    }

    /* Structure + binding checks BEFORE the signature so attackers learn
     * nothing from timing of signature math on mismatched challenges. */
    const uint32_t pid = ((uint32_t)ch[5] << 24) | ((uint32_t)ch[6] << 16) |
                         ((uint32_t)ch[7] << 8) | (uint32_t)ch[8];
    if (pid != product_id) {
        return ACT_ERR_PRODUCT;
    }
    if (act_secure_memcmp(ch + 9, machine_code, 16) != 0) {
        return ACT_ERR_MACHINE;
    }
    int64_t iat = 0;
    for (int i = 0; i < 8; i++) {
        iat = (iat << 8) | ch[41 + i];
    }
    if (now_unix - iat > max_age) {
        return ACT_ERR_EXPIRED;
    }

    uint8_t resp[RESP_SIZE];
    if (b64url_decode(response, resp, sizeof(resp)) != RESP_SIZE ||
        memcmp(resp, RESP_MAGIC, 5) != 0) {
        return ACT_ERR_FORMAT;
    }
    if (act_ed25519_verify(resp + 5, ch, CHAL_SIZE, pk) != 0) {
        return ACT_ERR_SIGNATURE;
    }
    return ACT_OK;
}
