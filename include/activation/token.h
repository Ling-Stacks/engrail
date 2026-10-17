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
 * @file  token.h
 * @brief General-purpose offline authentication tokens and
 *        challenge-response authentication.
 *
 * While license.h solves "entitle a machine", this module solves the
 * broader "authenticate a message/person offline" problem:
 *
 *   - Signed tokens: arbitrary payload bytes + Ed25519 signature +
 *     issue-time + TTL, wire-encoded as URL-safe Base64. Use them for
 *     signed commands, offline session tickets, signed configuration,
 *     API-offline webhooks, etc.
 *
 *   - Challenge-response: the offline party issues a fresh random
 *     challenge bound to (product, machine, time); the vendor side signs
 *     it; the challenge is verified locally, offline. Proves possession
 *     of the vendor key *for this machine, right now* without ever
 *     transmitting anything secret.
 *
 * Token wire format (Base64URL, no padding):
 *   "ACTT" magic(4) | version(1) | product(4BE) | iat(8BE) | ttl(4BE)
 *   | payload_len(4BE) | payload(n) | Ed25519 sig(64) over everything
 *   before the signature.
 *
 * Challenge wire format (Base64URL):
 *   "ACTC1" magic(5) | product(4BE) | machine(16) | nonce(16) | iat(8BE)
 *   = 49 bytes.
 * Response token: "ACTR1" magic(5) | Ed25519 sig(64) over the 49-byte
 * challenge = 69 bytes.
 *
 * Community: https://t.me/Stack_Traces
 */

#ifndef ACTIVATION_TOKEN_H
#define ACTIVATION_TOKEN_H

#include "activation/license.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Recommended maximum arbitrary payload (keeps tokens reasonable). */
#define ACT_TOKEN_MAX_PAYLOAD 4096
/** Token text capacity for a given payload length:
 *  header(25) + payload + sig(64), Base64URL, + NUL. */
#define ACT_TOKEN_MAX_CHARS(payload_len) \
    ((((25 + (size_t)(payload_len) + 64) + 2) / 3) * 4 + 1)

/** Challenge nonce size. */
#define ACT_CHALLENGE_NONCE_SIZE 16
/** Default challenge validity for act_challenge_verify(). */
#define ACT_CHALLENGE_MAX_AGE 300

/** Decoded token metadata. */
typedef struct act_token_info {
    uint32_t product_id;
    int64_t  issued_at;   /**< Unix time of signing            */
    uint32_t ttl;         /**< seconds of validity (0 = forever)*/
    size_t   payload_len;
} act_token_info;

/* Signed tokens                                                       */

/**
 * @brief Create a signed offline token over arbitrary payload bytes.
 *
 * @param sk           vendor private key.
 * @param product_id   product identifier (checked at verify time).
 * @param payload      arbitrary bytes (NOT interpreted by the library).
 * @param payload_len  payload length (<= #ACT_TOKEN_MAX_PAYLOAD).
 * @param ttl_seconds  validity window from now (0 = no expiry).
 * @param out          output token text (NUL-terminated Base64URL).
 * @param out_cap      capacity; use ACT_TOKEN_MAX_CHARS(payload_len)+1.
 * @return #ACT_OK or #ACT_ERR_ARG.
 */
act_status act_token_create(const uint8_t sk[64], uint32_t product_id,
                            const uint8_t *payload, size_t payload_len,
                            uint32_t ttl_seconds,
                            char *out, size_t out_cap);

/**
 * @brief Verify a token: signature, product binding and TTL.
 *
 * @param token        token text.
 * @param pk           vendor public key.
 * @param product_id   expected product id.
 * @param now_unix     current time.
 * @param payload_out  optional output buffer for the payload.
 * @param cap          capacity of @p payload_out.
 * @param len_out      optional: receives the payload length.
 * @param info_out     optional: receives token metadata.
 * @return #ACT_OK, #ACT_ERR_FORMAT (structure), #ACT_ERR_SIGNATURE,
 *         #ACT_ERR_PRODUCT, or #ACT_ERR_EXPIRED.
 */
act_status act_token_verify(const char *token, const uint8_t pk[32],
                            uint32_t product_id, int64_t now_unix,
                            uint8_t *payload_out, size_t cap,
                            size_t *len_out, act_token_info *info_out);

/* Challenge-response                                                  */

/**
 * @brief (Offline party) Create a fresh challenge bound to this machine.
 *
 * The nonce is drawn from the OS CSPRNG; the challenge embeds the
 * machine fingerprint so responses are non-transferable.
 *
 * @param machine_code   local fingerprint (16 bytes).
 * @param product_id     product identifier.
 * @param now_unix       current time (embedded for replay protection).
 * @param out            output challenge text.
 * @param out_cap        capacity (>= 80 chars recommended).
 */
act_status act_challenge_create(const uint8_t machine_code[16],
                                uint32_t product_id, int64_t now_unix,
                                char *out, size_t out_cap);

/**
 * @brief (Vendor side) Sign a challenge. No secret ever touches the wire
 *        -- only the Ed25519 signature over the challenge bytes.
 */
act_status act_challenge_respond(const char *challenge, const uint8_t sk[64],
                                 char *out, size_t out_cap);

/**
 * @brief (Offline party) Verify a response against a challenge.
 *
 * Checks: response is a signature over EXACTLY these challenge bytes,
 * made by @p pk; product and machine match; the challenge is still
 * fresh (<= @p max_age seconds, pass 0 for #ACT_CHALLENGE_MAX_AGE).
 *
 * @return #ACT_OK or the failing check's #act_status.
 */
act_status act_challenge_verify(const char *challenge, const char *response,
                                const uint8_t pk[32], uint32_t product_id,
                                const uint8_t machine_code[16],
                                int64_t now_unix, int64_t max_age);

#ifdef __cplusplus
}
#endif

#endif /* ACTIVATION_TOKEN_H */
