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
 * @file  license.h
 * @brief Activation code format: signed payload + Crockford Base32 wire form.
 *
 * Wire format (v2)
 *   code = BASE32_CROCKFORD( payload[36] || signature[64] )
 *
 *   payload:
 *     [ 0]      format version (0x02)
 *     [ 1.. 4]  product id (big-endian uint32)
 *     [ 5..20]  machine code (16 bytes, see fingerprint.h)
 *     [21..24]  expiry, days since 2020-01-01 UTC (big-endian uint32)
 *     [25]      flags (bit0: perpetual, bit1: trial)
 *     [26..33]  serial (8 bytes, random; the revocation identity)
 *     [34..35]  feature mask (big-endian uint16, product-defined tiers)
 *
 *   signature: Ed25519 over payload[36] with the vendor private key.
 *
 * The Base32 string is presented in groups of 5 separated by '-'.
 * Decoding accepts any case, '-', spaces and the Crockford confusables
 * (O->0, I->1, L->1).
 *
 * The serial lets vendors publish a *signed revocation list* (see
 * revoke.h): stolen/refunded codes can be invalidated by shipping an
 * updated revocation file, without touching the app's verification logic.
 *
 * The feature mask lets one product line encode tiers (e.g. bit0 = pro,
 * bit1 = ultimate) -- the app interprets the bits.
 *
 * Security properties
 *   - Forgery requires the vendor private key (Ed25519 unforgeability).
 *   - Any payload modification invalidates the signature (tamper-evidence).
 *   - The machine code inside the payload binds the code to one device.
 *   - The payload is fully public; nothing in a code is secret.
 */

#ifndef ACTIVATION_LICENSE_H
#define ACTIVATION_LICENSE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Sizes                                                               */

#define ACT_PAYLOAD_SIZE   36   /**< signed payload bytes                */
#define ACT_SIG_SIZE       64   /**< Ed25519 signature bytes             */
#define ACT_SERIAL_SIZE    8    /**< license serial bytes                */
#define ACT_CODE_RAW_SIZE  100  /**< payload + signature                 */
#define ACT_CODE_MAX_CHARS 200  /**< decoded-string capacity (with '-'s) */

/** Current payload format version. */
#define ACT_LICENSE_VERSION 0x02

/** Payload flag: perpetual license, expiry field is ignored. */
#define ACT_FLAG_PERPETUAL 0x01
/** Payload flag: trial license (meaning is app-defined). */
#define ACT_FLAG_TRIAL     0x02

/* Status codes                                                        */

/**
 * @brief Result codes shared by the whole library.
 *
 * All failures are negative; ACT_OK is zero. Values are stable ABI.
 */
typedef enum act_status {
    ACT_OK               =  0,  /**< success                            */
    ACT_ERR_ARG          = -1,  /**< NULL / bad argument                */
    ACT_ERR_FORMAT       = -2,  /**< code is not a valid wire format    */
    ACT_ERR_VERSION      = -3,  /**< unknown payload version            */
    ACT_ERR_PRODUCT      = -4,  /**< product id mismatch                */
    ACT_ERR_SIGNATURE    = -5,  /**< signature invalid (forged/tampered)*/
    ACT_ERR_MACHINE      = -6,  /**< machine fingerprint mismatch       */
    ACT_ERR_EXPIRED      = -7,  /**< license expired                    */
    ACT_ERR_STATE_MISSING= -8,  /**< local state file does not exist    */
    ACT_ERR_STATE_IO     = -9,  /**< state file read/write failure      */
    ACT_ERR_STATE_CORRUPT= -10, /**< state file failed integrity check  */
    ACT_ERR_REVOKED      = -11, /**< serial found on revocation list    */
    /* -12 .. -14 are reserved by harden.h (debugger / integrity /
     * mismatch). Keep new core codes at -15 and below. */
    ACT_ERR_ENTROPY      = -15  /**< system CSPRNG unavailable/failed   */
} act_status;

/** Decoded, verified license payload. */
typedef struct act_license_info {
    uint32_t product_id;                  /**< product identifier          */
    uint8_t  machine_code[16];            /**< bound machine fingerprint   */
    uint32_t expiry_days;                 /**< days since 2020-01-01 UTC   */
    uint8_t  flags;                       /**< ACT_FLAG_* bitmap           */
    int      perpetual;                   /**< convenience: flags&bit0 !=0 */
    int      trial;                       /**< convenience: flags&bit1 !=0 */
    uint8_t  serial[ACT_SERIAL_SIZE];     /**< revocation identity         */
    uint16_t features;                    /**< product-defined tier mask   */
} act_license_info;

/* Payload helpers                                                     */

/**
 * @brief Build and sign a payload.
 *
 * @param out_payload  output payload (#ACT_PAYLOAD_SIZE bytes).
 * @param out_sig      output signature (#ACT_SIG_SIZE bytes).
 * @param product_id   product identifier.
 * @param machine_code 16-byte machine code the license is bound to.
 * @param expiry_days  days since 2020-01-01 UTC after which the code
 *                     expires (ignored when perpetual != 0).
 * @param flags        ACT_FLAG_* bitmap (perpetual / trial).
 * @param serial       8-byte serial; when NULL a random one is drawn
 *                     from the OS CSPRNG.
 * @param features     product-defined feature mask.
 * @param sk           Ed25519 private key (#ACT_ED25519_PRIVKEY_SIZE).
 */
void act_license_make(uint8_t out_payload[ACT_PAYLOAD_SIZE],
                      uint8_t out_sig[ACT_SIG_SIZE],
                      uint32_t product_id,
                      const uint8_t machine_code[16],
                      uint32_t expiry_days,
                      unsigned flags,
                      const uint8_t serial[ACT_SERIAL_SIZE],
                      uint16_t features,
                      const uint8_t *sk);

/* Wire format                                                         */

/**
 * @brief Encode payload||signature into the dashed Crockford string.
 *
 * @param payload    #ACT_PAYLOAD_SIZE bytes.
 * @param sig        #ACT_SIG_SIZE bytes.
 * @param out        output buffer.
 * @param out_cap    buffer capacity (>= #ACT_CODE_MAX_CHARS recommended).
 * @return #ACT_OK, or #ACT_ERR_ARG on NULL/small buffer.
 */
act_status act_license_encode(const uint8_t payload[ACT_PAYLOAD_SIZE],
                              const uint8_t sig[ACT_SIG_SIZE],
                              char *out, size_t out_cap);

/**
 * @brief Decode a user-supplied activation code (normalisation included).
 *
 * @param code    NUL-terminated user input (case/dashes/spaces forgiven).
 * @param payload output payload, #ACT_PAYLOAD_SIZE bytes.
 * @param sig     output signature, #ACT_SIG_SIZE bytes.
 * @return #ACT_OK or #ACT_ERR_FORMAT / #ACT_ERR_ARG.
 */
act_status act_license_decode(const char *code,
                              uint8_t payload[ACT_PAYLOAD_SIZE],
                              uint8_t sig[ACT_SIG_SIZE]);

/**
 * @brief Fully verify an activation code (decode + signature + binding).
 *
 * Verification order: format -> version -> signature -> product ->
 * machine binding -> expiry. The first failure wins.
 *
 * @param code          user-supplied activation code.
 * @param pubkey        product Ed25519 public key.
 * @param product_id    expected product identifier.
 * @param machine_code  local machine fingerprint (16 bytes).
 * @param now_unix      current UTC time (time(NULL)); enables expiry check.
 * @param info          optional output of decoded fields (may be NULL).
 * @return #ACT_OK or the corresponding #act_status error.
 */
act_status act_license_verify(const char *code,
                              const uint8_t pubkey[32],
                              uint32_t product_id,
                              const uint8_t machine_code[16],
                              int64_t now_unix,
                              act_license_info *info);

/**
 * @brief Verify a decoded payload directly (no string parsing).
 * @see act_license_verify
 */
act_status act_license_verify_payload(const uint8_t payload[ACT_PAYLOAD_SIZE],
                                      const uint8_t sig[ACT_SIG_SIZE],
                                      const uint8_t pubkey[32],
                                      uint32_t product_id,
                                      const uint8_t machine_code[16],
                                      int64_t now_unix,
                                      act_license_info *info);

/** Unix timestamp of the expiry epoch anchor (2020-01-01T00:00:00Z). */
#define ACT_EXPIRY_EPOCH 1577836800LL

/** Convert expiry_days (payload field) to a Unix timestamp. */
int64_t act_expiry_to_unix(uint32_t expiry_days);

/**
 * @brief Days remaining until the license expires (>= 0).
 * @return #INT64_MAX for perpetual licenses, 0 when already expired.
 *
 * `days > 0` therefore means "still valid" for every license kind;
 * check @c info->perpetual (or compare against #INT64_MAX) to single
 * out unlimited terms.
 */
int64_t act_days_remaining(const act_license_info *info, int64_t now_unix);

/** @brief Feature-tier query: is feature bit @p bit set? */
int act_has_feature(const act_license_info *info, int bit);

#ifdef __cplusplus
}
#endif

#endif /* ACTIVATION_LICENSE_H */
