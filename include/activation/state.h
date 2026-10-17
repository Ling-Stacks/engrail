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
 * @file  state.h
 * @brief Local activation state persistence.
 *
 * Design: the client never holds any secret. The state file simply
 * persists the *vendor-signed* payload+signature of a previously accepted
 * activation code, prefixed with a small header:
 *
 *   offset  size  field
 *   0       4     magic "ACT1"
 *   4       1     state format version (0x01)
 *   5       26    license payload (vendor-signed)
 *   31      64    Ed25519 signature over the payload
 *
 * Because validity always comes from the vendor signature:
 *   - editing any byte of the state breaks the signature (tamper-evident),
 *   - a state file copied from another machine fails the machine-binding
 *     check (anti-cloning),
 *   - nothing in the file can be regenerated offline (anti-forgery).
 */

#ifndef ACTIVATION_STATE_H
#define ACTIVATION_STATE_H

#include "activation/license.h"

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** On-disk size of a state file in bytes (4 + 1 + payload + sig). */
#define ACT_STATE_FILE_SIZE 105

/**
 * @brief Persist an accepted activation payload.
 *
 * Creates/truncates @p path. On POSIX the file mode is 0600.
 *
 * @param path    destination file path.
 * @param payload accepted payload (#ACT_PAYLOAD_SIZE bytes).
 * @param sig     matching signature (#ACT_SIG_SIZE bytes).
 * @return #ACT_OK or #ACT_ERR_ARG / #ACT_ERR_STATE_IO.
 */
act_status act_state_save(const char *path,
                          const uint8_t payload[ACT_PAYLOAD_SIZE],
                          const uint8_t sig[ACT_SIG_SIZE]);

/**
 * @brief Read a state file (raw, integrity-checked structurally only).
 *
 * @param path    source file path.
 * @param payload output payload.
 * @param sig     output signature.
 * @return #ACT_OK, #ACT_ERR_STATE_MISSING / #ACT_ERR_STATE_IO /
 *         #ACT_ERR_STATE_CORRUPT.
 */
act_status act_state_load(const char *path,
                          uint8_t payload[ACT_PAYLOAD_SIZE],
                          uint8_t sig[ACT_SIG_SIZE]);

/**
 * @brief Load AND fully verify the saved activation state.
 *
 * Convenience for the common startup check:
 * `load -> signature -> product -> machine -> expiry`.
 *
 * @param path         state file path.
 * @param pubkey       product public key.
 * @param product_id   expected product id.
 * @param machine_code current machine fingerprint.
 * @param now_unix     current UTC time.
 * @param info         optional decoded license info (may be NULL).
 * @return #ACT_OK or the specific #act_status failure.
 */
act_status act_state_check(const char *path,
                           const uint8_t pubkey[32],
                           uint32_t product_id,
                           const uint8_t machine_code[16],
                           int64_t now_unix,
                           act_license_info *info);

#ifdef __cplusplus
}
#endif

#endif /* ACTIVATION_STATE_H */
