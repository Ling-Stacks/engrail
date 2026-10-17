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
 * @file  audit.h
 * @brief Tamper-evident chained audit log (compliance grade).
 *
 * Enterprise deployments need provable trails of licensing events
 * (ISO 27001 A.12.4, SOC 2 CC7.2). This module provides an
 * append-only log where every entry is cryptographically chained to
 * its predecessor:
 *
 *   genesis : "ACTAUDIT1" || nonce(16) || genesis_hmac
 *   entry   : type(1) || ts(8BE) || len(2BE) || detail(len)
 *             || prev_hmac(32) || entry_hmac(32)
 *
 *   entry_hmac = HMAC-SHA512(log_key, header || detail || prev_hmac)
 *
 * Tampering with ANY byte, deleting ANY entry, or reordering entries
 * breaks the chain and is detected by act_audit_verify(). The log key
 * is deployment-derived (e.g. the HKDF session key), so an attacker
 * who can read the file still cannot forge or re-spin the chain.
 *
 * Community: https://t.me/Stack_Traces
 */

#ifndef ACTIVATION_AUDIT_H
#define ACTIVATION_AUDIT_H

#include "activation/license.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Genesis record size: magic(9) + nonce(16) + hmac(64->truncated 32). */
#define ACT_AUDIT_GENESIS_SIZE 57
/** Per-entry overhead: type(1) + ts(8) + len(2) + prev(32) + hmac(32). */
#define ACT_AUDIT_ENTRY_OVERHEAD 75

/** Well-known event types (applications may define 0x40..0xFF). */
#define ACT_AUDIT_EV_ACTIVATE   0x01
#define ACT_AUDIT_EV_VERIFY     0x02
#define ACT_AUDIT_EV_REJECT     0x03
#define ACT_AUDIT_EV_REVOKE     0x04
#define ACT_AUDIT_EV_HEARTBEAT  0x05
#define ACT_AUDIT_EV_APP_CUSTOM 0x40

/**
 * @brief Create (or re-open) an audit log.
 *
 * If the file does not exist, a genesis record with a fresh CSPRNG
 * nonce is written. If it exists, its chain is verified first.
 *
 * @param path log file path.
 * @param key  32-byte log key (deployment-derived; keep consistent).
 * @return #ACT_OK; #ACT_ERR_SIGNATURE when an existing log fails
 *         verification; I/O errors otherwise.
 */
act_status act_audit_init(const char *path, const uint8_t key[32]);

/**
 * @brief Append one tamper-evident entry.
 * @param path   log file.
 * @param key    log key.
 * @param type   event type (#ACT_AUDIT_EV_* or application-defined).
 * @param detail optional detail bytes (max 65535).
 */
act_status act_audit_append(const char *path, const uint8_t key[32],
                            uint8_t type, const void *detail, size_t len);

/**
 * @brief Verify the full chain from genesis to the last entry.
 *
 * @param path      log file.
 * @param key       log key.
 * @param count_out optional: number of verified entries.
 * @param tail_out  optional: last entry HMAC (32 bytes) -- compare
 *                  against a remotely stored value to detect a
 *                  truncated-and-rebuilt log.
 * @return #ACT_OK when the whole chain verifies.
 */
act_status act_audit_verify(const char *path, const uint8_t key[32],
                            uint32_t *count_out, uint8_t tail_out[32]);

#ifdef __cplusplus
}
#endif

#endif /* ACTIVATION_AUDIT_H */
