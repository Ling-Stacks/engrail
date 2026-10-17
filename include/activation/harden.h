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
 * @file  harden.h
 * @brief Local hardening: anti-debug, self-integrity, redundant checks.
 *
 * Local license checks can always be *patched out* of the binary that
 * performs them -- that is true for every offline scheme. What this module
 * adds is friction: an attacker must defeat several independent,
 * mutually-reinforcing checks instead of flipping one branch.
 *
 * Provided layers
 *  1. Anti-debug probing (per-platform):
 *       Windows   IsDebuggerPresent / CheckRemoteDebuggerPresent
 *       Linux     /proc/self/status TracerPid + PTRACE_TRACEME probe
 *       Android   as Linux, plus ptrace self-attach
 *       macOS, BSD  sysctl / procctl P_TRACED
 *
 *  2. Executable self-integrity: a SHA-512 digest of your binary is
 *     embedded by `engrail-integrity patch` (see tools/integrity).
 *     act_harden_selfcheck() re-computes the digest over the running
 *     executable (with the embedded slot zeroed) and compares.
 *     Any modification of a distributed, patched binary is detected.
 *
 *  3. Redundant verification: act_verify_hardened() runs the full
 *     license verification twice through independent code paths
 *     (forward and pre-negotiated hash of the inputs) and only accepts
 *     when both agree -- patching a single comparison is not enough.
 *
 * Combine with your own techniques (control-flow flattening, packing,
 * obfuscation) for best effect. Community: https://t.me/Stack_Traces
 */

#ifndef ACTIVATION_HARDEN_H
#define ACTIVATION_HARDEN_H

#include "activation/license.h"

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Statuses                                                            */

#define ACT_ERR_DEBUGGER  (-12) /**< debugger / tracer detected        */
#define ACT_ERR_INTEGRITY (-13) /**< executable failed self-check      */
#define ACT_ERR_MISMATCH  (-14) /**< redundant verification disagreed  */

/* Layer 1: anti-debug                                                 */

/**
 * @brief Probe for debuggers / tracers on the current process.
 * @return 1 when a debugger is (likely) present, 0 otherwise.
 */
int act_harden_debugger_present(void);

/* Layer 2: executable self-integrity                                  */

/**
 * Magic marker that delimits the 64-byte integrity slot inside the
 * binary. `engrail-integrity patch` locates this marker, zeroes the
 * slot, hashes the whole file and writes the digest into the slot.
 */
#define ACT_INTEGRITY_MAGIC     "ACT-INTEGRITY-V1!"
#define ACT_INTEGRITY_MAGIC_LEN 17
#define ACT_INTEGRITY_END       "ACT-INTEGRITY-END!"
#define ACT_INTEGRITY_END_LEN   18
/** Digest starts right after the two magics. */
#define ACT_INTEGRITY_DIGEST_OFF (ACT_INTEGRITY_MAGIC_LEN + ACT_INTEGRITY_END_LEN)
/** Full slot layout: magic(17) + end magic(18) + digest(64) = 99 bytes. */
#define ACT_INTEGRITY_SLOT_SIZE (ACT_INTEGRITY_DIGEST_OFF + 64)

/**
 * Place this once at file scope in your application to reserve the
 * 81-byte integrity slot that `engrail-integrity patch` fills in:
 *
 *     #include "activation/harden.h"
 *     ACT_INTEGRITY_SLOT;
 */
#if defined(__GNUC__)
#  define ACT_INTEGRITY_SLOT_USED __attribute__((used))
#else
#  define ACT_INTEGRITY_SLOT_USED
#endif
/** Un-patched slots carry this 64-byte fingerprint in the digest region
 *  (never zeros -- .rodata alignment padding must not look like a slot). */
#define ACT_INTEGRITY_FRESH 0xAA

#ifdef __cplusplus
/* C++ forbids string-literal initializers for unsigned char[]; use an
 * explicit byte list: magic(17) + end(18) + fingerprint(64) = 99. */
#  define ACT_INTEGRITY_SLOT                                                  \
    ACT_INTEGRITY_SLOT_USED                                                   \
    volatile const unsigned char act_integrity_slot[ACT_INTEGRITY_SLOT_SIZE] =\
        { 'A','C','T','-','I','N','T','E','G','R','I','T','Y','-', \
          'V','1','!','A','C','T','-','I','N','T','E','G','R','I', \
          'T','Y','-','E','N','D','!',0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA, \
          0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA, \
          0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA, \
          0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA, \
          0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA, \
          0xAA }
#else
#  define ACT_INTEGRITY_SLOT                                                  \
    ACT_INTEGRITY_SLOT_USED                                                   \
    volatile const unsigned char act_integrity_slot[ACT_INTEGRITY_SLOT_SIZE] = \
        ACT_INTEGRITY_MAGIC ACT_INTEGRITY_END                                 \
        "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa" \
        "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa" \
        "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa" \
        "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
#endif

/**
 * @brief Verify the integrity of the running executable.
 *
 * Returns #ACT_OK when the binary was patched by `engrail-integrity
 * patch` and has not been modified since. Returns #ACT_ERR_INTEGRITY on
 * mismatch or corruption. A binary that was never patched reports
 * #ACT_ERR_STATE_MISSING (integrity protection simply not enabled).
 */
act_status act_harden_selfcheck(void);

/**
 * @brief Convenience: compute the digest that `patch` should embed.
 *
 * Reads @p path, zeroes the slot region, hashes everything with
 * SHA-512. Used by the integrity tool; exposed for testing.
 */
act_status act_harden_compute_digest(const char *path, uint8_t out[64]);

/* Layer 3: redundant verification                                     */

/**
 * @brief Hardened activation-code verification.
 *
 * Runs the standard verification pipeline twice -- once directly, once
 * through a re-derived sub-key comparison -- and requires both runs to
 * agree on the verdict. Optionally gates on anti-debug and self-integrity.
 *
 * @param code          user-supplied activation code.
 * @param pubkey        vendor public key.
 * @param product_id    expected product id.
 * @param machine_code  local machine fingerprint.
 * @param now_unix      current time.
 * @param check_debugger non-zero: return #ACT_ERR_DEBUGGER when traced.
 * @param check_integrity non-zero: run act_harden_selfcheck() first.
 * @param info          optional decoded license info.
 * @return #ACT_OK or the first failing check's status.
 */
act_status act_verify_hardened(const char *code,
                               const uint8_t pubkey[32],
                               uint32_t product_id,
                               const uint8_t machine_code[16],
                               int64_t now_unix,
                               int check_debugger,
                               int check_integrity,
                               act_license_info *info);

#ifdef __cplusplus
}
#endif

#endif /* ACTIVATION_HARDEN_H */
