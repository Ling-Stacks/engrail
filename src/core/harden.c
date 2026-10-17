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
 * @file  harden.c
 * @brief Anti-debug, self-integrity and redundant verification. See harden.h.
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

#include "activation/harden.h"
#include "activation/ed25519.h"
#include "activation/hmac.h"
#include "activation/sha512.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Executable path resolution (per platform)                           */

#if defined(_WIN32)
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  ifndef NOMINMAX
#    define NOMINMAX
#  endif
#  include <windows.h>
#elif defined(__APPLE__)
#  include <mach-o/dyld.h>
#  include <limits.h>
#  include <sys/types.h>
#  include <sys/sysctl.h>
#  include <unistd.h>
#  ifndef P_TRACED
#    define P_TRACED 0x00000800
#  endif
#elif defined(__linux__) || defined(__ANDROID__) || defined(__unix__)
#  include <unistd.h>
#  include <limits.h>
#endif

/**
 * @brief Resolve the path of the running executable into @p buf.
 * @return length written, or -1 when unsupported.
 */
static int self_path(char *buf, size_t cap)
{
#if defined(_WIN32)
    const DWORD n = GetModuleFileNameA(NULL, buf, (DWORD)cap);
    return (n > 0 && n < cap) ? (int)n : -1;
#elif defined(__APPLE__)
    uint32_t size = (uint32_t)cap;
    return (_NSGetExecutablePath(buf, &size) == 0) ? (int)strlen(buf) : -1;
#elif defined(__linux__) || defined(__ANDROID__)
    const ssize_t n = readlink("/proc/self/exe", buf, cap - 1);
    if (n > 0) {
        buf[n] = '\0';
        return (int)n;
    }
    return -1;
#elif defined(__unix__)
    const ssize_t n = readlink("/proc/curproc/exe", buf, cap - 1);
    if (n > 0) {
        buf[n] = '\0';
        return (int)n;
    }
    return -1;
#else
    (void)buf; (void)cap;
    return -1;
#endif
}

/* Layer 1: anti-debug                                                 */

int act_harden_debugger_present(void)
{
#if defined(_WIN32)
    if (IsDebuggerPresent()) {
        return 1;
    }
    BOOL remote = FALSE;
    if (CheckRemoteDebuggerPresent(GetCurrentProcess(), &remote) && remote) {
        return 1;
    }
    return 0;
#elif defined(__linux__) || defined(__ANDROID__)
    /* 1) TracerPid in our own status file. */
    FILE *f = fopen("/proc/self/status", "rb");
    if (f != NULL) {
        char line[256];
        while (fgets(line, sizeof(line), f) != NULL) {
            if (strncmp(line, "TracerPid:", 10) == 0) {
                const int pid = atoi(line + 10);
                fclose(f);
                if (pid != 0) {
                    return 1;
                }
                break;
            }
        }
        fclose(f);
    }
    /* TracerPid alone is the probe on Linux/Android: a second
     * TRACEME-based check would leave THIS process traced by its
     * parent, hanging the application at exit (the parent never
     * wait()s for trace events). Cost: one missed detection family
     * (tracers that hide TracerPid need root anyway, at which point
     * they can defeat any userspace check). */
    return 0;
#elif defined(__APPLE__)
    /* sysctl(kern.proc) exposes the P_TRACED flag via kinfo_proc. */
    struct kinfo_proc info;
    size_t size = sizeof(info);
    int mib[4] = { CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid() };
    memset(&info, 0, sizeof(info));
    if (sysctl(mib, 4, &info, &size, NULL, 0) == 0) {
        return (info.kp_proc.p_flag & P_TRACED) ? 1 : 0;
    }
    return 0;
#else
    return 0; /* platform unsupported: stay silent, never false-positive */
#endif
}

/* Layer 2: self-integrity                                             */

act_status act_harden_compute_digest(const char *path, uint8_t out[64])
{
    /* Digest of the file with EVERY integrity slot's digest region
     * zeroed. Slot = magic(17) || end-magic(18) || digest(64).
     *
     * Reads the whole file (executables are a few MB -- fine for a
     * startup check), zeroes slot regions in memory, hashes once.
     * Simple > streaming-clever: security-critical code must be
     * obviously right.
     */
    if (path == NULL || out == NULL) {
        return ACT_ERR_ARG;
    }

    FILE *f = fopen(path, "rb");
    if (f == NULL) {
        return ACT_ERR_STATE_MISSING;
    }
    if (fseek(f, 0, SEEK_END) != 0) {
        fclose(f);
        return (act_status)ACT_ERR_INTEGRITY;
    }
    const long fsize = ftell(f);
    if (fsize <= 0 || fsize > (64L * 1024 * 1024)) {
        fclose(f);
        return (act_status)ACT_ERR_INTEGRITY;
    }
    rewind(f);

    uint8_t *buf = (uint8_t *)malloc((size_t)fsize);
    if (buf == NULL) {
        fclose(f);
        return (act_status)ACT_ERR_INTEGRITY;
    }
    if (fread(buf, 1, (size_t)fsize, f) != (size_t)fsize) {
        free(buf);
        fclose(f);
        return (act_status)ACT_ERR_INTEGRITY;
    }
    fclose(f);

    const long limit = fsize - ACT_INTEGRITY_SLOT_SIZE;
    for (long i = 0; i <= limit; i++) {
        if (buf[i] == 'A' &&
            memcmp(buf + i, ACT_INTEGRITY_MAGIC, ACT_INTEGRITY_MAGIC_LEN) == 0 &&
            memcmp(buf + i + ACT_INTEGRITY_MAGIC_LEN,
                   ACT_INTEGRITY_END, ACT_INTEGRITY_END_LEN) == 0) {
            memset(buf + i + ACT_INTEGRITY_DIGEST_OFF, 0, 64);
        }
    }

    act_sha512(buf, (size_t)fsize, out);
    act_secure_wipe(buf, (size_t)fsize);
    free(buf);
    return ACT_OK;
}

act_status act_harden_selfcheck(void)
{
    /* Same whole-file approach as act_harden_compute_digest: read once,
     * classify slots in memory, compare against the zeroed-file digest. */
    char path[1024];
    if (self_path(path, sizeof(path)) < 0) {
        return (act_status)ACT_ERR_INTEGRITY; /* cannot resolve: paranoid */
    }

    uint8_t actual[ACT_SHA512_DIGEST_SIZE];
    const act_status st = act_harden_compute_digest(path, actual);
    if (st == ACT_ERR_STATE_MISSING) {
        return ACT_ERR_STATE_MISSING; /* integrity not enabled */
    }
    if (st != ACT_OK) {
        return (act_status)ACT_ERR_INTEGRITY;
    }

    FILE *f = fopen(path, "rb");
    if (f == NULL) {
        return (act_status)ACT_ERR_INTEGRITY;
    }
    fseek(f, 0, SEEK_END);
    const long fsize = ftell(f);
    rewind(f);
    if (fsize <= 0 || fsize > (64L * 1024 * 1024)) {
        fclose(f);
        return (act_status)ACT_ERR_INTEGRITY;
    }
    uint8_t *buf = (uint8_t *)malloc((size_t)fsize);
    if (buf == NULL || fread(buf, 1, (size_t)fsize, f) != (size_t)fsize) {
        free(buf);
        fclose(f);
        return (act_status)ACT_ERR_INTEGRITY;
    }
    fclose(f);

    int valid_slot = 0;
    int fresh_slot = 0;
    int structure_seen = 0;
    const long limit = fsize - ACT_INTEGRITY_SLOT_SIZE;
    for (long i = 0; i <= limit; i++) {
        if (buf[i] == 'A' &&
            memcmp(buf + i, ACT_INTEGRITY_MAGIC, ACT_INTEGRITY_MAGIC_LEN) == 0 &&
            memcmp(buf + i + ACT_INTEGRITY_MAGIC_LEN,
                   ACT_INTEGRITY_END, ACT_INTEGRITY_END_LEN) == 0) {
            structure_seen = 1;
            const uint8_t *stored = buf + i + ACT_INTEGRITY_DIGEST_OFF;
            int is_fresh = 1;
            for (int j = 0; j < 64; j++) {
                if (stored[j] != ACT_INTEGRITY_FRESH) {
                    is_fresh = 0;
                    break;
                }
            }
            if (is_fresh) {
                fresh_slot = 1;
            } else if (act_secure_memcmp(stored, actual, 64) == 0) {
                valid_slot = 1;
                break;
            }
        }
    }
    act_secure_wipe(buf, (size_t)fsize);
    free(buf);

    if (valid_slot) {
        return ACT_OK;
    }
    if (fresh_slot) {
        return ACT_ERR_STATE_MISSING; /* slot present, never patched */
    }
    if (structure_seen) {
        return (act_status)ACT_ERR_INTEGRITY;
    }
    return ACT_ERR_STATE_MISSING;
}


/* Layer 3: redundant verification                                     */

/**
 * Independent re-checks that all PASS for a genuine license and each
 * detect a different failure mode:
 *   leg 1  canonical signature verification
 *   leg 2  NEGATIVE CONTROL: a deliberately corrupted signature must be
 *          rejected -- this exposes a patched-out (always-true) verifier
 *   leg 3  machine binding, re-compared through a hash window
 *   leg 4  structural field sanity (version byte)
 */
static int verify_redundant(const uint8_t payload[ACT_PAYLOAD_SIZE],
                            const uint8_t sig[ACT_SIG_SIZE],
                            const uint8_t pubkey[32],
                            uint32_t product_id,
                            const uint8_t machine_code[16])
{
    /* Leg 1: signature verification in the canonical direction. */
    if (act_ed25519_verify(sig, payload, ACT_PAYLOAD_SIZE, pubkey) != 0) {
        return 0;
    }

    /* Leg 2: negative control. Flip a bit inside the s-part of the
     * signature: the scalar multiplication then lands on a different
     * point and the (untampered) verifier must reject. If this call
     * succeeds, the verifier itself has been patched. */
    {
        uint8_t bad[ACT_SIG_SIZE];
        memcpy(bad, sig, ACT_SIG_SIZE);
        bad[45] ^= 0x08;
        if (act_ed25519_verify(bad, payload, ACT_PAYLOAD_SIZE, pubkey) == 0) {
            act_secure_wipe(bad, sizeof(bad));
            return 0;
        }
        act_secure_wipe(bad, sizeof(bad));
    }

    /* Leg 3: machine binding via an independent hash window. */
    {
        uint8_t mh[ACT_SHA512_DIGEST_SIZE];
        uint8_t pl[ACT_SHA512_DIGEST_SIZE];
        act_sha512(machine_code, 16, mh);
        act_sha512(payload + 5, 16, pl);
        const int eq = act_secure_memcmp(mh, pl, ACT_SHA512_DIGEST_SIZE);
        act_secure_wipe(mh, sizeof(mh));
        act_secure_wipe(pl, sizeof(pl));
        if (eq != 0) {
            return 0;
        }
    }

    /* Leg 4: structural sanity. */
    if (payload[0] != ACT_LICENSE_VERSION) {
        return 0;
    }
    (void)product_id;
    return 1;
}

act_status act_verify_hardened(const char *code,
                               const uint8_t pubkey[32],
                               uint32_t product_id,
                               const uint8_t machine_code[16],
                               int64_t now_unix,
                               int check_debugger,
                               int check_integrity,
                               act_license_info *info)
{
    if (code == NULL || pubkey == NULL || machine_code == NULL) {
        return (act_status)ACT_ERR_ARG;
    }

    /* Gate 1: anti-debug. */
    if (check_debugger && act_harden_debugger_present()) {
        return (act_status)ACT_ERR_DEBUGGER;
    }

    /* Gate 2: executable self-integrity. */
    if (check_integrity) {
        const act_status st = act_harden_selfcheck();
        if (st != ACT_OK && st != ACT_ERR_STATE_MISSING) {
            return (act_status)ACT_ERR_INTEGRITY;
        }
        /* ACT_ERR_STATE_MISSING => binary was never patched; tolerated so
         * developers can run unpatched builds, distributors should ship
         * patched ones. */
    }

    /* Gate 3: the standard pipeline. */
    uint8_t payload[ACT_PAYLOAD_SIZE];
    uint8_t sig[ACT_SIG_SIZE];
    act_status st = act_license_decode(code, payload, sig);
    if (st != ACT_OK) {
        return st;
    }
    st = act_license_verify_payload(payload, sig, pubkey, product_id,
                                    machine_code, now_unix, info);
    if (st != ACT_OK) {
        return st;
    }

    /* Gate 4: independent redundant re-verification. */
    if (!verify_redundant(payload, sig, pubkey, product_id, machine_code)) {
        return (act_status)ACT_ERR_MISMATCH;
    }

    return ACT_OK;
}
