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
 * @file  random.c
 * @brief OS-backed CSPRNG. See random.h for documentation.
 */

/*
 * Feature-macro prelude (must precede every system include): the code
 * below uses POSIX/glibc extensions (syscall, readlink family in other
 * units). Strict `-std=c99` defines __STRICT_ANSI__ and hides those
 * declarations on glibc; each platform needs its own unlock macro.
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

#include "activation/random.h"

#include <stdio.h>
#include <stdlib.h>

#if defined(_WIN32)
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  ifndef NOMINMAX
#    define NOMINMAX
#  endif
#  include <windows.h>
#  include <bcrypt.h>
   /* MinGW-w64 does not ship NT_SUCCESS (MSVC SDK only). */
#  ifndef NT_SUCCESS
#    define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#  endif
#else
#  include <unistd.h>
#  include <fcntl.h>
#  include <errno.h>
#endif

void act_random_bytes(uint8_t *buf, size_t len)
{
    if (buf == NULL || len == 0) {
        return;
    }

#if defined(_WIN32)
    /* ProcessPrng is the modern minimal-surface API (Win10+);
     * BCryptGenRandom covers older Windows. Both pull from the OS
     * entropy pool. Both are resolved dynamically so that NO import
     * library (advapi32/bcrypt) is ever needed at link time -- the
     * amalgamation and every binding link cleanly on MinGW/MSVC as-is.
     */
    {
        BOOL ok = FALSE;
        HMODULE adv = GetModuleHandleW(L"advapi32.dll");
        typedef LONG (WINAPI *ProcessPrngFn)(PBYTE, SIZE_T);
        ProcessPrngFn prng =
            (ProcessPrngFn)(void *)GetProcAddress(adv, "ProcessPrng");
        if (prng != NULL) {
            ok = (prng(buf, len) == 0);
        }
        if (!ok) {
            HMODULE bc = GetModuleHandleW(L"bcrypt.dll");
            if (bc == NULL) {
                bc = LoadLibraryW(L"bcrypt.dll");
            }
            if (bc != NULL) {
                typedef LONG (WINAPI *BCGRFn)(PVOID, PUCHAR, ULONG, ULONG);
                BCGRFn bcgr =
                    (BCGRFn)(void *)GetProcAddress(bc, "BCryptGenRandom");
                if (bcgr != NULL) {
                    ok = NT_SUCCESS(bcgr(NULL, (PUCHAR)buf, (ULONG)len,
                                         BCRYPT_USE_SYSTEM_PREFERRED_RNG));
                }
            }
        }
        if (!ok) {
            abort(); /* fail closed */
        }
    }
    /* R1: reference the label on Windows too. Every goto above lives
     * in the POSIX branch, so without this one the label would be
     * unreferenced here and -Werror=unused-label breaks MinGW builds
     * (fall-through would work at runtime; this is for the compiler). */
    goto health_check;
#else  /* POSIX */
    /* 1) getrandom(2) syscall first: no filesystem dependency, no fd
     *    exhaustion, works in chroot/sandbox/seccomp contexts that
     *    block /dev. EINTR/short reads are retried; only EFAULT (a bug
     *    in our caller contract) or ENOSYS falls through. */
#  if defined(__linux__) || defined(__ANDROID__)
#    include <sys/syscall.h>
#    if defined(SYS_getrandom)
    {
        size_t off = 0;
        while (off < len) {
            const long r = syscall(SYS_getrandom, buf + off, len - off, 0);
            if (r < 0) {
                if (errno == EINTR) {
                    continue; /* signal before any byte: retry */
                }
                break;       /* ENOSYS / blocked: fall to /dev/urandom */
            }
            if (r == 0) {
                break;       /* should not happen; treat as failure */
            }
            off += (size_t)r;
        }
        if (off == len) {
            goto health_check;
        }
    }
#    endif
#  endif

    /* 2) /dev/urandom fallback: the OS CSPRNG on every mainstream POSIX
     *    platform; blocks only until the pool is initialised at boot. */
    {
        int fd;
        size_t off = 0;
        do {
            fd = open("/dev/urandom", O_RDONLY);
        } while (fd < 0 && errno == EINTR);
        if (fd >= 0) {
            while (off < len) {
                const ssize_t r = read(fd, buf + off, len - off);
                if (r < 0) {
                    if (errno == EINTR) {
                        continue;
                    }
                    break;
                }
                if (r == 0) {
                    break;
                }
                off += (size_t)r;
            }
            close(fd);
            if (off == len) {
                goto health_check;
            }
        }
    }
    abort(); /* fail closed -- never fall back to weak randomness */
#endif

health_check:
    /* Degenerate-output detection: an all-zero or all-0xFF buffer means
     * the source is broken (some emulators / fuzzers stub getrandom);
     * treating it as success would hand every key in the system to an
     * attacker. Reject and fail closed. Common to every platform. */
    {
        uint8_t acc = 0;
        size_t i;
        for (i = 0; i < len; i++) {
            acc |= buf[i] ^ 0xFF; /* nonzero unless all-0xFF */
        }
        if (acc == 0) {
            abort(); /* all 0xFF: broken source */
        }
        acc = 0;
        for (i = 0; i < len; i++) {
            acc |= buf[i];        /* nonzero unless all-zero */
        }
        if (acc == 0) {
            abort(); /* all zero: broken source */
        }
    }
}
