/*
 * MIT License
 *
 * Copyright (c) 2026 ActivationSystem Contributors
 *
 * crack_me -- a fully hardened reverse-engineering challenge built on
 * Engrail. Five gates, each a real defense layer of the
 * library (see ADVERSARIAL.md for the full model):
 *
 *   Gate 1  activation code validation      (Ed25519, cannot be forged)
 *   Gate 2  machine binding                 (HKDF fingerprint cascade)
 *   Gate 3  anti-debug probe                (TracerPid / ptrace)
 *   Gate 4  executable self-integrity       (patched SHA-512 slot)
 *   Gate 5  negative-control verification   (a known-bad signature
 *            MUST be rejected -- catches patched verifiers)
 *
 * Success prints the FLAG (derived from your machine code, so every
 * machine has its own -- write-ups welcome at t.me/Stack_Traces).
 *
 * Build & patch (order matters; integrity is last):
 *   ./configure && make
 *   cc -Iinclude -DACT_CRACKME_PUBKEY=... examples/crack_me.c \
 *      build/libactivation.a -o build/crack_me
 *   ./build/engrail-integrity patch build/crack_me
 *
 * Community: https://t.me/Stack_Traces
 */

#include "activation/ed25519.h"
#include "activation/fingerprint.h"
#include "activation/license.h"
#include "activation/sha512.h"
#include "activation/harden.h"
#include "activation/sm2.h"

#include <stdio.h>
#include <string.h>
#include <time.h>

/* Demo deployment -- replace with yours when deploying the challenge. */
#ifndef ACT_CRACKME_PUBKEY_HEX
#  define ACT_CRACKME_PUBKEY_HEX \
       "3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29"
#endif
#ifndef ACT_CRACKME_DSALT_HEX
#  define ACT_CRACKME_DSALT_HEX \
       "00000000000000000000000000000000" \
       "00000000000000000000000000000000"
#endif
#define ACT_CRACKME_PRODUCT 1

ACT_INTEGRITY_SLOT; /* executable self-integrity slot (Gate 4) */

static void print_flag(const uint8_t machine[16])
{
    /* FLAG = machine-bound: no license, no flag -- and no two machines
     * share one. (Demo derivation; swap in your own for real events.)
     * NB: SHA-512 writes 64 bytes; the Ed25519 seed uses the first 32. */
    uint8_t seed[ACT_SHA512_DIGEST_SIZE];
    act_sha512(machine, 16, seed);
    uint8_t sk[64], pk[32];
    act_ed25519_keypair(seed, pk, sk);
    char flag[65];
    static const char hexd[] = "0123456789ABCDEF";
    for (int i = 0; i < 32; i++) {
        flag[2 * i] = hexd[sk[32 + i] >> 4]; /* public half of the key */
        flag[2 * i + 1] = hexd[sk[32 + i] & 15];
    }
    flag[64] = '\0';
    printf("\n  FLAG{act_v_%s}\n\n", flag);
    (void)pk;
}

static int hex2bin(const char *h, uint8_t *o, size_t n)
{
    if (strlen(h) != n * 2) return -1;
    for (size_t i = 0; i < n; i++) {
        unsigned v;
        if (sscanf(h + 2 * i, "%2x", &v) != 1) return -1;
        o[i] = (uint8_t)v;
    }
    return 0;
}

int main(int argc, char **argv)
{
    uint8_t pubkey[32], dsalt[32];
    if (hex2bin(ACT_CRACKME_PUBKEY_HEX, pubkey, 32) != 0 ||
        hex2bin(ACT_CRACKME_DSALT_HEX, dsalt, 32) != 0) {
        fprintf(stderr, "config error\n");
        return 2;
    }

    printf("== Engrail crack-me ==\n");
    printf("   five gates; write-ups -> t.me/Stack_Traces\n\n");

    /* Gate 3: anti-debug (checked FIRST so debuggers never see the rest) */
    printf("[gate 3] anti-debug probe ... ");
    fflush(stdout);
    if (act_harden_debugger_present()) {
        printf("TRACED\n");
        return 1;
    }
    printf("clean\n");

    /* Gate 4: executable self-integrity */
    printf("[gate 4] self-integrity .... ");
    fflush(stdout);
    {
        const act_status st = act_harden_selfcheck();
        if (st == ACT_OK) {
            printf("patched-binary OK\n");
        } else if (st == ACT_ERR_STATE_MISSING) {
            printf("not patched (dev build) -- allowed\n");
        } else {
            printf("BINARY MODIFIED\n");
            return 1;
        }
    }

    /* Machine code (Gate 2 binding target) */
    {
        uint8_t machine[16];
        act_fingerprint(pubkey, dsalt, ACT_CRACKME_PRODUCT, NULL, 0, machine);
        char mc[ACT_MACHINE_CODE_STR_SIZE];
        act_fp_to_string(machine, mc);
        printf("[gate 2] machine .......... %s\n", mc);

        /* Gate 1 + 5: hardened verification of the supplied code */
        if (argc > 1) {
            printf("[gate 1] license check .... ");
            fflush(stdout);
            uint8_t payload[ACT_PAYLOAD_SIZE], sig[ACT_SIG_SIZE];
            act_status st = act_license_decode(argv[1], payload, sig);
            if (st != ACT_OK) {
                printf("malformed\n");
                return 1;
            }
            st = act_license_verify_payload(payload, sig, pubkey,
                                            ACT_CRACKME_PRODUCT, machine,
                                            (int64_t)time(NULL), NULL);
            if (st != ACT_OK) {
                printf("rejected (%d)\n", st);
                return 1;
            }
            printf("valid\n");

            printf("[gate 5] negative control . ");
            fflush(stdout);
            uint8_t bad[ACT_SIG_SIZE];
            memcpy(bad, sig, ACT_SIG_SIZE);
            bad[45] ^= 0x08;
            if (act_ed25519_verify(bad, payload, ACT_PAYLOAD_SIZE, pubkey) == 0) {
                /* verifier accepted a corrupted signature => patched */
                printf("VERIFIER TAMPERED\n");
                return 1;
            }
            printf("verifier honest\n");

            print_flag(machine);
            return 0;
        }
        printf("\nno license supplied: run `%s <activation-code>`\n"
               "ask for a code at t.me/Stack_Traces with your machine code\n",
               argv[0]);
        return 0;
    }
}
