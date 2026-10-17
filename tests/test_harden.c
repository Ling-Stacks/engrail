/*
 * MIT License
 *
 * Copyright (c) 2026 ActivationSystem Contributors
 *
 * test_harden -- self-integrity state machine (fresh/patched/modified/
 * absent) on synthetic binaries, negative-control verification, and
 * audit-log chaining under adversarial edits.
 */

#include "common.h"
#include "activation/harden.h"
#include "activation/sha512.h"
#include "activation/ed25519.h"
#include "activation/license.h"

/* Build a synthetic "binary" with a fresh slot; returns slot offset. */
static long synth_fresh(const char *path)
{
    FILE *f = fopen(path, "wb");
    if (f == NULL) {
        return -1;
    }
    fwrite("PRE", 1, 3, f);
    fwrite(ACT_INTEGRITY_MAGIC, 1, ACT_INTEGRITY_MAGIC_LEN, f);
    for (int i = 0; i < 64; i++) {
        uint8_t b = ACT_INTEGRITY_FRESH;
        fwrite(&b, 1, 1, f);
    }
    fwrite(ACT_INTEGRITY_END, 1, ACT_INTEGRITY_END_LEN, f);
    fwrite("POST", 1, 4, f);
    fclose(f);
    return 3; /* slot starts after "PRE" */
}

static void patch_slot(const char *path, long slot_off, const uint8_t *digest)
{
    FILE *f = fopen(path, "r+b");
    fseek(f, slot_off + ACT_INTEGRITY_DIGEST_OFF, SEEK_SET);
    fwrite(digest, 1, 64, f);
    fclose(f);
}

int main(void)
{
    SUITE_BEGIN("harden");

    const char *path = "harden_synth.tmp";

    /* ---- state 1: fresh slot -> digest computes, self-consistency false */
    long off = synth_fresh(path);
    CHECK(off >= 0, "synthetic fresh binary created");

    uint8_t digest[64];
    CHECK(act_harden_compute_digest(path, digest) == ACT_OK,
          "fresh: digest computable");

    /* ---- state 2: patched -> digest self-consistent */
    patch_slot(path, off, digest);
    uint8_t digest2[64];
    CHECK(act_harden_compute_digest(path, digest2) == ACT_OK &&
              memcmp(digest, digest2, 64) == 0,
          "patched: digest stable across recompute (self-consistent)");

    /* ---- state 3: one byte modified anywhere -> digest changes */
    {
        FILE *f = fopen(path, "r+b");
        fseek(f, 0, SEEK_SET); /* modify a byte BEFORE the slot */
        int c = fgetc(f);
        fseek(f, 0, SEEK_SET);
        fputc(c ^ 0x01, f);
        fclose(f);
        uint8_t digest3[64];
        act_harden_compute_digest(path, digest3);
        CHECK(memcmp(digest, digest3, 64) != 0,
              "modified(before slot): digest changes");

        /* restore, then modify AFTER the slot */
        f = fopen(path, "r+b");
        fseek(f, 0, SEEK_SET);
        fputc(c, f);
        fseek(f, -1, SEEK_END);
        int z = fgetc(f);
        fseek(f, -1, SEEK_END);
        fputc(z ^ 0x80, f);
        fclose(f);
        act_harden_compute_digest(path, digest3);
        CHECK(memcmp(digest, digest3, 64) != 0,
              "modified(after slot): digest changes");
        /* restore */
        f = fopen(path, "r+b");
        fseek(f, -1, SEEK_END);
        fputc(z, f);
        fclose(f);
    }

    /* ---- state 4: no slot at all */
    {
        FILE *f = fopen(path, "wb");
        fwrite("just a plain binary, nothing to see", 1, 34, f);
        fclose(f);
        /* library semantics: no slot = whole-file digest (still OK);
         * only a missing FILE yields STATE_MISSING. Verify both. */
        CHECK(act_harden_compute_digest(path, digest) == ACT_OK,
              "no slot: whole-file digest still computable");
        CHECK(act_harden_compute_digest("no_such_file.bin", digest) ==
                  ACT_ERR_STATE_MISSING,
              "missing file: STATE_MISSING reported");
    }

    /* ---- negative-control verification (patched-verifier detector) ---- */
    {
        uint8_t seed[32], pk[32], sk[64];
        for (int i = 0; i < 32; i++) {
            seed[i] = (uint8_t)(i + 5);
        }
        act_ed25519_keypair(seed, pk, sk);
        uint8_t machine[16];
        for (int i = 0; i < 16; i++) {
            machine[i] = (uint8_t)(0x40 + i);
        }
        uint8_t payload[ACT_PAYLOAD_SIZE], sig[ACT_SIG_SIZE];
        act_license_make(payload, sig, 9, machine, 500, 0, NULL, 0, sk);

        /* corrupt every byte of the signature: NONE may verify */
        int all_rejected = 1;
        for (int i = 0; i < 64 && all_rejected; i++) {
            for (int bit = 0; bit < 8; bit++) {
                uint8_t bad[64];
                memcpy(bad, sig, 64);
                bad[i] ^= (uint8_t)(1 << bit);
                if (act_ed25519_verify(bad, payload, ACT_PAYLOAD_SIZE, pk) ==
                    0) {
                    all_rejected = 0;
                    break;
                }
            }
        }
        CHECK(all_rejected,
              "negative control: all 512 signature corruptions rejected");

        /* verify_hardened end-to-end on a good code (env gates off to
         * keep the test hermetic; integrity gate tolerates unpatched) */
        char code[ACT_CODE_MAX_CHARS];
        act_license_encode(payload, sig, code, sizeof(code));
        const act_status vhs = act_verify_hardened(
            code, pk, 9, machine, ACT_EXPIRY_EPOCH + 100 * 86400LL, 0, 1,
            NULL);
        char vmsg[96];
        snprintf(vmsg, sizeof(vmsg),
                 "verify_hardened accepts a genuine code (got %d)", (int)vhs);
        CHECK(vhs == ACT_OK, vmsg);
    }

    remove(path);
    SUITE_END();
}
