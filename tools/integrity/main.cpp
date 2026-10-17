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
 * @file  main.cpp
 * @brief engrail-integrity -- embed/verify the executable self-integrity
 *        digest (see harden.h for the slot layout).
 *
 * Slot layout: magic(17) || end-magic(18) || digest(64) = 99 bytes.
 * A FRESH slot carries 0xAA x64 in the digest region; a PATCHED slot
 * carries the file digest computed with every slot's digest region
 * zeroed. Multiple candidate structures may appear in a binary (e.g.
 * the magic literals inside libactivation itself); candidates are
 * therefore classified, not just found:
 *
 *   fresh    -- digest region is all 0xAA (a real, unpatched slot)
 *   patched  -- digest region equals the expected zeroed-file digest
 *   other    -- anything else (string-literal adjacency, corruption)
 *
 * Community: https://t.me/Stack_Traces
 */

#include "activation/harden.h"
#include "activation/sha512.h"
#include "activation/version.h"

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <string>

namespace {

enum SlotKind { SLOT_NONE = 0, SLOT_FRESH, SLOT_PATCHED, SLOT_STRUCTURE };

/** Collect up to 8 slot offsets by kind. Returns count of that kind. */
int collect_slots(FILE *f, SlotKind want, const uint8_t *expected,
                  long *offs, int max_offs)
{
    uint8_t win[512];
    size_t fill = 0;
    long file_off = 0;
    size_t n;
    const size_t keep = ACT_INTEGRITY_SLOT_SIZE - 1;
    int found = 0;

    rewind(f);
    while ((n = fread(win + fill, 1, sizeof(win) - fill, f)) > 0) {
        const size_t have = fill + n;
        for (size_t i = 0; i + ACT_INTEGRITY_SLOT_SIZE <= have; i++) {
            if (memcmp(win + i, ACT_INTEGRITY_MAGIC,
                       ACT_INTEGRITY_MAGIC_LEN) != 0 ||
                memcmp(win + i + ACT_INTEGRITY_END_OFF,
                       ACT_INTEGRITY_END, ACT_INTEGRITY_END_LEN) != 0) {
                continue;
            }
            const uint8_t *digest = win + i + ACT_INTEGRITY_DIGEST_OFF;
            int is_fresh = 1;
            for (int j = 0; j < 64; j++) {
                if (digest[j] != ACT_INTEGRITY_FRESH) {
                    is_fresh = 0;
                    break;
                }
            }
            const SlotKind kind = is_fresh
                                      ? SLOT_FRESH
                                      : (expected != NULL &&
                                         act_secure_memcmp(digest, expected,
                                                           64) == 0)
                                            ? SLOT_PATCHED
                                            : SLOT_STRUCTURE;
            if (kind == want && found < max_offs) {
                offs[found++] = file_off + (long)i;
            }
        }
        if (have > keep) {
            memmove(win, win + have - keep, keep);
            fill = keep;
            file_off += (long)(have - keep); /* window base follows the slide */
        } else {
            fill = have;
        }
    }
    return found;
}

/** Classify all slot-shaped structures in @p f. */
SlotKind scan_slots(FILE *f, const uint8_t *expected, long *slot_off)
{
    uint8_t win[512];
    size_t fill = 0;
    long file_off = 0;
    size_t n;
    const size_t keep = ACT_INTEGRITY_SLOT_SIZE - 1;
    SlotKind best = SLOT_NONE;

    rewind(f);
    while ((n = fread(win + fill, 1, sizeof(win) - fill, f)) > 0) {
        const size_t have = fill + n;
        for (size_t i = 0; i + ACT_INTEGRITY_SLOT_SIZE <= have; i++) {
            if (memcmp(win + i, ACT_INTEGRITY_MAGIC,
                       ACT_INTEGRITY_MAGIC_LEN) != 0 ||
                memcmp(win + i + ACT_INTEGRITY_END_OFF,
                       ACT_INTEGRITY_END, ACT_INTEGRITY_END_LEN) != 0) {
                continue;
            }
            const long cand = file_off + (long)i;
            const uint8_t *digest = win + i + ACT_INTEGRITY_DIGEST_OFF;

            int is_fresh = 1;
            for (int j = 0; j < 64; j++) {
                if (digest[j] != ACT_INTEGRITY_FRESH) {
                    is_fresh = 0;
                    break;
                }
            }
            if (is_fresh) {
                if (slot_off != NULL) {
                    *slot_off = cand;
                }
                return SLOT_FRESH; /* exact */
            }
            if (expected != NULL &&
                act_secure_memcmp(digest, expected, 64) == 0) {
                if (slot_off != NULL) {
                    *slot_off = cand;
                }
                return SLOT_PATCHED; /* exact */
            }
            best = SLOT_STRUCTURE; /* shape only */
        }
        if (have > keep) {
            memmove(win, win + have - keep, keep);
            fill = keep;
            file_off += (long)(have - keep); /* window base follows the slide */
        } else {
            fill = have;
        }
    }
    return best;
}

int cmd_patch(int argc, char **argv)
{
    if (argc < 1) {
        std::fprintf(stderr, "usage: engrail-integrity patch <binary>\n");
        return 2;
    }
    const char *path = argv[0];

    FILE *f = fopen(path, "r+b");
    if (f == NULL) {
        std::fprintf(stderr, "error: cannot open %s\n", path);
        return 2;
    }

    /* Collect ALL fresh slots (a binary may legitimately contain the
     * slot macro expanded more than once, e.g. literal + array copies). */
    long offs[8];
    const int nfresh = collect_slots(f, SLOT_FRESH, NULL, offs, 8);
    if (nfresh == 0) {
        long po = -1;
        const SlotKind kind = scan_slots(f, NULL, &po);
        fclose(f);
        if (kind == SLOT_PATCHED) {
            std::printf("already patched (self-consistent)\n");
            return 0;
        }
        std::fprintf(stderr,
                     "error: no fresh integrity slot in %s\n"
                     "       add `ACT_INTEGRITY_SLOT;` (0xAA region) and rebuild\n",
                     path);
        return 2;
    }

    /* R2/BUG-7: patch a TEMP COPY and atomically replace the original.
     * The old in-place flow (zero slots -> hash -> write digest) left a
     * permanently broken binary when interrupted between those steps;
     * with the copy-then-rename approach the original stays valid until
     * the final rename. */
    const std::string tmp = std::string(path) + ".integrity-tmp";
    {
        std::ifstream src(path, std::ios::binary);
        std::ofstream dst(tmp, std::ios::binary | std::ios::trunc);
        if (!src || !dst) {
            fclose(f);
            std::fprintf(stderr, "error: cannot create %s\n", tmp.c_str());
            return 2;
        }
        dst << src.rdbuf();
        if (!dst) {
            fclose(f);
            std::remove(tmp.c_str());
            std::fprintf(stderr, "error: copying failed\n");
            return 2;
        }
    }
    fclose(f);

    FILE *g = fopen(tmp.c_str(), "r+b");
    if (g == NULL) {
        std::remove(tmp.c_str());
        std::fprintf(stderr, "error: cannot reopen %s\n", tmp.c_str());
        return 2;
    }
    /* Zero every fresh slot in the copy, hash the copy, then write the
     * digest into every slot -- identical content keeps them consistent. */
    const uint8_t zeros[64] = { 0 };
    for (int k = 0; k < nfresh; k++) {
        fseek(g, offs[k] + (long)ACT_INTEGRITY_DIGEST_OFF, SEEK_SET);
        if (fwrite(zeros, 1, 64, g) != 64) {
            fclose(g);
            std::remove(tmp.c_str());
            std::fprintf(stderr, "error: zeroing failed\n");
            return 2;
        }
    }
    fclose(g);

    uint8_t digest[ACT_SHA512_DIGEST_SIZE];
    if (act_harden_compute_digest(tmp.c_str(), digest) != ACT_OK) {
        std::remove(tmp.c_str());
        std::fprintf(stderr, "error: hashing failed\n");
        return 2;
    }

    g = fopen(tmp.c_str(), "r+b");
    if (g == NULL) {
        std::remove(tmp.c_str());
        std::fprintf(stderr, "error: cannot reopen %s\n", tmp.c_str());
        return 2;
    }
    for (int k = 0; k < nfresh; k++) {
        if (fseek(g, offs[k] + (long)ACT_INTEGRITY_DIGEST_OFF, SEEK_SET) != 0 ||
            fwrite(digest, 1, 64, g) != 64) {
            fclose(g);
            std::remove(tmp.c_str());
            std::fprintf(stderr, "error: writing digest failed\n");
            return 2;
        }
    }
    fclose(g);

    /* Atomic swap: the original is only replaced once the patched copy
     * is complete. Windows rename() refuses to overwrite, hence the
     * remove() there first (original still on disk until that point). */
    if (std::remove(path) != 0 && errno != ENOENT) {
        std::remove(tmp.c_str());
        std::fprintf(stderr, "error: cannot replace %s\n", path);
        return 2;
    }
    if (std::rename(tmp.c_str(), path) != 0) {
        std::fprintf(stderr,
                     "error: rename failed -- patched copy left at %s\n",
                     tmp.c_str());
        return 2;
    }

    char hex[129];
    for (int i = 0; i < 64; i++) {
        std::snprintf(hex + 2 * i, 3, "%02x", digest[i]);
    }
    std::printf("integrity digest embedded: %s\n", hex);
    std::printf("patch complete -- do NOT re-sign/re-pack after this step\n");
    return 0;
}

int cmd_check(int argc, char **argv)
{
    if (argc < 1) {
        std::fprintf(stderr, "usage: engrail-integrity check <binary>\n");
        return 2;
    }
    const char *path = argv[0];

    uint8_t digest[ACT_SHA512_DIGEST_SIZE];
    if (act_harden_compute_digest(path, digest) != ACT_OK) {
        std::printf("HASH ERROR\n");
        return 1;
    }

    FILE *f = fopen(path, "rb");
    if (f == NULL) {
        std::printf("CANNOT OPEN\n");
        return 1;
    }
    const SlotKind kind = scan_slots(f, digest, NULL);
    fclose(f);

    switch (kind) {
    case SLOT_PATCHED:
        std::printf("INTEGRITY OK\n");
        return 0;
    case SLOT_FRESH:
        std::printf("NOT PATCHED (fresh slot present)\n");
        return 1;
    case SLOT_STRUCTURE:
        std::printf("INTEGRITY FAILED (file was modified)\n");
        return 1;
    default:
        std::printf("NOT PATCHED (no slot)\n");
        return 1;
    }
}

} // namespace

int main(int argc, char **argv)
{
    if (argc < 3) {
        std::fprintf(stderr,
                     "engrail-integrity v%s -- executable self-integrity\n"
                     "usage: engrail-integrity patch <binary>\n"
                     "       engrail-integrity check <binary>\n"
                     "community: %s (%s)\n",
                     ACT_VERSION, ACT_TELEGRAM_CHANNEL, ACT_TELEGRAM_URL);
        return 1;
    }
    const std::string cmd = argv[1];
    if (cmd == "patch") return cmd_patch(argc - 2, argv + 2);
    if (cmd == "check") return cmd_check(argc - 2, argv + 2);
    std::fprintf(stderr, "unknown command: %s\n", cmd.c_str());
    return 1;
}
