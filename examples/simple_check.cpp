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
 * @file  simple_check.cpp
 * @brief Minimal end-to-end demonstration of the activation SDK.
 *
 * Usage:
 *   simple_check                 print this machine's code + saved status
 *   simple_check <CODE>          activate with CODE, persist state
 *
 * Compile-time configuration:
 *   -DACT_PUBKEY_HEX='"aabb..."'   vendor public key (from keygen)
 *   -DACT_PRODUCT_ID=1             product identifier
 *   -DACT_STATE_PATH='"app.act"'   where the state file is stored
 */

#include "activation/activation.hpp"
#include "activation/harden.h"

#include <cstdio>
#include <string>

/* Reserve the self-integrity slot so `engrail-integrity patch` can
 * embed a digest of the final binary (anti-tamper, see harden.h). */
ACT_INTEGRITY_SLOT;

#ifndef ACT_PUBKEY_HEX
#  define ACT_PUBKEY_HEX "0000000000000000000000000000000000000000000000000000000000000000"
#endif
#ifndef ACT_DSALT_HEX
#  define ACT_DSALT_HEX "0000000000000000000000000000000000000000000000000000000000000000"
#endif
#ifndef ACT_PRODUCT_ID
#  define ACT_PRODUCT_ID 1
#endif
#ifndef ACT_STATE_PATH
#  define ACT_STATE_PATH "app.act"
#endif

namespace {

bool hex_to_bytes(const std::string &hex, uint8_t *out, size_t outlen)
{
    if (hex.size() != outlen * 2) {
        return false;
    }
    for (size_t i = 0; i < outlen; i++) {
        unsigned v;
        if (sscanf(hex.c_str() + 2 * i, "%2x", &v) != 1) {
            return false;
        }
        out[i] = (uint8_t)v;
    }
    return true;
}

} // namespace

int main(int argc, char **argv)
{
    uint8_t pubkey[act::kPubkeySize];
    uint8_t dsalt[act::kDsaltSize];
    if (!hex_to_bytes(ACT_PUBKEY_HEX, pubkey, sizeof(pubkey)) ||
        !hex_to_bytes(ACT_DSALT_HEX, dsalt, sizeof(dsalt))) {
        std::fprintf(stderr,
                     "configuration error: ACT_PUBKEY_HEX / ACT_DSALT_HEX "
                     "must be 64 hex chars each\n");
        return 2;
    }

    const act::Verifier verifier(pubkey, dsalt, ACT_PRODUCT_ID);
    const std::string mc = verifier.machine_code();

    std::printf("product id  : %u\n", ACT_PRODUCT_ID);
    std::printf("machine code: %s\n\n", mc.c_str());

    if (argc > 1) {
        const act::Status st = verifier.activate(argv[1], ACT_STATE_PATH);
        if (st == act::Status::Ok) {
            std::printf("activation successful, state saved to %s\n",
                        ACT_STATE_PATH);
            return 0;
        }
        std::fprintf(stderr, "activation failed: %s\n",
                     act::status_string(st));
        return 1;
    }

    const act::Status st = verifier.verify_saved(ACT_STATE_PATH);
    if (st == act::Status::Ok) {
        std::printf("license ACTIVE (state verified)\n");
        return 0;
    }
    std::printf("license INACTIVE: %s\n", act::status_string(st));
    return 1;
}
