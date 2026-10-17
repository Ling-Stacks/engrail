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
 * @file  activation.hpp
 * @brief Modern C++17 wrapper around the C core.
 *
 * Typical vendor-side flow
 *   1. `engrail-keygen keygen` once: creates the vendor key pair.
 *   2. Embed the *public* key in your application.
 *   3. `engrail-keygen issue ...` to mint codes for customers.
 *
 * Application-side flow
 * @code
 *   static const uint8_t PUBKEY[32] = { ... from keygen ... };
 *   act::Verifier verifier(PUBKEY, 0x00000001);
 *
 *   switch (verifier.activate(user_input_code, "app.act")) {
 *       case act::Status::Ok:              // fully activated
 *       case act::Status::MachineMismatch: // code for another box
 *       case act::Status::Expired:         // too late
 *       default:                           // invalid / forged
 *   }
 *   // ... later, at every startup:
 *   if (verifier.verify_saved("app.act") == act::Status::Ok) { ... }
 * @endcode
 */

#ifndef ACTIVATION_ACTIVATION_HPP
#define ACTIVATION_ACTIVATION_HPP

#include "activation/license.h"
#include "activation/fingerprint.h"
#include "activation/state.h"
#include "activation/revoke.h"
#include "activation/harden.h"
#include "activation/token.h"
#include "activation/sm2.h"
#include "activation/keyfile.h"
#include "activation/kdf.h"
#include "activation/chacha20.h"
#include "activation/ed25519.h"

#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace act {

/** Byte sizes of the crypto material. */
inline constexpr size_t kPubkeySize  = ACT_ED25519_PUBKEY_SIZE;
inline constexpr size_t kDsaltSize   = ACT_DSALT_SIZE;
inline constexpr size_t kPrivkeySize = ACT_ED25519_PRIVKEY_SIZE;
inline constexpr size_t kMachineCodeSize = ACT_MACHINE_CODE_SIZE;

/**
 * @brief Verification outcomes. Mirrors ::act_status 1:1.
 */
enum class Status {
    Ok = ACT_OK,
    BadArgument = ACT_ERR_ARG,
    BadFormat = ACT_ERR_FORMAT,
    BadVersion = ACT_ERR_VERSION,
    ProductMismatch = ACT_ERR_PRODUCT,
    BadSignature = ACT_ERR_SIGNATURE,
    MachineMismatch = ACT_ERR_MACHINE,
    Expired = ACT_ERR_EXPIRED,
    StateMissing = ACT_ERR_STATE_MISSING,
    StateIoError = ACT_ERR_STATE_IO,
    StateCorrupt = ACT_ERR_STATE_CORRUPT,
    Revoked = ACT_ERR_REVOKED,
    DebuggerDetected = ACT_ERR_DEBUGGER,
    IntegrityFailure = ACT_ERR_INTEGRITY,
    VerificationMismatch = ACT_ERR_MISMATCH,
    EntropyFailure = ACT_ERR_ENTROPY
};

/** @return short human-readable explanation of a status. */
const char *status_string(Status s) noexcept;

/** Decoded license metadata. */
struct LicenseInfo {
    uint32_t product_id = 0;                        /**< product identifier */
    std::array<uint8_t, kMachineCodeSize> machine_code{}; /**< bound device */
    uint32_t expiry_days = 0;                       /**< days since anchor  */
    bool perpetual = false;                         /**< never expires      */
    bool trial = false;                             /**< trial license      */
    std::array<uint8_t, 8> serial{};                /**< revocation id      */
    uint16_t features = 0;                          /**< product tier mask  */

    /** @return expiry as a Unix timestamp (anchor when perpetual). */
    int64_t expiry_unix() const noexcept;

    /** @return whole days remaining; INT64_MAX when perpetual, 0 when
     *          expired (so `days > 0` is valid for every license kind). */
    int64_t days_remaining(int64_t now_unix) const noexcept;

    /** @brief Feature-tier query (bit 0..15 of the feature mask). */
    bool has_feature(int bit) const noexcept;

    /** @return true when the ACT_FLAG_TRIAL bit is set. */
    bool is_trial() const noexcept;
};

/**
 * @brief License verifier bound to one product public key.
 *
 * The object is stateless apart from the immutable key material, so a
 * single instance can be shared freely across threads.
 */
class Verifier {
public:
    /**
     * @param pubkey     vendor Ed25519 public key (32 bytes).
     * @param dsalt      deployment salt (32 bytes) -- from
     *                   `engrail-keygen export-pub`; unique per
     *                   deployment, feeds every derived key.
     * @param product_id your product identifier (must match at issuance).
     */
    Verifier(const uint8_t pubkey[kPubkeySize],
             const uint8_t dsalt[kDsaltSize],
             uint32_t product_id) noexcept;

    /** @return this machine's 16-byte fingerprint. */
    std::array<uint8_t, kMachineCodeSize>
    fingerprint(const std::vector<uint8_t> &salt = {}) const;

    /** @return fingerprint as "XXXXXXXX-XXXXXXXX" (uppercase hex). */
    std::string machine_code(const std::vector<uint8_t> &salt = {}) const;

    /**
     * @brief Verify a user-entered activation code and persist the state.
     *
     * @param code       user input (formatting is forgiven).
     * @param state_path where to store the activation state file.
     * @param salt       optional device-entropy salt (same value must be
     *                   used for every later verify_saved() call).
     * @return Status::Ok on success; the state file is written only when
     *         the code fully verified.
     */
    Status activate(const std::string &code,
                    const std::string &state_path,
                    const std::vector<uint8_t> &salt = {}) const;

    /**
     * @brief Re-verify the previously saved activation state.
     *
     * Detects tampering (signature), cloning (machine binding) and aging
     * (expiry) on every call -- call it on every startup.
     */
    Status verify_saved(const std::string &state_path,
                        const std::vector<uint8_t> &salt = {}) const;

    /**
     * @brief verify_saved + vendor-signed revocation list check.
     *
     * @param state_path      saved activation state file.
     * @param revocation_path revocation list distributed with updates.
     * @param salt            device salt (same as activate()).
     * @return Status::Revoked when the license serial is on the list.
     */
    Status verify_saved(const std::string &state_path,
                        const std::string &revocation_path,
                        const std::vector<uint8_t> &salt = {}) const;

    /**
     * @brief Hardened verification: redundant re-verification plus
     *        optional anti-debug and executable self-integrity gates.
     *
     * @see act_verify_hardened
     */
    Status verify_hardened(const std::string &code,
                           const std::vector<uint8_t> &salt = {},
                           bool check_debugger = true,
                           bool check_integrity = true) const;

    /** @brief Verify a code without persisting anything. */
    Status check_code(const std::string &code,
                      const std::vector<uint8_t> &salt = {}) const;

    /** @brief Verify a code and, on success, return its metadata. */
    Status check_code(const std::string &code, LicenseInfo &info_out,
                      const std::vector<uint8_t> &salt = {}) const;

    /** @return a copy of the deployment salt. */
    std::array<uint8_t, kDsaltSize> dsalt() const noexcept;

    /**
     * @brief Offline authentication: verify a signed token produced by
     *        the vendor (act::vendor::make_token / engrail-keygen
     *        token sign). Optional payload output.
     */
    Status verify_token(const std::string &token, int64_t now_unix,
                        std::string &payload_out) const;

    /**
     * @brief Offline challenge-response authentication (all offline):
     *   1. app:     ch = challenge()            (nonce + machine + time)
     *   2. vendor:  resp = respond(ch)           (Ed25519 over ch)
     *   3. app:     verify_challenge(ch, resp)   (local, no network)
     */
    std::string challenge(int64_t now_unix = 0) const;
    Status verify_challenge(const std::string &challenge,
                            const std::string &response,
                            int64_t now_unix = 0,
                            int64_t max_age = 0) const;

    /** @return the product id this verifier is bound to. */
    uint32_t product_id() const noexcept { return product_id_; }

    /** @return copy of the embedded public key. */
    std::array<uint8_t, kPubkeySize> pubkey() const noexcept;

private:
    std::array<uint8_t, kPubkeySize> pubkey_{};
    std::array<uint8_t, kDsaltSize> dsalt_{};
    uint32_t product_id_;
};

/**
 * @brief Vendor-side issuance helpers (link with the core; never ship
 *        these code paths inside your end-user application).
 */
namespace vendor {

/** Ed25519 key pair. */
struct KeyPair {
    std::array<uint8_t, 32> seed;      /**< secret seed -- keep offline!  */
    std::array<uint8_t, kPubkeySize> pubkey;
    std::array<uint8_t, kPrivkeySize> privkey; /**< seed || pubkey */
};

/** @brief Generate a fresh random key pair (CSPRNG-backed). */
KeyPair generate_keypair();

/** @brief Build+sign a license; @see act_license_make. */
void make_license(const std::array<uint8_t, kPrivkeySize> &privkey,
                  uint32_t product_id,
                  const std::array<uint8_t, kMachineCodeSize> &machine_code,
                  uint32_t expiry_days, bool perpetual,
                  std::string &code_out);

/** @brief Sign an arbitrary offline auth token. @see act_token_create. */
Status make_token(const std::array<uint8_t, kPrivkeySize> &privkey,
                  uint32_t product_id, const std::string &payload,
                  uint32_t ttl_seconds, std::string &token_out);

/** @brief Sign a challenge. @see act_challenge_respond. */
Status respond_challenge(const std::array<uint8_t, kPrivkeySize> &privkey,
                         const std::string &challenge,
                         std::string &response_out);

} // namespace vendor

/* SM2 (GB/T 32918) thin C++ wrappers                                  */

namespace sm2 {

using ByteVec = std::vector<uint8_t>;

/** @brief Generate a key pair; empty seed => CSPRNG. */
struct KeyPair {
    std::array<uint8_t, 32> priv{};
    std::array<uint8_t, 64> pub{};
};
KeyPair generate_keypair();

/** @brief SM2 sign; returns empty string on failure. */
std::string sign(const std::array<uint8_t, 32> &priv,
                 const void *msg, size_t len,
                 const char *id = nullptr);

/** @brief SM2 verify. */
Status verify(const std::string &sig_hex, const std::array<uint8_t, 64> &pub,
              const void *msg, size_t len, const char *id = nullptr);

/** @brief SM2 encrypt -> hex string (C1C3C2). */
std::string encrypt(const std::array<uint8_t, 64> &pub,
                    const void *msg, size_t len);

/** @brief SM2 decrypt from hex; empty string on failure. */
std::string decrypt(const std::array<uint8_t, 32> &priv,
                    const std::string &ct_hex);

} // namespace sm2

} // namespace act

#endif /* ACTIVATION_ACTIVATION_HPP */
