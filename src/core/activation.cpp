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
 * @file  activation.cpp
 * @brief Implementation of the C++17 wrapper. See activation.hpp.
 */

#include "activation/activation.hpp"
#include "activation/ed25519.h"
#include "activation/random.h"

#include <ctime>

namespace act {

const char *status_string(Status s) noexcept
{
    switch (s) {
    case Status::Ok:             return "ok";
    case Status::BadArgument:    return "bad argument";
    case Status::BadFormat:      return "malformed activation code";
    case Status::BadVersion:     return "unsupported license version";
    case Status::ProductMismatch:return "license issued for another product";
    case Status::BadSignature:   return "signature check failed (forged or tampered)";
    case Status::MachineMismatch:return "license bound to another machine";
    case Status::Expired:        return "license expired";
    case Status::StateMissing:   return "no activation state found";
    case Status::StateIoError:   return "activation state i/o error";
    case Status::StateCorrupt:   return "activation state corrupt";
    case Status::Revoked:        return "license revoked";
    case Status::DebuggerDetected: return "debugger detected";
    case Status::IntegrityFailure: return "executable integrity failure";
    case Status::VerificationMismatch: return "redundant verification mismatch";
    case Status::EntropyFailure:  return "system CSPRNG unavailable";
    }
    return "unknown status";
}

int64_t LicenseInfo::expiry_unix() const noexcept
{
    return perpetual ? 0 : act_expiry_to_unix(expiry_days);
}

int64_t LicenseInfo::days_remaining(int64_t now_unix) const noexcept
{
    if (perpetual) {
        return INT64_MAX; /* unlimited: any `days > 0` test stays true */
    }
    const int64_t exp = act_expiry_to_unix(expiry_days);
    if (now_unix >= exp) {
        return 0;
    }
    return (exp - now_unix + 86399) / 86400;
}

bool LicenseInfo::has_feature(int bit) const noexcept
{
    return bit >= 0 && bit <= 15 && ((features >> bit) & 1) != 0;
}

bool LicenseInfo::is_trial() const noexcept
{
    return trial;
}

/* Verifier                                                            */

Verifier::Verifier(const uint8_t pubkey[kPubkeySize],
                   const uint8_t dsalt[kDsaltSize],
                   uint32_t product_id) noexcept
    : product_id_(product_id)
{
    for (size_t i = 0; i < kPubkeySize; i++) {
        pubkey_[i] = pubkey[i];
    }
    for (size_t i = 0; i < kDsaltSize; i++) {
        dsalt_[i] = dsalt[i];
    }
}

std::array<uint8_t, kMachineCodeSize>
Verifier::fingerprint(const std::vector<uint8_t> &salt) const
{
    std::array<uint8_t, kMachineCodeSize> out{};
    const uint8_t *salt_ptr =
        salt.empty() ? nullptr : salt.data();
    act_fingerprint(pubkey_.data(), dsalt_.data(), product_id_,
                    salt_ptr, salt.size(), out.data());
    return out;
}

std::array<uint8_t, kDsaltSize> Verifier::dsalt() const noexcept
{
    return dsalt_;
}

Status Verifier::verify_token(const std::string &token, int64_t now_unix,
                              std::string &payload_out) const
{
    std::vector<uint8_t> buf(ACT_TOKEN_MAX_PAYLOAD);
    size_t len = 0;
    const act_status st = act_token_verify(token.c_str(), pubkey_.data(),
                                           product_id_, now_unix,
                                           buf.data(), buf.size(), &len,
                                           nullptr);
    if (st == ACT_OK) {
        payload_out.assign(buf.begin(), buf.begin() + (long)len);
    }
    return (Status)st;
}

std::string Verifier::challenge(int64_t now_unix) const
{
    const auto fp = fingerprint();
    char out[96];
    if (now_unix == 0) {
        now_unix = (int64_t)time(nullptr);
    }
    if (act_challenge_create(fp.data(), product_id_, now_unix, out,
                             sizeof(out)) != ACT_OK) {
        return std::string();
    }
    return std::string(out);
}

Status Verifier::verify_challenge(const std::string &challenge,
                                  const std::string &response,
                                  int64_t now_unix, int64_t max_age) const
{
    const auto fp = fingerprint();
    if (now_unix == 0) {
        now_unix = (int64_t)time(nullptr);
    }
    return (Status)act_challenge_verify(challenge.c_str(), response.c_str(),
                                        pubkey_.data(), product_id_,
                                        fp.data(), now_unix, max_age);
}

std::string Verifier::machine_code(const std::vector<uint8_t> &salt) const
{
    char buf[ACT_MACHINE_CODE_STR_SIZE];
    const auto fp = fingerprint(salt);
    act_fp_to_string(fp.data(), buf);
    return std::string(buf);
}

Status Verifier::activate(const std::string &code,
                          const std::string &state_path,
                          const std::vector<uint8_t> &salt) const
{
    const auto fp = fingerprint(salt);
    act_license_info info{};
    const act_status st = act_license_verify(
        code.c_str(), pubkey_.data(), product_id_, fp.data(),
        (int64_t)time(nullptr), &info);
    if (st != ACT_OK) {
        return (Status)st;
    }
    uint8_t payload[ACT_PAYLOAD_SIZE];
    uint8_t sig[ACT_SIG_SIZE];
    /* Re-decode: payload bytes are needed verbatim for the state file. */
    if (act_license_decode(code.c_str(), payload, sig) != ACT_OK) {
        return Status::BadFormat; /* unreachable: verify() decoded fine */
    }
    return (Status)act_state_save(state_path.c_str(), payload, sig);
}

Status Verifier::verify_saved(const std::string &state_path,
                              const std::vector<uint8_t> &salt) const
{
    const auto fp = fingerprint(salt);
    return (Status)act_state_check(state_path.c_str(), pubkey_.data(),
                                   product_id_, fp.data(),
                                   (int64_t)time(nullptr), nullptr);
}

Status Verifier::verify_saved(const std::string &state_path,
                              const std::string &revocation_path,
                              const std::vector<uint8_t> &salt) const
{
    const auto fp = fingerprint(salt);
    act_license_info info{};
    const act_status st = act_state_check(state_path.c_str(), pubkey_.data(),
                                          product_id_, fp.data(),
                                          (int64_t)time(nullptr), &info);
    if (st != ACT_OK) {
        return (Status)st;
    }
    const int rv = act_revoke_check(revocation_path.c_str(), pubkey_.data(),
                                    &info);
    if (rv == 1) {
        return Status::Revoked;
    }
    if (rv == (int)ACT_ERR_STATE_MISSING) {
        return Status::Ok; /* no list deployed => nothing revoked */
    }
    if (rv != 0) {
        return (Status)rv; /* corrupt/unsigned list: fail closed */
    }
    return Status::Ok;
}

Status Verifier::verify_hardened(const std::string &code,
                                 const std::vector<uint8_t> &salt,
                                 bool check_debugger,
                                 bool check_integrity) const
{
    const auto fp = fingerprint(salt);
    return (Status)act_verify_hardened(code.c_str(), pubkey_.data(),
                                       product_id_, fp.data(),
                                       (int64_t)time(nullptr),
                                       check_debugger ? 1 : 0,
                                       check_integrity ? 1 : 0,
                                       nullptr);
}

Status Verifier::check_code(const std::string &code,
                            const std::vector<uint8_t> &salt) const
{
    const auto fp = fingerprint(salt);
    return (Status)act_license_verify(
        code.c_str(), pubkey_.data(), product_id_, fp.data(),
        (int64_t)time(nullptr), nullptr);
}

Status Verifier::check_code(const std::string &code, LicenseInfo &info_out,
                            const std::vector<uint8_t> &salt) const
{
    const auto fp = fingerprint(salt);
    act_license_info info{};
    const act_status st = act_license_verify(
        code.c_str(), pubkey_.data(), product_id_, fp.data(),
        (int64_t)time(nullptr), &info);
    if (st == ACT_OK) {
        info_out.product_id = info.product_id;
        for (size_t i = 0; i < kMachineCodeSize; i++) {
            info_out.machine_code[i] = info.machine_code[i];
        }
        info_out.expiry_days = info.expiry_days;
        info_out.perpetual = info.perpetual != 0;
        info_out.trial = info.trial != 0;
        for (size_t i = 0; i < 8; i++) {
            info_out.serial[i] = info.serial[i];
        }
        info_out.features = info.features;
    }
    return (Status)st;
}

std::array<uint8_t, kPubkeySize> Verifier::pubkey() const noexcept
{
    return pubkey_;
}

/* Vendor helpers                                                      */

namespace vendor {

KeyPair generate_keypair()
{
    KeyPair kp{};
    act_ed25519_keypair(kp.seed.data(), kp.pubkey.data(), kp.privkey.data());
    return kp;
}

Status make_token(const std::array<uint8_t, kPrivkeySize> &privkey,
                  uint32_t product_id, const std::string &payload,
                  uint32_t ttl_seconds, std::string &token_out)
{
    std::vector<char> buf(ACT_TOKEN_MAX_CHARS(ACT_TOKEN_MAX_PAYLOAD) + 1);
    const act_status st = act_token_create(privkey.data(), product_id,
        reinterpret_cast<const uint8_t *>(payload.data()), payload.size(),
        ttl_seconds, buf.data(), buf.size());
    if (st == ACT_OK) {
        token_out.assign(buf.data());
    }
    return (Status)st;
}

Status respond_challenge(const std::array<uint8_t, kPrivkeySize> &privkey,
                         const std::string &challenge,
                         std::string &response_out)
{
    char buf[128];
    const act_status st = act_challenge_respond(challenge.c_str(),
                                                privkey.data(), buf,
                                                sizeof(buf));
    if (st == ACT_OK) {
        response_out.assign(buf);
    }
    return (Status)st;
}

void make_license(const std::array<uint8_t, kPrivkeySize> &privkey,
                  uint32_t product_id,
                  const std::array<uint8_t, kMachineCodeSize> &machine_code,
                  uint32_t expiry_days, bool perpetual,
                  std::string &code_out)
{
    uint8_t payload[ACT_PAYLOAD_SIZE];
    uint8_t sig[ACT_SIG_SIZE];
    act_license_make(payload, sig, product_id, machine_code.data(),
                     expiry_days, perpetual ? ACT_FLAG_PERPETUAL : 0,
                     NULL, 0, privkey.data());
    char buf[ACT_CODE_MAX_CHARS];
    if (act_license_encode(payload, sig, buf, sizeof(buf)) == ACT_OK) {
        code_out.assign(buf);
    }
}

} // namespace vendor

namespace sm2 {

KeyPair generate_keypair()
{
    KeyPair kp;
    act_sm2_keypair(NULL, kp.pub.data(), kp.priv.data());
    return kp;
}

static int hexval(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

std::string sign(const std::array<uint8_t, 32> &priv,
                 const void *msg, size_t len, const char *id)
{
    uint8_t sig[ACT_SM2_SIG_SIZE];
    if (act_sm2_sign(sig, (const uint8_t *)msg, len, priv.data(), id) !=
        ACT_OK) {
        return std::string();
    }
    static const char *hx = "0123456789abcdef";
    std::string out;
    out.reserve(128);
    for (int i = 0; i < ACT_SM2_SIG_SIZE; i++) {
        out += hx[sig[i] >> 4];
        out += hx[sig[i] & 15];
    }
    return out;
}

Status verify(const std::string &sig_hex, const std::array<uint8_t, 64> &pub,
              const void *msg, size_t len, const char *id)
{
    if (sig_hex.size() != 128) {
        return Status::BadFormat;
    }
    uint8_t sig[ACT_SM2_SIG_SIZE];
    for (int i = 0; i < ACT_SM2_SIG_SIZE; i++) {
        const int h = hexval(sig_hex[2 * i]);
        const int l = hexval(sig_hex[2 * i + 1]);
        if (h < 0 || l < 0) {
            return Status::BadFormat;
        }
        sig[i] = (uint8_t)((h << 4) | l);
    }
    return (Status)act_sm2_verify(sig, (const uint8_t *)msg, len,
                                  pub.data(), id);
}

std::string encrypt(const std::array<uint8_t, 64> &pub,
                    const void *msg, size_t len)
{
    std::vector<uint8_t> ct(len + 97);
    size_t olen = 0;
    if (act_sm2_encrypt(pub.data(), (const uint8_t *)msg, len, ct.data(),
                        ct.size(), &olen) != ACT_OK) {
        return std::string();
    }
    static const char *hx = "0123456789abcdef";
    std::string out;
    out.reserve(olen * 2);
    for (size_t i = 0; i < olen; i++) {
        out += hx[ct[i] >> 4];
        out += hx[ct[i] & 15];
    }
    return out;
}

std::string decrypt(const std::array<uint8_t, 32> &priv,
                    const std::string &ct_hex)
{
    if (ct_hex.empty() || ct_hex.size() % 2 != 0) {
        return std::string();
    }
    std::vector<uint8_t> ct(ct_hex.size() / 2);
    for (size_t i = 0; i < ct.size(); i++) {
        const int h = hexval(ct_hex[2 * i]);
        const int l = hexval(ct_hex[2 * i + 1]);
        if (h < 0 || l < 0) {
            return std::string();
        }
        ct[i] = (uint8_t)((h << 4) | l);
    }
    std::vector<uint8_t> pt(ct.size() > 97 ? ct.size() - 97 : 1);
    size_t olen = 0;
    if (act_sm2_decrypt(ct.data(), ct.size(), priv.data(), pt.data(),
                        pt.size(), &olen) != ACT_OK) {
        return std::string();
    }
    return std::string((const char *)pt.data(), olen);
}

} // namespace sm2

} // namespace act
