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
 * @brief engrail-keygen -- vendor-side key management, issuance and
 *        offline authentication operations.
 *
 * SECURITY: this tool operates on the vendor *private* key. Keep it
 * offline; prefer passphrase-encrypted key files (ACTKEY2) -- a stolen
 * key file is useless without the passphrase, and the passphrase never
 * exists in source, templates or constants.
 *
 * Commands:
 *   keygen     [--pass P] [secret.key]              create key pair (+dsalt)
 *   pubkey     [--pass P] [secret.key]              print public key
 *   export-pub [--pass P] [secret.key] deploy.pub  pubkey+dsalt bundle
 *   issue      [--pass P] [secret.key] [options]    mint a license code
 *   issuefile  [--pass P] [secret.key] in out       batch issue
 *   inspect    <code>                               offline code metadata
 *   revoke     [--pass P] [secret.key] list.dat <serial|code>
 *   revokelist [--pass P] [secret.key] list.dat
 *   token sign [--pass P] [secret.key] --ttl N --payload "text"
 *   token verify deploy.pub <token>                 offline token check
 *   challenge  [secret.key?] --machine MC --product N   (needs no key)
 *   respond    [--pass P] [secret.key] <challenge>  sign a challenge
 *   verify     deploy.pub <challenge> <response>    offline challenge check
 *   version
 *
 * Community: https://t.me/Stack_Traces
 */

#include "activation/activation.hpp"
#include "activation/ed25519.h"
#include "activation/random.h"
#include "activation/revoke.h"
#include "activation/sm2.h"
#include "activation/version.h"

#include <array>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#ifndef _WIN32
#  include <sys/stat.h>
#  include <termios.h>
#  include <unistd.h>
#else
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  ifndef NOMINMAX
#    define NOMINMAX
#  endif
#  include <windows.h>
#endif

namespace {

/* Vendor key bundle: seed + dsalt + derived material                  */

struct VendorKey {
    std::array<uint8_t, 32> seed{};
    std::array<uint8_t, 32> dsalt{};   /* public, per-deployment */
    std::array<uint8_t, 32> pubkey{};
    std::array<uint8_t, 64> privkey{};

    void derive()
    {
        act_ed25519_keypair(seed.data(), pubkey.data(), privkey.data());
    }
};

constexpr const char *kHeaderV2 = "activation-secret-key v2";

/* Pretty terminal output                                              */

struct Style {
    bool on;
    const char *bold, *dim, *green, *yellow, *red, *cyan, *reset;
};

Style style()
{
    const char *nc = getenv("NO_COLOR");
    if (nc != NULL && nc[0] != '\0') {
        return {false, "", "", "", "", "", "", ""};
    }
    return {true, "\033[1m", "\033[2m", "\033[32m", "\033[33m",
            "\033[31m", "\033[36m", "\033[0m"};
}

/* Bilingual CLI (i18n): --lang zh|en > $ACT_LANG > $LANG auto-detect  */

static int g_zh = 0; /* 0 = English, 1 = 简体中文 */

/** Pick a string by the active language. */
#define TR(en, zh) (g_zh ? (zh) : (en))

/** Resolve language: explicit env, else locale auto-detection. */
static void init_lang_from_env()
{
    const char *env = getenv("ACT_LANG");
    if (env != NULL && env[0] != '\0') {
        g_zh = (strncmp(env, "zh", 2) == 0);
        return;
    }
    env = getenv("LC_ALL");
    if (env == NULL || env[0] == '\0') {
        env = getenv("LANG");
    }
    g_zh = (env != NULL && strncmp(env, "zh", 2) == 0);
}

void banner()
{
    const Style s = style();
    const std::string title =
        std::string("  ") + ACT_PROJECT_NAME + " v" + ACT_VERSION;
    const std::string pad(38 > title.size() ? 38 - title.size() : 1, ' ');
    const std::string tagline =
        TR("offline licensing & authentication", "离线授权 · 离线认证 · 国密双栈  ");
    const std::string pad2(36 > tagline.size() ? 36 - tagline.size() : 1, ' ');
    std::cout
        << s.cyan << s.bold
        << "  ______________________________________\n"
        << " /                                      \\\n"
        << " |" << title << pad << "|\n"
        << " |  " << tagline << pad2 << "  |\n"
        << " \\______________________________________/\n"
        << s.reset
        << s.dim << "  " << TR("community", "社区") << " " << s.reset
        << s.bold << ACT_TELEGRAM_CHANNEL
        << s.reset << s.dim << "  " ACT_TELEGRAM_URL "\n" << s.reset << "\n";
}

/* Helpers                                                             */

std::string to_hex(const uint8_t *data, size_t len)
{
    static const char *hex = "0123456789abcdef";
    std::string out;
    out.reserve(len * 2);
    for (size_t i = 0; i < len; i++) {
        out += hex[data[i] >> 4];
        out += hex[data[i] & 15];
    }
    return out;
}

int from_hex(const std::string &hex, uint8_t *out, size_t outlen)
{
    if (hex.size() != outlen * 2) {
        return -1;
    }
    for (size_t i = 0; i < outlen; i++) {
        unsigned v;
        if (sscanf(hex.c_str() + 2 * i, "%2x", &v) != 1) {
            return -1;
        }
        out[i] = (uint8_t)v;
    }
    return 0;
}

/**
 * Passphrase handling.
 *
 * extract_passphrase() REMOVES the `--pass VALUE` (or `--pass=VALUE`)
 * pair from @p args in place, so that later positional parsing can
 * never mistake the VALUE for a file path (audit R2/BUG-1: with the
 * old scan-only helper, `keygen --pass s3cret out.key` silently wrote
 * the key to a file named `s3cret`, leaking the passphrase as a path).
 *
 * Resolution order: --pass VALUE  >  $ACT_PASSPHRASE  >  interactive
 * prompt (only for passphrase-protected files on a TTY, echo off).
 *
 * @return 1 when a passphrase was found, 0 when none, -1 when `--pass`
 *         was given without a value (caller must abort).
 */
int extract_passphrase(std::vector<std::string> &args, std::string &pass)
{
    for (size_t i = 0; i < args.size(); i++) {
        if (args[i] == "--pass") {
            if (i + 1 >= args.size()) {
                return -1; /* value missing: let the caller error out */
            }
            pass = args[i + 1];
            args.erase(args.begin() + (long)i,
                       args.begin() + (long)i + 2);
            return 1;
        }
        if (args[i].rfind("--pass=", 0) == 0) {
            pass = args[i].substr(7);
            args.erase(args.begin() + (long)i);
            return 1;
        }
    }
    const char *env = getenv("ACT_PASSPHRASE");
    if (env != NULL && env[0] != '\0') {
        pass = env;
        return 1;
    }
    return 0;
}

/**
 * Interactive passphrase prompt with echo suppression. Returns false
 * when stdin is not a TTY (scripts/CI keep working unmodified).
 */
bool prompt_passphrase(const char *what, std::string &pass)
{
#if !defined(_WIN32)
    struct termios oldt;
    if (!isatty(STDIN_FILENO) ||
        tcgetattr(STDIN_FILENO, &oldt) != 0) {
        return false;
    }
    struct termios noecho = oldt;
    noecho.c_lflag &= ~(tcflag_t)ECHO;
    if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &noecho) != 0) {
        return false;
    }
    std::fprintf(stderr, "%s: ", what);
    std::getline(std::cin, pass);
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &oldt);
    std::fprintf(stderr, "\n");
    return true;
#else
    /* Windows: console echo off via SetConsoleMode on CONIN$. */
    HANDLE con = CreateFileW(L"CONIN$", GENERIC_READ | GENERIC_WRITE,
                             FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (con == INVALID_HANDLE_VALUE || GetFileType(GetStdHandle(
                                           STD_INPUT_HANDLE)) !=
                                           FILE_TYPE_CHAR) {
        if (con != INVALID_HANDLE_VALUE) CloseHandle(con);
        return false;
    }
    DWORD mode = 0;
    BOOL had = GetConsoleMode(con, &mode);
    if (had) SetConsoleMode(con, mode & ~ENABLE_ECHO_INPUT);
    std::fprintf(stderr, "%s: ", what);
    std::getline(std::cin, pass);
    if (had) SetConsoleMode(con, mode);
    CloseHandle(con);
    std::fprintf(stderr, "\n");
    return true;
#endif
}

bool write_secret_file(const std::string &path, const VendorKey &key,
                       const std::string &pass)
{
    if (!pass.empty()) {
        if (act_keyfile_save(path.c_str(), key.seed.data(), key.dsalt.data(),
                             pass.c_str(), 0) != ACT_OK) {
            return false;
        }
    } else {
        std::ofstream f(path, std::ios::binary | std::ios::trunc);
        if (!f) {
            return false;
        }
        f << kHeaderV2 << "\n"
          << to_hex(key.seed.data(), 32) << "\n"
          << to_hex(key.dsalt.data(), 32) << "\n";
        f.close();
        if (!f) {
            return false;
        }
    }
#ifndef _WIN32
    (void)::chmod(path.c_str(), 0600);
#endif
    return true;
}

bool read_secret_file(const std::string &path, VendorKey &key,
                      const std::string &pass = std::string())
{
    { /* ACTKEY2 encrypted? */
        std::ifstream probe(path, std::ios::binary);
        char magic[8] = {0};
        if (probe.read(magic, 7) && memcmp(magic, "ACTKEY2", 7) == 0) {
            act_status st = act_keyfile_load(
                path.c_str(), pass.empty() ? nullptr : pass.c_str(),
                key.seed.data(), key.dsalt.data());
            if (st != ACT_OK && pass.empty()) {
                /* R2/BUG-2: the file needs a passphrase and none was
                 * supplied -- offer an echo-off prompt on a TTY (pipes
                 * and CI fall through unchanged). */
                std::string asked;
                if (prompt_passphrase("passphrase (encrypted key file)",
                                      asked) && !asked.empty()) {
                    st = act_keyfile_load(path.c_str(), asked.c_str(),
                                          key.seed.data(), key.dsalt.data());
                }
            }
            if (st != ACT_OK) {
                std::fprintf(stderr,
                             "error: %s is passphrase-protected -- supply it "
                             "via --pass or $ACT_PASSPHRASE\n", path.c_str());
                return false;
            }
            key.derive();
            return true;
        }
    }

    std::ifstream f(path, std::ios::binary);
    if (!f) {
        return false;
    }
    std::string line;
    if (!std::getline(f, line) ||
        (line.compare(0, std::strlen(kHeaderV2), kHeaderV2) != 0 &&
         line != "activation-secret-key v1")) {
        std::fprintf(stderr, "error: %s is not a valid secret key file\n",
                     path.c_str());
        return false;
    }
    const bool legacy_v1 = (line == "activation-secret-key v1");
    if (!std::getline(f, line)) {
        return false;
    }
    while (!line.empty() && (line.back() == '\r' || line.back() == '\n')) {
        line.pop_back();
    }
    if (from_hex(line, key.seed.data(), key.seed.size()) != 0) {
        return false;
    }
    if (legacy_v1) {
        key.dsalt.fill(0);
        std::fprintf(stderr,
                     "warning: legacy v1 key file (no deployment salt) -- "
                     "re-run `keygen` to upgrade\n");
    } else {
        std::string dline;
        if (!std::getline(f, dline) ||
            from_hex(dline, key.dsalt.data(), key.dsalt.size()) != 0) {
            return false;
        }
    }
    key.derive();
    return true;
}

std::string fmt_time(int64_t unix_ts)
{
    const time_t t = (time_t)unix_ts;
    char buf[64]; /* GCC -Wformat-truncation worst case */
#ifdef _WIN32
    struct tm tmv {};
    gmtime_s(&tmv, &t);
#else
    struct tm tmv {};
    gmtime_r(&t, &tmv);
#endif
    std::snprintf(buf, sizeof(buf), "%04d-%02d-%02d %02d:%02d UTC",
                  tmv.tm_year + 1900, tmv.tm_mon + 1, tmv.tm_mday,
                  tmv.tm_hour, tmv.tm_min);
    return std::string(buf);
}

bool parse_machine(const std::string &machine, uint8_t out[16])
{
    if (machine.size() != 33 || machine[16] != '-') {
        return false;
    }
    std::string compact;
    for (char c : machine) {
        if (c != '-') compact += c;
    }
    return from_hex(compact, out, 16) == 0;
}

/* Commands                                                            */

int cmd_keygen(int argc, char **argv)
{
    const Style s = style();
    banner();
    std::vector<std::string> args(argv, argv + argc);
    std::string pass;
    const int pass_rc = extract_passphrase(args, pass);
    if (pass_rc < 0) {
        std::fprintf(stderr, "error: --pass needs a value\n");
        return 2;
    }
    const bool encrypted = (pass_rc > 0);

    std::string path = "secret.key";
    for (const std::string &a : args) {
        if (a.rfind("--", 0) != 0) {
            path = a;
            break;
        }
    }

    VendorKey key;
    act_random_bytes(key.seed.data(), key.seed.size());
    act_random_bytes(key.dsalt.data(), key.dsalt.size());
    key.derive();

    if (!write_secret_file(path, key, pass)) {
        std::fprintf(stderr, "error: cannot write %s\n", path.c_str());
        return 2;
    }

    std::cout
        << s.green << s.bold << "[OK]" << s.reset
        << " " << TR("secret key written to", "私钥已写入") << " : "
        << s.bold << path << s.reset
        << (encrypted ? TR("  (passphrase-encrypted ACTKEY2)",
                           "  (已口令加密 ACTKEY2)") : "") << "\n"
        << "     " << TR("public key (hex)", "公钥 (hex)") << "  : "
        << s.cyan
        << to_hex(key.pubkey.data(), 32) << s.reset << "\n"
        << "     " << TR("deployment salt", "部署盐") << "   : "
        << to_hex(key.dsalt.data(), 32) << "\n\n"
        << TR("Embed BOTH values in your application (or ship deploy.pub):",
              "把这两个值都嵌入你的应用 (或随包分发 deploy.pub):") << "\n\n"
        << s.dim << "  static const uint8_t ACT_PUBKEY[32] = {\n      "
        << s.reset;
    for (size_t i = 0; i < 32; i++) {
        char byte[8];
        std::snprintf(byte, sizeof(byte), "0x%02x%s", key.pubkey[i],
                      (i == 31) ? "" : ", ");
        std::cout << byte;
        if (i % 8 == 7 && i != 31) {
            std::cout << "\n      ";
        }
    }
    std::cout << "\n  };\n"
              << s.dim << "  static const uint8_t ACT_DSALT[32] = { /* "
              << to_hex(key.dsalt.data(), 32) << " */ };\n" << s.reset
              << "\n" << s.red << s.bold << "[!]" << s.reset << " "
              << TR(std::string("KEEP '") + path +
                        "' OFFLINE AND NEVER COMMIT IT.",
                    std::string("务必把 '") + path +
                        "' 离线保存, 严禁提交到仓库!") << "\n"
              << s.dim << "  " << TR("community ->", "社区 ->") << " "
              << s.reset
              << ACT_TELEGRAM_URL << "\n";
    return 0;
}

int cmd_pubkey(int argc, char **argv)
{
    std::vector<std::string> args(argv, argv + argc);
    std::string pass, path = "secret.key";
    if (extract_passphrase(args, pass) < 0) {
        std::fprintf(stderr, "error: --pass needs a value\n");
        return 2;
    }
    for (const std::string &a : args) {
        if (a.rfind("--", 0) != 0) {
            path = a;
            break;
        }
    }
    VendorKey key;
    if (!read_secret_file(path, key, pass)) {
        return 2;
    }
    std::cout << to_hex(key.pubkey.data(), 32) << "\n";
    return 0;
}

int cmd_export_pub(int argc, char **argv)
{
    std::vector<std::string> args(argv, argv + argc);
    std::string pass, path = "secret.key", out_path = "deploy.pub";
    if (extract_passphrase(args, pass) < 0) {
        std::fprintf(stderr, "error: --pass needs a value\n");
        return 2;
    }
    int positional = 0;
    for (const std::string &a : args) {
        if (a.rfind("--", 0) != 0) {
            if (positional++ == 0) path = a; else out_path = a;
        }
    }
    VendorKey key;
    if (!read_secret_file(path, key, pass)) {
        return 2;
    }
    /* bundle = base64url(pubkey || dsalt) */
    uint8_t bundle[64];
    memcpy(bundle, key.pubkey.data(), 32);
    memcpy(bundle + 32, key.dsalt.data(), 32);
    char b64[128];
    {
        static const char *B = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef"
                               "ghijklmnopqrstuvwxyz0123456789-_";
        size_t i = 0, o = 0;
        while (i + 3 <= 64) {
            const uint32_t v = ((uint32_t)bundle[i] << 16) |
                               ((uint32_t)bundle[i + 1] << 8) | bundle[i + 2];
            b64[o++] = B[(v >> 18) & 63];
            b64[o++] = B[(v >> 12) & 63];
            b64[o++] = B[(v >> 6) & 63];
            b64[o++] = B[v & 63];
            i += 3;
        }
        const size_t rem = 64 - i; /* 64 % 3 == 1 -> one tail byte */
        if (rem == 1) {
            const uint32_t v = (uint32_t)bundle[i] << 16;
            b64[o++] = B[(v >> 18) & 63];
            b64[o++] = B[(v >> 12) & 63];
        } else if (rem == 2) {
            const uint32_t v = ((uint32_t)bundle[i] << 16) |
                               ((uint32_t)bundle[i + 1] << 8);
            b64[o++] = B[(v >> 18) & 63];
            b64[o++] = B[(v >> 12) & 63];
            b64[o++] = B[(v >> 6) & 63];
        }
        b64[o] = '\0';
    }
    std::ofstream f(out_path, std::ios::trunc);
    if (!f) {
        std::fprintf(stderr, "error: cannot write %s\n", out_path.c_str());
        return 2;
    }
    f << "# Engrail deployment bundle (PUBLIC - safe to ship)\n"
      << "# pubkey(32B) || dsalt(32B), base64url\n"
      << b64 << "\n";
    std::cout << "wrote " << out_path << " (public bundle: "
              << to_hex(key.pubkey.data(), 32) << " / "
              << to_hex(key.dsalt.data(), 32) << ")\n";
    return 0;
}

int cmd_issue(int argc, char **argv)
{
    const Style s = style();
    std::vector<std::string> args(argv, argv + argc);
    std::string pass, key_path = "secret.key";
    uint32_t product_id = 1;
    uint32_t days = 365;
    bool perpetual = false, trial = false;
    unsigned long features_in = 0;
    std::string machine, serial_hex;

    const int pass_rc = extract_passphrase(args, pass);
    if (pass_rc < 0) {
        std::fprintf(stderr, "error: --pass needs a value\n");
        return 2;
    }
    const bool encrypted = (pass_rc > 0);
    for (size_t i = 0; i < args.size(); i++) {
        const std::string &a = args[i];
        if (a == "--product" && i + 1 < args.size()) {
            product_id = (uint32_t)std::strtoul(args[++i].c_str(), nullptr, 0);
        } else if (a == "--days" && i + 1 < args.size()) {
            days = (uint32_t)std::strtoul(args[++i].c_str(), nullptr, 10);
        } else if (a == "--perpetual") {
            perpetual = true;
        } else if (a == "--trial") {
            trial = true;
        } else if (a == "--features" && i + 1 < args.size()) {
            features_in = std::strtoul(args[++i].c_str(), nullptr, 0);
        } else if (a == "--serial" && i + 1 < args.size()) {
            serial_hex = args[++i];
        } else if (a == "--machine" && i + 1 < args.size()) {
            machine = args[++i];
        } else if (!a.empty() && a[0] != '-') {
            key_path = a;
        } else if (!a.empty()) {
            std::fprintf(stderr, "error: unknown/incomplete option '%s'\n",
                         a.c_str());
            return 2;
        }
    }
    (void)encrypted;

    uint8_t mc[16];
    if (!parse_machine(machine, mc)) {
        std::fprintf(stderr, "%s",
                     TR("error: --machine must look like "
                        "XXXXXXXXXXXXXXXX-XXXXXXXXXXXXXXXX\n"
                        "       (run the target app once to see its machine "
                        "code)\n",
                        "错误: --machine 格式应为 "
                        "XXXXXXXXXXXXXXXX-XXXXXXXXXXXXXXXX\n"
                        "      (先运行一次目标程序即可看到机器码)\n"));
        return 2;
    }

    uint8_t serial[8];
    if (!serial_hex.empty()) {
        if (from_hex(serial_hex, serial, 8) != 0) {
            std::fprintf(stderr, "error: --serial must be 16 hex chars\n");
            return 2;
        }
    }

    VendorKey key;
    if (!read_secret_file(key_path, key, pass)) {
        std::fprintf(stderr, "error: cannot read %s\n", key_path.c_str());
        return 2;
    }

    const uint32_t anchor_day = (uint32_t)(
        (int64_t)std::time(nullptr) / 86400 - ACT_EXPIRY_EPOCH / 86400);
    unsigned flags = 0;
    if (perpetual) flags |= ACT_FLAG_PERPETUAL;
    if (trial) flags |= ACT_FLAG_TRIAL;

    uint8_t payload[ACT_PAYLOAD_SIZE], sig[ACT_SIG_SIZE];
    act_license_make(payload, sig, product_id, mc,
                     perpetual ? 0 : anchor_day + days, flags,
                     serial_hex.empty() ? NULL : serial,
                     (uint16_t)features_in, key.privkey.data());
    char buf[ACT_CODE_MAX_CHARS];
    if (act_license_encode(payload, sig, buf, sizeof(buf)) != ACT_OK) {
        std::fprintf(stderr, "error: license encoding failed\n");
        return 2;
    }

    /* stdout: only the code (script-friendly). */
    std::cout << buf << std::endl;
    /* stderr: metadata. */
    std::cerr << s.dim;
    std::cerr << TR("serial   : ", "序列号   : ") << to_hex(payload + 26, 8)
              << "\n";
    std::cerr << TR("features : ", "功能位   : ") << "0x" << std::hex
              << (payload[34] << 8 | payload[35]) << std::dec << "\n";
    if (perpetual) {
        std::cerr << TR("expiry   : never (perpetual)", "有效期   : 永久") << "\n";
    } else {
        std::cerr << TR("expiry   : ", "有效期   : ")
                  << fmt_time(act_expiry_to_unix(anchor_day + days)) << "\n";
    }
    if (trial) {
        std::cerr << TR("type     : TRIAL", "类型     : 试用版") << "\n";
    }
    std::cerr << s.reset;
    return 0;
}

int cmd_issuefile(int argc, char **argv)
{
    std::vector<std::string> args(argv, argv + argc);
    std::string pass, key_path = "secret.key";
    std::string machines_path = "machines.txt", out_path = "codes.txt";
    uint32_t days = 365;
    uint32_t product_id = 1;
    unsigned long features_in = 0;
    bool perpetual = false, trial = false;
    if (extract_passphrase(args, pass) < 0) {
        std::fprintf(stderr, "error: --pass needs a value\n");
        return 2;
    }
    int positional = 0;
    for (size_t i = 0; i < args.size(); i++) {
        const std::string &a = args[i];
        if (a == "--days" && i + 1 < args.size()) {
            days = (uint32_t)std::strtoul(args[++i].c_str(), nullptr, 10);
        } else if (a == "--product" && i + 1 < args.size()) {
            product_id =
                (uint32_t)std::strtoul(args[++i].c_str(), nullptr, 0);
        } else if (a == "--features" && i + 1 < args.size()) {
            features_in = std::strtoul(args[++i].c_str(), nullptr, 0);
        } else if (a == "--perpetual") {
            perpetual = true;
        } else if (a == "--trial") {
            trial = true;
        } else if (a.rfind("--", 0) != 0) {
            if (positional++ == 0) key_path = a;
            else if (positional == 2) machines_path = a;
            else if (positional == 3) out_path = a;
        }
    }

    VendorKey key;
    if (!read_secret_file(key_path, key, pass)) {
        std::fprintf(stderr, "error: cannot read %s\n", key_path.c_str());
        return 2;
    }

    std::ifstream in(machines_path);
    std::ofstream out(out_path, std::ios::trunc);
    if (!in || !out) {
        std::fprintf(stderr, "error: cannot open %s or %s\n",
                     machines_path.c_str(), out_path.c_str());
        return 2;
    }

    const uint32_t anchor_day = (uint32_t)(
        (int64_t)std::time(nullptr) / 86400 - ACT_EXPIRY_EPOCH / 86400);
    std::string line;
    size_t ok_count = 0, bad_count = 0;
    while (std::getline(in, line)) {
        while (!line.empty() && (line.back() == '\r' || line.back() == ' ')) {
            line.pop_back();
        }
        if (line.empty() || line[0] == '#') {
            continue;
        }
        uint8_t mc[16];
        if (!parse_machine(line, mc)) {
            std::fprintf(stderr, "skip (bad format): %s\n", line.c_str());
            bad_count++;
            continue;
        }
        uint8_t payload[ACT_PAYLOAD_SIZE], sig[ACT_SIG_SIZE];
        const unsigned flags = (perpetual ? ACT_FLAG_PERPETUAL : 0u) |
                               (trial ? ACT_FLAG_TRIAL : 0u);
        act_license_make(payload, sig, product_id, mc, anchor_day + days,
                         flags, NULL, (uint16_t)features_in,
                         key.privkey.data());
        char buf[ACT_CODE_MAX_CHARS];
        if (act_license_encode(payload, sig, buf, sizeof(buf)) == ACT_OK) {
            out << line << ';' << buf << '\n';
            ok_count++;
        }
    }
    std::printf("issued %zu code(s) -> %s (%zu skipped)\n", ok_count,
                out_path.c_str(), bad_count);
    return (bad_count == 0) ? 0 : 1;
}

int cmd_inspect(int argc, char **argv)
{
    const Style s = style();
    bool json = false;
    std::string code_arg;
    for (int i = 0; i < argc; i++) {
        if (std::string(argv[i]) == "--json") {
            json = true;
        } else {
            code_arg = argv[i];
        }
    }
    if (code_arg.empty()) {
        std::fprintf(stderr,
                     "usage: engrail-keygen inspect [--json] <code>\n");
        return 2;
    }
    const char *code = code_arg.c_str();
    uint8_t payload[ACT_PAYLOAD_SIZE], sig[ACT_SIG_SIZE];
    if (act_license_decode(code, payload, sig) != ACT_OK) {
        std::fprintf(stderr, "error: not a valid activation code\n");
        return 1;
    }
    const uint32_t pid = ((uint32_t)payload[1] << 24) |
                         ((uint32_t)payload[2] << 16) |
                         ((uint32_t)payload[3] << 8) | (uint32_t)payload[4];
    const uint32_t expiry = ((uint32_t)payload[21] << 24) |
                            ((uint32_t)payload[22] << 16) |
                            ((uint32_t)payload[23] << 8) |
                            (uint32_t)payload[24];
    const unsigned flags = payload[25];
    const uint16_t feats = (uint16_t)((payload[34] << 8) | payload[35]);
    char mcstr[ACT_MACHINE_CODE_STR_SIZE];
    {
        static const char *hx = "0123456789ABCDEF";
        int o = 0;
        for (int i = 0; i < 16; i++) {
            if (i == 8) mcstr[o++] = '-';
            mcstr[o++] = hx[payload[5 + i] >> 4];
            mcstr[o++] = hx[payload[5 + i] & 15];
        }
        mcstr[o] = '\0';
    }

    if (json) {
        std::printf("{\n");
        std::printf("  \"format\": %d,\n", (int)payload[0]);
        std::printf("  \"product_id\": %u,\n", pid);
        std::printf("  \"machine\": \"%s\",\n", mcstr);
        std::printf("  \"serial\": \"%s\",\n", to_hex(payload + 26, 8).c_str());
        std::printf("  \"features\": %u,\n", (unsigned)feats);
        std::printf("  \"perpetual\": %s,\n",
                    (flags & ACT_FLAG_PERPETUAL) ? "true" : "false");
        std::printf("  \"trial\": %s,\n",
                    (flags & ACT_FLAG_TRIAL) ? "true" : "false");
        if (flags & ACT_FLAG_PERPETUAL) {
            std::printf("  \"expires\": null\n");
        } else {
            std::printf("  \"expires_unix\": %lld,\n",
                        (long long)act_expiry_to_unix(expiry));
            std::printf("  \"expires_utc\": \"%s\"\n",
                        fmt_time(act_expiry_to_unix(expiry)).c_str());
        }
        std::printf("}\n");
        return 0;
    }

    std::cout << s.bold << TR("code metadata (not authenticated)",
                               "授权码元数据 (未验证真伪)") << s.reset << "\n"
              << "  " << TR("format     : ", "格式       : ") << "v"
              << (int)payload[0] << "\n"
              << "  " << TR("product id : ", "产品 ID    : ") << pid
              << " (0x" << std::hex << pid << ")" << std::dec << "\n"
              << "  " << TR("machine    : ", "机器码     : ") << mcstr << "\n"
              << "  " << TR("serial     : ", "序列号     : ")
              << to_hex(payload + 26, 8) << "\n"
              << "  " << TR("features   : ", "功能位     : ") << "0x"
              << std::hex << feats << std::dec << "\n"
              << "  " << TR("perpetual  : ", "永久授权   : ")
              << ((flags & ACT_FLAG_PERPETUAL) ? TR("yes", "是") : TR("no", "否"))
              << "\n"
              << "  " << TR("trial      : ", "试用版     : ")
              << ((flags & ACT_FLAG_TRIAL) ? TR("yes", "是") : TR("no", "否"))
              << "\n";
    if (!(flags & ACT_FLAG_PERPETUAL)) {
        std::cout << "  " << TR("expires    : ", "到期时间   : ")
                  << fmt_time(act_expiry_to_unix(expiry)) << "\n";
    }
    std::cout << s.dim
              << TR("  authenticity requires the vendor public key\n",
                    "  真伪验证需要厂商公钥\n")
              << "  community: " ACT_TELEGRAM_URL "\n" << s.reset;
    return 0;
}

int cmd_revoke(int argc, char **argv)
{
    const Style s = style();
    std::vector<std::string> args(argv, argv + argc);
    std::string pass;
    if (extract_passphrase(args, pass) < 0) {
        std::fprintf(stderr, "error: --pass needs a value\n");
        return 2;
    }
    std::vector<std::string> pos;
    for (const std::string &a : args) {
        if (a != "--pass" && a.rfind("--", 0) != 0) pos.push_back(a);
    }
    if (pos.size() < 2) {
        std::fprintf(stderr,
                     "usage: engrail-keygen revoke [secret.key] list.dat "
                     "<serial-or-code>\n");
        return 2;
    }
    const std::string key_path = pos[0];
    const std::string list_path = pos[1];
    const std::string what = pos[2];

    VendorKey key;
    if (!read_secret_file(key_path, key, pass)) {
        std::fprintf(stderr, "error: cannot read %s\n", key_path.c_str());
        return 2;
    }

    uint8_t serial[8];
    uint8_t payload[ACT_PAYLOAD_SIZE], sig[ACT_SIG_SIZE];
    if (act_license_decode(what.c_str(), payload, sig) == ACT_OK &&
        payload[0] == ACT_LICENSE_VERSION) {
        memcpy(serial, payload + 26, 8);
    } else if (from_hex(what, serial, 8) != 0) {
        std::fprintf(stderr,
                     "error: give an 8-byte serial (16 hex chars) or a "
                     "full activation code\n");
        return 2;
    }

    const act_status st = act_revoke_add(list_path.c_str(), key.privkey.data(),
                                         serial);
    if (st != ACT_OK) {
        std::fprintf(stderr, "error: revocation update failed (%d)\n", st);
        return 2;
    }
    uint32_t count = 0;
    (void)act_revoke_load(list_path.c_str(), key.pubkey.data(), NULL, 0,
                          &count);
    std::cout << s.green << s.bold << "[OK]" << s.reset << " "
              << TR("serial", "序列号") << " " << to_hex(serial, 8) << " "
              << TR("revoked (list now holds", "已吊销 (当前名单共") << " "
              << count << (count == 1 ? TR(" entry)", " 条)") : TR(" entries)", " 条)"))
              << "\n"
              << s.dim
              << TR("ship the updated list with your next release -> ",
                    "随下次发布分发更新后的名单 -> ")
              << s.reset << list_path << "\n";
    return 0;
}

int cmd_revokelist(int argc, char **argv)
{
    const Style s = style();
    std::vector<std::string> args(argv, argv + argc);
    std::string pass;
    if (extract_passphrase(args, pass) < 0) {
        std::fprintf(stderr, "error: --pass needs a value\n");
        return 2;
    }
    std::vector<std::string> pos;
    for (const std::string &a : args) {
        if (a != "--pass" && a.rfind("--", 0) != 0) pos.push_back(a);
    }
    const std::string key_path = pos.size() > 0 ? pos[0] : "secret.key";
    const std::string list_path = pos.size() > 1 ? pos[1] : "revoke.dat";
    VendorKey key;
    if (!read_secret_file(key_path, key, pass)) {
        return 2;
    }
    uint32_t count = 0;
    const act_status st = act_revoke_load(list_path.c_str(), key.pubkey.data(),
                                          NULL, 0, &count);
    if (st == ACT_ERR_STATE_MISSING) {
        std::printf("no revocation list at %s\n", list_path.c_str());
        return 1;
    }
    if (st != ACT_OK) {
        std::fprintf(stderr, "error: list verification failed (%d)\n", st);
        return 1;
    }
    std::vector<uint8_t> flat((size_t)count * 8);
    (void)act_revoke_load(list_path.c_str(), key.pubkey.data(), flat.data(),
                          count, &count);
    std::cout << s.bold << count << " revoked serial(s)" << s.reset << s.dim
              << " (signature verified)" << s.reset << "\n";
    for (uint32_t i = 0; i < count; i++) {
        std::cout << "  " << to_hex(flat.data() + (size_t)i * 8, 8) << "\n";
    }
    return 0;
}

/* Parse "pubkey-hex:dsalt-hex" or base64url bundle from deploy.pub. */
bool load_bundle(const std::string &path, std::array<uint8_t, 32> &pk,
                 std::array<uint8_t, 32> &ds)
{
    std::ifstream f(path);
    if (!f) {
        return false;
    }
    std::string line;
    while (std::getline(f, line)) {
        if (line.empty() || line[0] == '#') continue;
        while (!line.empty() &&
               (line.back() == '\r' || line.back() == '\n')) {
            line.pop_back();
        }
        break;
    }
    if (line.find(':') != std::string::npos) {
        const size_t c = line.find(':');
        return from_hex(line.substr(0, c), pk.data(), 32) == 0 &&
               from_hex(line.substr(c + 1), ds.data(), 32) == 0;
    }
    /* base64url bundle of 64 bytes -> 86 chars (86*6=516 >= 512) */
    static const char *B = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef"
                           "ghijklmnopqrstuvwxyz0123456789-_";
    uint8_t out[64];
    size_t o = 0;
    uint32_t acc = 0;
    int bits = 0;
    for (const char ch : line) {
        const char *p = strchr(B, ch);
        if (p == NULL || o >= sizeof(out)) return false;
        acc = (acc << 6) | (uint32_t)(p - B);
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out[o++] = (uint8_t)(acc >> bits);
        }
    }
    if (o != 64) return false;
    memcpy(pk.data(), out, 32);
    memcpy(ds.data(), out + 32, 32);
    return true;
}

int cmd_token(int argc, char **argv)
{
    const Style s = style();
    std::vector<std::string> args(argv, argv + argc);
    if (args.empty()) {
        std::fprintf(stderr,
                     "usage: engrail-keygen token sign [--pass P] "
                     "[secret.key] --ttl N --payload \"text\"\n"
                     "       engrail-keygen token verify deploy.pub "
                     "<token>\n");
        return 2;
    }
    const std::string sub = args[0];
    args.erase(args.begin());

    if (sub == "sign") {
        std::string pass, key_path = "secret.key", payload;
        uint32_t ttl = 3600;
        if (extract_passphrase(args, pass) < 0) {
            std::fprintf(stderr, "error: --pass needs a value\n");
            return 2;
        }
        for (size_t i = 0; i < args.size(); i++) {
            const std::string &a = args[i];
            if (a == "--ttl" && i + 1 < args.size()) {
                ttl = (uint32_t)std::strtoul(args[++i].c_str(), nullptr, 10);
            } else if (a == "--payload" && i + 1 < args.size()) {
                payload = args[++i];
            } else if (a[0] != '-') {
                key_path = a;
            }
        }
        VendorKey key;
        if (!read_secret_file(key_path, key, pass)) {
            std::fprintf(stderr, "error: cannot read %s\n", key_path.c_str());
            return 2;
        }
        std::string tok;
        const act::Status st = act::vendor::make_token(
            key.privkey, 1, payload, ttl, tok);
        if (st != act::Status::Ok) {
            std::fprintf(stderr, "error: token creation failed\n");
            return 2;
        }
        std::cout << tok << std::endl; /* stdout: token only */
        std::cerr << s.dim << "payload  : " << payload << "\n"
                  << "ttl      : " << ttl << "s\n"
                  << s.reset;
        return 0;
    }

    if (sub == "verify") {
        std::string bundle_path = "deploy.pub";
        std::string tok;
        int positional = 0;
        for (const std::string &a : args) {
            if (a.rfind("--", 0) != 0) {
                if (positional++ == 0) bundle_path = a; else tok = a;
            }
        }
        std::array<uint8_t, 32> pk{}, ds{};
        if (!load_bundle(bundle_path, pk, ds)) {
            std::fprintf(stderr, "error: cannot read bundle %s\n",
                         bundle_path.c_str());
            return 2;
        }
        std::string payload;
        const act::Status st = act::Verifier(pk.data(), ds.data(), 1)
                                   .verify_token(tok, (int64_t)std::time(NULL),
                                                 payload);
        if (st == act::Status::Ok) {
            std::cout << s.green << s.bold << TR("VALID", "有效") << s.reset
                      << "  " << TR("payload: ", "载荷: ") << payload << "\n";
            return 0;
        }
        std::cout << s.red << s.bold << TR("INVALID", "无效") << s.reset << " ("
                  << act::status_string(st) << ")\n";
        return 1;
    }

    std::fprintf(stderr, "unknown token subcommand: %s\n", sub.c_str());
    return 2;
}

int cmd_challenge(int argc, char **argv)
{
    std::vector<std::string> args(argv, argv + argc);
    std::string machine;
    uint32_t product_id = 1;
    for (size_t i = 0; i < args.size(); i++) {
        if (args[i] == "--machine" && i + 1 < args.size()) {
            machine = args[++i];
        } else if (args[i] == "--product" && i + 1 < args.size()) {
            product_id = (uint32_t)std::strtoul(args[++i].c_str(), nullptr, 0);
        }
    }
    uint8_t mc[16];
    if (!parse_machine(machine, mc)) {
        std::fprintf(stderr,
                     "usage: engrail-keygen challenge --machine "
                     "XXXXXXXXXXXXXXXX-XXXXXXXXXXXXXXXX [--product N]\n"
                     "(apps normally call act::Verifier::challenge())\n");
        return 2;
    }
    char out[96];
    if (act_challenge_create(mc, product_id, (int64_t)std::time(NULL), out,
                             sizeof(out)) != ACT_OK) {
        return 2;
    }
    std::cout << out << "\n";
    return 0;
}

int cmd_respond(int argc, char **argv)
{
    std::vector<std::string> args(argv, argv + argc);
    std::string pass, key_path = "secret.key", challenge;
    if (extract_passphrase(args, pass) < 0) {
        std::fprintf(stderr, "error: --pass needs a value\n");
        return 2;
    }
    int positional = 0;
    for (size_t i = 0; i < args.size(); i++) {
        const std::string &a = args[i];
        if (a.rfind("--", 0) != 0) {
            if (positional++ == 0) key_path = a; else challenge = a;
        }
    }
    if (challenge.empty()) {
        std::fprintf(stderr,
                     "usage: engrail-keygen respond [--pass P] "
                     "[secret.key] <challenge>\n");
        return 2;
    }
    VendorKey key;
    if (!read_secret_file(key_path, key, pass)) {
        std::fprintf(stderr, "error: cannot read %s\n", key_path.c_str());
        return 2;
    }
    char out[128];
    if (act_challenge_respond(challenge.c_str(), key.privkey.data(), out,
                              sizeof(out)) != ACT_OK) {
        std::fprintf(stderr, "error: bad challenge\n");
        return 2;
    }
    std::cout << out << "\n";
    return 0;
}

int cmd_verify(int argc, char **argv)
{
    if (argc < 3) {
        std::fprintf(stderr,
                     "usage: engrail-keygen verify deploy.pub "
                     "<challenge> <response> [--machine MC] [--product N]\n");
        return 2;
    }
    std::array<uint8_t, 32> pk{}, ds{};
    if (!load_bundle(argv[0], pk, ds)) {
        std::fprintf(stderr, "error: cannot read bundle %s\n", argv[0]);
        return 2;
    }
    const std::string challenge = argv[1];
    const std::string response = argv[2];
    std::string machine;
    uint32_t product_id = 1;
    for (int i = 3; i < argc - 1; i++) {
        if (std::string(argv[i]) == "--machine") machine = argv[i + 1];
        if (std::string(argv[i]) == "--product") {
            product_id = (uint32_t)std::strtoul(argv[i + 1], nullptr, 0);
        }
    }
    uint8_t mc[16];
    if (!parse_machine(machine, mc)) {
        std::fprintf(stderr, "error: --machine required (33-char code)\n");
        return 2;
    }
    /* Reconstruct the challenge binding locally: verify() re-derives the
     * machine fingerprint from the bundle to prove the challenge was
     * created by THIS machine. For CLI use we accept the machine code
     * passed in; apps use act::Verifier::verify_challenge(). */
    (void)ds;
    const act_status st = act_challenge_verify(
        challenge.c_str(), response.c_str(), pk.data(), product_id, mc,
        (int64_t)std::time(NULL), 0);
    if (st == ACT_OK) {
        std::cout << TR("CHALLENGE AUTHENTICATED (offline)",
                        "质询-应答认证通过 (完全离线)") << "\n";
        return 0;
    }
    std::printf("REJECTED (%d)\n", st);
    return 1;
}

/* ---- SM2 (GB/T 32918) 国密子命令 ---- */

int cmd_sm2(int argc, char **argv)
{
    if (argc < 1) {
        std::fprintf(stderr,
                     "usage: engrail-keygen sm2 keygen   [seed-hex]\n"
                     "       engrail-keygen sm2 sign   <seed-hex> <msg-hex> [id]\n"
                     "       engrail-keygen sm2 verify <pub-hex> <msg-hex> <sig-hex> [id]\n"
                     "       engrail-keygen sm2 encrypt <pub-hex> <msg-hex>\n"
                     "       engrail-keygen sm2 decrypt <seed-hex> <ct-hex>\n");
        return 2;
    }
    const std::string sub = argv[0];
    argv += 1; argc -= 1;

    if (sub == "keygen" && argc >= 1) {
        uint8_t seed[32], pub[64], priv[32];
        if (from_hex(argv[0], seed, 32) != 0) {
            std::fprintf(stderr, "error: seed must be 64 hex chars\n");
            return 2;
        }
        act_sm2_keypair(seed, pub, priv);
        std::cout << to_hex(pub, 64) << "\n";
        return 0;
    }
    if (sub == "sign" && argc >= 2) {
        uint8_t seed[32], sig[64];
        if (from_hex(argv[0], seed, 32) != 0) return 2;
        std::vector<uint8_t> msg(strlen(argv[1]) / 2);
        for (size_t i = 0; i < msg.size(); i++) {
            unsigned v; sscanf(argv[1] + 2 * i, "%2x", &v); msg[i] = (uint8_t)v;
        }
        const char *id = argc > 2 ? argv[2] : NULL;
        if (act_sm2_sign(sig, msg.data(), msg.size(), seed, id) != ACT_OK) return 1;
        std::cout << to_hex(sig, 64) << "\n";
        return 0;
    }
    if (sub == "verify" && argc >= 3) {
        uint8_t pub[64], sig[64];
        if (from_hex(argv[0], pub, 64) != 0) return 2;
        std::vector<uint8_t> msg(strlen(argv[1]) / 2);
        for (size_t i = 0; i < msg.size(); i++) {
            unsigned v; sscanf(argv[1] + 2 * i, "%2x", &v); msg[i] = (uint8_t)v;
        }
        if (from_hex(argv[2], sig, 64) != 0) return 2;
        const char *id = argc > 3 ? argv[3] : NULL;
        const act_status st = act_sm2_verify(sig, msg.data(), msg.size(), pub, id);
        std::cout << (st == ACT_OK ? "ok" : "bad") << "\n";
        return st == ACT_OK ? 0 : 1;
    }
    if (sub == "encrypt" && argc >= 2) {
        uint8_t pub[64];
        if (from_hex(argv[0], pub, 64) != 0) return 2;
        std::vector<uint8_t> msg(strlen(argv[1]) / 2);
        for (size_t i = 0; i < msg.size(); i++) {
            unsigned v; sscanf(argv[1] + 2 * i, "%2x", &v); msg[i] = (uint8_t)v;
        }
        std::vector<uint8_t> ct(msg.size() + 97);
        size_t olen = 0;
        if (act_sm2_encrypt(pub, msg.data(), msg.size(), ct.data(), ct.size(),
                            &olen) != ACT_OK) return 1;
        std::cout << to_hex(ct.data(), olen) << "\n";
        return 0;
    }
    if (sub == "decrypt" && argc >= 2) {
        uint8_t seed[32];
        if (from_hex(argv[0], seed, 32) != 0) return 2;
        std::vector<uint8_t> ct(strlen(argv[1]) / 2);
        for (size_t i = 0; i < ct.size(); i++) {
            unsigned v; sscanf(argv[1] + 2 * i, "%2x", &v); ct[i] = (uint8_t)v;
        }
        std::vector<uint8_t> pt(ct.size() > 97 ? ct.size() - 97 : 1);
        size_t olen = 0;
        const act_status st = act_sm2_decrypt(ct.data(), ct.size(), seed,
                                              pt.data(), pt.size(), &olen);
        if (st != ACT_OK) {
            std::fprintf(stderr, "error: decrypt failed (%d)\n", st);
            return 1;
        }
        std::cout << to_hex(pt.data(), olen) << "\n";
        return 0;
    }
    std::fprintf(stderr, "unknown sm2 subcommand: %s\n", sub.c_str());
    return 2;
}

/* 本机机器码 (公钥+部署盐视角) —— shell/服务端集成拼图 */
int cmd_machine_code(int argc, char **argv)
{
    uint8_t pubkey[32], dsalt[32];
    uint32_t product_id = 1;
    uint8_t salt[128];
    size_t salt_len = 0;
    std::string pk_hex, ds_hex, salt_hex;

    for (int i = 0; i < argc; i++) {
        const std::string a = argv[i];
        if (a == "--pubkey" && i + 1 < argc) pk_hex = argv[++i];
        else if (a == "--dsalt" && i + 1 < argc) ds_hex = argv[++i];
        else if (a == "--product" && i + 1 < argc)
            product_id = (uint32_t)std::strtoul(argv[++i], nullptr, 0);
        else if (a == "--salt-hex" && i + 1 < argc) salt_hex = argv[++i];
        else if (a == "--json") { /* handled below */ }
    }
    if (from_hex(pk_hex, pubkey, 32) != 0 ||
        from_hex(ds_hex, dsalt, 32) != 0) {
        std::fprintf(stderr, "%s",
            TR("error: --pubkey and --dsalt must be 64 hex chars each\n"
               "       (both are printed by `keygen` / `export-pub`)\n",
               "错误: --pubkey 与 --dsalt 各需 64 位十六进制字符\n"
               "      (两者都由 `keygen` / `export-pub` 输出)\n"));
        return 2;
    }
    if (!salt_hex.empty()) {
        if (salt_hex.size() > sizeof(salt) * 2 ||
            from_hex(salt_hex, salt, salt_hex.size() / 2) != 0) {
            std::fprintf(stderr, "error: bad --salt-hex\n");
            return 2;
        }
        salt_len = salt_hex.size() / 2;
    }

    uint8_t mc[16];
    act_fingerprint(pubkey, dsalt, product_id, salt_len ? salt : NULL,
                    salt_len, mc);
    char str[ACT_MACHINE_CODE_STR_SIZE];
    act_fp_to_string(mc, str);
    std::cout << str << "\n"; /* stdout 仅机器码, 便于脚本捕获 */
    return 0;
}

int cmd_version()
{
    banner();
    if (g_zh) {
        std::printf("库版本 : %d.%d.%d\n", ACT_VERSION_MAJOR, ACT_VERSION_MINOR,
                    ACT_VERSION_PATCH);
        std::printf("格式   : 授权载荷 v%d (36 B) + ed25519; 令牌; 质询\n",
                    ACT_LICENSE_VERSION);
        std::printf("密码学 : sha512 + hmac + ed25519 + chacha20 + hkdf + pbkdf2\n"
                    "          sm3 + sm2 (GB/T 32918 国密)\n");
        std::printf("密钥库 : 支持口令加密 (ACTKEY2)\n");
        std::printf("界面   : --lang zh | en ($ACT_LANG / $LANG 自动探测)\n");
        std::printf("电报   : %s\n", ACT_TELEGRAM_CHANNEL);
    } else {
        std::printf("library : %d.%d.%d\n", ACT_VERSION_MAJOR, ACT_VERSION_MINOR,
                    ACT_VERSION_PATCH);
        std::printf("format  : payload v%d (36 B) + ed25519; tokens; challenges\n",
                    ACT_LICENSE_VERSION);
        std::printf("crypto  : sha512 + hmac + ed25519 + chacha20 + hkdf + pbkdf2\n"
                    "           sm3 + sm2 (GB/T 32918)\n");
        std::printf("keyfile : passphrase-encrypted (ACTKEY2) supported\n");
        std::printf("cli     : --lang zh | en ($ACT_LANG / $LANG auto-detect)\n");
        std::printf("telegram: %s\n", ACT_TELEGRAM_CHANNEL);
    }
    return 0;
}

void usage()
{
    banner();
    if (g_zh) {
        std::cout
            << "用法 (--lang zh | en 切换语言):\n"
            << "  engrail-keygen keygen     [--pass 口令] [secret.key]   生成密钥对\n"
            << "  engrail-keygen pubkey     [--pass 口令] [secret.key]   查看公钥\n"
            << "  engrail-keygen export-pub [--pass 口令] [key] deploy.pub  导出部署公钥\n"
            << "  engrail-keygen issue      [--pass 口令] [key] 签发授权码:\n"
            << "        --product N  --machine XXXXXXXXXXXXXXXX-XXXXXXXXXXXXXXXX\n"
            << "        [--days N | --perpetual] [--trial] [--features 0xMASK]\n"
            << "        [--serial HEX16]\n"
            << "  engrail-keygen issuefile  [--pass 口令] [key] in out    批量签发\n"
            << "  engrail-keygen inspect [--json] <code>                 离线查看授权码\n"
            << "  engrail-keygen revoke     [key] list.dat <序列号|码>   吊销\n"
            << "  engrail-keygen revokelist [key] list.dat               查看吊销名单\n"
            << "  engrail-keygen token sign/verify                       离线认证令牌\n"
            << "  engrail-keygen challenge / respond / verify            质询-应答\n"
            << "  engrail-keygen sm2 keygen|sign|verify|encrypt|decrypt  国密 SM2\n"
            << "  engrail-keygen machine-code --pubkey H --dsalt H [--product N]  本机机器码\n"
        << "  engrail-keygen version                                  版本信息\n"
            << "\n口令: --pass 值 或 环境变量 $ACT_PASSPHRASE (启用 ACTKEY2 加密密钥文件)\n"
            << "社区支持: " ACT_TELEGRAM_CHANNEL "  " ACT_TELEGRAM_URL "\n";
        return;
    }
    std::cout
        << "usage (--lang zh | en to switch language):\n"
        << "  engrail-keygen keygen     [--pass P] [secret.key]\n"
        << "  engrail-keygen pubkey     [--pass P] [secret.key]\n"
        << "  engrail-keygen export-pub [--pass P] [secret.key] deploy.pub\n"
        << "  engrail-keygen issue      [--pass P] [secret.key] --product N\n"
        << "          --machine XXXXXXXXXXXXXXXX-XXXXXXXXXXXXXXXX\n"
        << "          [--days N | --perpetual] [--trial] [--features 0xMASK]\n"
        << "          [--serial HEX16]\n"
        << "  engrail-keygen issuefile  [--pass P] [secret.key] in out [--days N]\n"
        << "  engrail-keygen inspect [--json] <code>\n"
        << "  engrail-keygen revoke     [--pass P] [secret.key] list.dat <serial|code>\n"
        << "  engrail-keygen revokelist [--pass P] [secret.key] list.dat\n"
        << "  engrail-keygen token sign     [--pass P] [key] --ttl N --payload T\n"
        << "  engrail-keygen token verify   deploy.pub <token>\n"
        << "  engrail-keygen challenge      --machine MC [--product N]\n"
        << "  engrail-keygen respond        [--pass P] [key] <challenge>\n"
        << "  engrail-keygen verify         deploy.pub <challenge> <response> --machine MC\n"
        << "  engrail-keygen sm2 keygen|sign|verify|encrypt|decrypt ...\n"
        << "  engrail-keygen machine-code --pubkey H --dsalt H [--product N]\n"
        << "  engrail-keygen version\n"
        << "\npassphrases: --pass VALUE or $ACT_PASSPHRASE "
           "(enables ACTKEY2 encrypted key files)\n"
        << "community / support: " ACT_TELEGRAM_CHANNEL "  " ACT_TELEGRAM_URL "\n";
}

} // namespace

int main(int argc, char **argv)
{
    /* --lang zh|en 全局选项: 从参数中摘除后再分发 */
    int lang_explicit = -1;
    int out_argc = 1;
    for (int i = 1; i < argc; i++) {
        const std::string a = argv[i];
        if (a == "--lang" && i + 1 < argc) {
            lang_explicit =
                (strncmp(argv[i + 1], "zh", 2) == 0) ? 1 : 0;
            i++; /* skip value */
            continue;
        }
        if (a.rfind("--lang=", 0) == 0) {
            lang_explicit = (a.find("zh") != std::string::npos) ? 1 : 0;
            continue;
        }
        argv[out_argc++] = argv[i];
    }
    argc = out_argc;

    if (lang_explicit >= 0) {
        g_zh = lang_explicit;
    } else {
        init_lang_from_env();
    }

    if (argc < 2) {
        usage();
        return 1;
    }
    const std::string cmd = argv[1];
    if (cmd == "keygen")     return cmd_keygen(argc - 2, argv + 2);
    if (cmd == "pubkey")     return cmd_pubkey(argc - 2, argv + 2);
    if (cmd == "export-pub") return cmd_export_pub(argc - 2, argv + 2);
    if (cmd == "issue")      return cmd_issue(argc - 2, argv + 2);
    if (cmd == "issuefile")  return cmd_issuefile(argc - 2, argv + 2);
    if (cmd == "inspect")    return cmd_inspect(argc - 2, argv + 2);
    if (cmd == "revoke")     return cmd_revoke(argc - 2, argv + 2);
    if (cmd == "revokelist") return cmd_revokelist(argc - 2, argv + 2);
    if (cmd == "token")      return cmd_token(argc - 2, argv + 2);
    if (cmd == "challenge")  return cmd_challenge(argc - 2, argv + 2);
    if (cmd == "respond")    return cmd_respond(argc - 2, argv + 2);
    if (cmd == "verify")     return cmd_verify(argc - 2, argv + 2);
    if (cmd == "sm2")          return cmd_sm2(argc - 2, argv + 2);
    if (cmd == "machine-code") return cmd_machine_code(argc - 2, argv + 2);
    if (cmd == "version")    return cmd_version();
    usage();
    return (cmd == "help" || cmd == "--help" || cmd == "-h") ? 0 : 1;
}
