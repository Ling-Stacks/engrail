# Engrail

**Offline licensing engine + standalone modern-crypto toolkit. Pure C and C++. Zero dependencies. MIT.**

Embed the public key in your app, sign activation codes with your private key — forging a code that passes verification reduces (in the random-oracle model) to the elliptic-curve discrete logarithm problem. The SM2/SM3/Ed25519 stack ships as an independent single-file crypto library you can take on its own, licensing entirely optional.

Runs on Linux, macOS, Windows, Android — and in the browser via WebAssembly.

[简体中文](README_zh.md) · [Integration manual 对接手册](docs/INTEGRATION.md)

---

## Why You'd Star This

### One C file holds the whole national-crypto + modern-crypto stack

`engrail_crypto.c` is a single translation unit containing SM2 signing, SM2 public-key encryption (C1C3C2), SM3, Ed25519, SHA-512, HMAC, HKDF, PBKDF2, ChaCha20 and a fail-closed OS CSPRNG interface. Copy two files into any C99 project and you are done — no configure, no submodules, no OpenSSL, no runtime. Cross-compiles to embedded targets, NDK, MinGW, MSVC and wasm without a single `#ifdef` on your side.

### Chinese national crypto in the browser

The WebAssembly build runs SM2/SM3/Ed25519 and full license verification client-side, in WebAssembly, with zero network calls, zero dependencies and zero CDN. Front-end signature verification without a backend — until now you basically could not do this with GB/T 32918 implementations.

### Nine languages, one ABI

C, C++, Python, Rust, Java, Kotlin, C# (Unity included), Shell, JavaScript/WASM all bind the *same* pure-C core. Nothing rewritten, nothing transliterated, no separate implementations drifting apart — a signature verified in Rust matches one minted in Java matches one checked in the browser. One test suite covers every language.

### Cryptographically correct, independently verified

Every primitive passes its official test vectors: FIPS 180-4 (SHA-512), RFC 4231 (HMAC), RFC 5869 (HKDF), RFC 8018 (PBKDF2), RFC 8032 (Ed25519), RFC 8439 (ChaCha20), GB/T 32905 (SM3), GB/T 32918 (SM2). Beyond that, SM2/SM3 were cross-validated *bidirectionally* against an independent Python implementation: C-signed signatures verified by Python, Python-encrypted ciphertexts decrypted by C. Bit-flip fuzzing exhausts all 512 signature bits and all 288 payload bits.

### Full source disclosure doesn't leak anything

There is not a single secret constant in the codebase. Every runtime key derives per-deployment via a three-round HKDF cascade over the deployment salt (dsalt): same source, same machine, two deployments — completely different machine codes. Publishing your fork, losing your templates, shipping debug builds: none of it replicates your keys. The only thing that matters stays offline: your Ed25519 seed.

### Anti-reversing that assumes the attacker reads the source

Three independent, stackable layers:

1. **Debugger probes** — TracerPid on Linux/Android, P_TRACED on macOS, IsDebuggerPresent on Windows
2. **Executable self-integrity** — a 99-byte slot patched with the whole-file SHA-512 at release time; recomputed and compared at every startup. Patch the binary, the digest breaks.
3. **Negative-control redundant verification** — the hardened path deliberately feeds a known-bad signature and asserts the verifier *rejects* it. If someone NOP'd your checks, the negative control fires. Cheap to deploy, genuinely annoying to bypass.

### Entropy that fails closed

Keys come straight from `getrandom(2)` / `ProcessPrng`, with degenerate-output health checks (all-zero / all-FF detection). If the CSPRNG is broken the library aborts — it never silently degrades to weak randomness that would hand every key to an attacker.

### Licensing that's actually honest about its threat model

[ADVERSARIAL.md](ADVERSARIAL.md) documents every attack path that works, including the ones against ourselves — what root can fake, what a patched binary can skip, where the economics sit. Security tooling that claims to be unbreakable is marketing; this repo ships the attack/defense spreadsheet instead.

---

## What the Licensing Side Gives You

- **Machine binding** — 16-byte fingerprint from a three-round HKDF cascade over platform identifiers; a code issued for machine A is worthless on machine B
- **Timed / perpetual / trial / feature-tier codes** — 16-bit feature masks, expiry anchored to 2020-01-01 UTC, one flag field
- **Signed revocation lists** — refund or leak handling: sign a serial blacklist, ship it with updates, clients verify it against your public key. Users cannot delete their serial
- **Offline auth tokens** — Ed25519-signed Base64URL tokens with TTL for entitlement delivery; plus challenge-response (anti-replay) for one-shot offline grants
- **Hardened state storage** — activation state files carry your vendor signature; edit one byte and verification fails
- **Encrypted vendor key files** — passphrase-encrypted at rest (PBKDF2 × 200,000 + ChaCha20 + HMAC, encrypt-then-MAC)
- **Chained HMAC audit log** — tamper-evident event trail for compliance-sensitive deployments

---

## Quick Start

```bash
./configure
make
make test
```

Requires a C99 and a C++17 compiler. Nothing else. The configure step runs 94 environment checks and generates both `Makefile` and `CMakeLists.txt` from fully-variable templates.

## Usage

Vendor side (your machine):

```bash
./build/engrail-keygen keygen vendor.key    # once; keep offline
./build/engrail-keygen issue vendor.key \
    --product 1 \
    --machine F8BDE075F9DE40A3-D54D62B64E4D68AC \
    --days 365
```

Application side (inside your product):

```cpp
#include "activation/activation.hpp"

static const uint8_t PUBKEY[32] = { /* printed by keygen */ };
static const uint8_t DSALT[32]  = { /* printed by keygen */ };

act::Verifier verifier(PUBKEY, DSALT, 1);

verifier.activate(code, "app.act");   // user enters the code once

if (verifier.verify_saved("app.act") == act::Status::Ok) {
    // licensed — re-check on every startup
}
```

Want the crypto without the licensing? Copy two files:

```bash
sh crypto/build.sh    # generates crypto/dist/engrail_crypto.{h,c} + runs vectors
```

Step-by-step for every language and platform: **[Integration manual](docs/INTEGRATION.md)** — build modes, full CLI reference, API tables, error codes, hardening deployment, FAQ.

## Integration

| Method | Best for |
| --- | --- |
| Two files (`crypto/dist/engrail_crypto.{h,c}`) | crypto primitives only |
| Two files (`dist/activation.{h,c}`) | licensing + crypto |
| CMake subdirectory | existing CMake projects |
| `make install` + pkg-config | system-wide install |
| `bindings/` — 8 language bindings | Python, Rust, Java, Kotlin, C#, Shell, JS/WASM |

## Documentation

- [Integration manual (Chinese)](docs/INTEGRATION.md) — the complete docking guide
- [Standalone crypto library](crypto/README.md)
- [Benchmarks](docs/BENCHMARKS.md) — x86 / ARM64 / WASM methodology and numbers
- [Android integration](docs/ANDROID.md) · [Windows build](docs/WINDOWS.md)
- [Adversarial analysis](ADVERSARIAL.md) — for security researchers
- [Changelog](CHANGELOG.md)

## Testing

```bash
make check      # 10 test suites, 207+ cases
make e2e        # 14-step end-to-end demo
make bindings   # every available language binding + standalone vectors
crypto/build.sh # standalone conformance vectors
```

## Community

Questions, requests, updates: [t.me/Stack_Traces](https://t.me/Stack_Traces)

## License

MIT — see [LICENSE](LICENSE). The Ed25519 field arithmetic is a hardened port of TweetNaCl (public domain) — canonicalization checks, constant-time comparison finish, key wiping added; every other primitive is an independent implementation.
