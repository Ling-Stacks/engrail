# Contributing to Engrail

Thanks for your interest in improving Engrail!

## Ways to contribute

- **Bug reports** — open an issue with: platform, compiler, commit, minimal repro.
- **Crypto correctness** — if you find a discrepancy against a standard
  (FIPS 180-4, RFC 4231/5869/8018/8032/8439, GB/T 32905/32918), that is a
  **security-graded** report — see SECURITY.md.
- **Ports & builds** — CI covers Linux / macOS / MinGW / MSVC / WASM /
  C#; help with embedded toolchains, iOS, exotic platforms is welcome.
- **Bindings** — new languages should bind the existing C ABI
  (`include/activation/`); never reimplement the crypto. See
  `bindings/` for the eight existing patterns (ctypes / P-Invoke /
  JNI / wasm).
- **Docs & examples** — integration recipes for real-world frameworks
  (Qt, Unreal, Android JNI, iOS, Flutter FFI...) benefit everyone.
  The integration manual (`docs/INTEGRATION.md`) is the hub.
- **Performance** — portable speedups only; no intrinsics that break
  portability unless runtime-dispatched.

## Repository layout (what lives where)

| Path | Contents |
| --- | --- |
| `src/crypto/` | primitives (SHA-512, HMAC, Ed25519, SM2, SM3, ChaCha20, CSPRNG) |
| `src/core/` | licensing logic, fingerprint, state, tokens, hardening, audit |
| `include/activation/` | public C API + C++17 wrapper (frozen ABI surface) |
| `crypto/` | standalone single-file crypto distribution + its own vectors/bench |
| `bindings/` | python, rust, shell, java, kotlin, csharp, wasm |
| `tests/` | 10 suites + smoke + e2e drivers |
| `tools/` | keygen CLI, integrity patcher, bench |
| `docs/` | INTEGRATION (对接手册), ANDROID, WINDOWS, BENCHMARKS |

## Development ground rules

1. **No third-party dependencies.** The whole point. Everything is
   implemented in-repo: C99 core + C++17 wrapper.
2. **Standards-exact.** Crypto code follows the published
   specifications; no "simplified" variants. Any change to a crypto
   primitive must be validated against official test vectors or an
   independent reference implementation, in both directions.
3. **Zero warnings.** `make` compiles with `-Wall -Wextra -Werror`
   (C and C++). `crypto/build.sh` holds the standalone build to the
   same bar.
4. **Tests mandatory.** New features need tests in `tests/` (and
   `crypto/test/` when they touch the standalone distribution).
5. **API stability.** `include/activation/` is the public surface;
   breaking changes need a version bump and a CHANGELOG entry. Error
   codes are stable ABI — append at the tail, never renumber.
6. **Comments explain *why*.** Reference the spec/theorem/attack that
   motivates non-obvious code. Provenance notes (e.g. TweetNaCl
   lineage in ed25519.c) must be preserved.
7. **Style**: no emoji, no decorative `====`/`----` separator comments,
   CLI output bilingual (`--lang zh|en`) with `--json` staying
   machine-readable.
8. **Docs are bilingual by role**: `README.md` is English (the front
   page), `README_zh.md` is Chinese, `docs/INTEGRATION.md` is the
   Chinese integration manual. User-facing changes update both
   readmes.

## Benchmark policy

`docs/BENCHMARKS.md` numbers are **measured, never hand-edited**.
Run `sh crypto/bench.sh` (native) or `node bindings/wasm/bench.mjs`
(wasm) and paste actual output with the environment (CPU / compiler /
version). Fixed iteration counts — don't tune counts per machine.

## Pull request checklist

- [ ] `make check` green (all 10 suites)
- [ ] `make e2e` green (14-step end-to-end)
- [ ] `make bindings` green (all available language bindings)
- [ ] `sh crypto/build.sh` green when crypto/ or src/crypto/ changed
- [ ] `make amalgamation` still builds as both C and C++
- [ ] No new warnings with the project flags
- [ ] Docs updated (README / README_zh / INTEGRATION when user-facing)
- [ ] CHANGELOG.md entry under *Unreleased* or the current version

## Commit style

Conventional-ish, present tense:

```
feat(license): add transfer codes
fix(sm2): validate C1 on curve before decryption
docs(readme): document pkg-config flow
test(e2e): cover revocation at startup
bench(crypto): bump ed25519 sign iterations
```

## CI

`.github/workflows/ci.yml` runs on every push/PR: full suite on Linux
and macOS, core tests on MinGW, core build on MSVC, the standalone
crypto distribution on Linux/macOS/MinGW, the WASM build in the
emsdk container, and the C# binding with the dotnet SDK. Releases are
tag-driven (`release.yml`).

## Community

Questions, requests and announcements live on Telegram:
**[@Stack_Traces](https://t.me/Stack_Traces)**.
