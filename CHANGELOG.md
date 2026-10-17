# Changelog

All notable changes to Engrail are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/); versions follow semver.

## [1.7.2] — 2026-10

### Fixed — cross-platform build (field report R3, Linux GCC 15 / Windows MinGW)
- Strict `-std=c99` hid POSIX/glibc declarations (`syscall`, `readlink`,
  `fchmod`, `fileno`, `sysctl`) — L1/L2/L4. Root fix: configure now
  prefers `-std=gnu99` (c99 fallback), plus a platform feature-macro
  prelude (`_GNU_SOURCE` / `_DARWIN_C_SOURCE` / `_DEFAULT_SOURCE`) at
  the top of random.c/harden.c/state.c/keyfile.c and in both
  amalgamation generators, so user builds under strict C99 also work.
- MinGW: `NT_SUCCESS` fallback define (W1); `BCryptGenRandom` resolved
  dynamically via LoadLibrary/GetProcAddress — zero link-time
  dependency on bcrypt/advapi32 across Makefile, CMake, Rust, C#, Java
  and the standalone scripts (W2/B3/B8/C4 at the root).
- e2e: `CXX` default + Makefile passes the configured compiler (W4);
  executable paths handed to native Windows tools carry `$EXESUF`
  (W3).
- engrail-integrity: `std::sprintf` replaced with `std::snprintf` —
  recent macOS SDKs deprecate sprintf and the `-Werror` build
  rejected it.
- GCC 15/16 warning hygiene: tests/common.h self-contained `<stdint.h>`
  (L5); test_fuzz output buffer zero-init (L6); keygen UTC buffer 64B
  (L7).
- test_license challenge tamper is now deterministically valid
  base64url (L8: `^= 1` could produce an illegal char and fail the
  assertion probabilistically with ACT_ERR_FORMAT).

### Fixed — configure / build system
- GCC-compatibility probe was inverted (plain -E expands `__GNUC__`);
  now uses `-E -dM` (C1).
- Function-declaration probes used `(int)(long)fn`, a pointer-to-int
  truncation on Win64/LLP64; now `(int)(intptr_t)fn` (C2).
- EXEEXT detection: MSYS2 `[ -f exe ]` matches exe.exe; the suffix is
  now decided by toolchain family and verified (C12).
- Shared-library suffix is platform-derived (.so/.dll/.dylib) instead
  of a hardcoded `.so` for a PE DLL (C5).
- CMake minimum 3.13 (matches `target_link_options` usage, C3).
- `-static-libstdc++` is no longer passed on macOS: Apple clang treats
  it as an unused argument and, under `-Werror`, that warning killed
  both the configure C++17 probe and every generated-Makefile C++ link.
- MSVC (`--cc=cl`): the GNU-style warning-clean C99 probe degrades to
  a warning instead of aborting configure — the MSVC build path is the
  generated CMakeLists, not the GNU-flag Makefile.
- tests/run_all.sh fallback build: `CC` default, `EXESUF`, and link
  flags sourced from config.vars (C10).
- crypto/build.sh & bench.sh: robust Python resolution (C9);
  amalgamation written with LF newlines on all platforms (C11).
- amalgamation scripts (`scripts/make_amalgamation.py`,
  `crypto/tools/amalgamate.py`) now refuse output directories outside
  the project tree, closing a path-traversal on the `distdir` argument.
- engrail-bench banner rebranded to Engrail.

### Fixed — language bindings (field-report B1..B15)
- Python: package-to-repo path now three dirname levels — the documented
  run flow actually finds the shared library (B1).
- Rust: vendored amalgamation regenerated from v1.7.1 sources (was a
  stale 1.3/1.4 artifact missing the MinGW compat), crate version
  aligned (B2).
- Kotlin: removed import of a nonexistent package (B6); classpath
  includes `.` with the platform separator (B7).
- C#: AllowUnsafeBlocks enabled in the generated project (B9); template
  Program.cs removed so the demo really runs (B10); sources copied on
  every build (B11); machine-code assertion fixed (B12); native library
  named per platform and placed in the .NET output dir (B13).
- WASM: EXPORTED_FUNCTIONS single-line (backslash-continuation inside
  single quotes broke emcc, B14); JS wrapper NUL-terminates allocations
  passed to `const char *` APIs (B15 — an out-of-bounds read).
- bindings_test.sh: Java uses the JDK's platform JNI headers and emits
  the library name `System.loadLibrary` probes (B4/B5); C# is verified
  by the demo's success marker, not exit code alone (B10 lesson).

### Changed — CI
- windows-mingw job now runs the full matrix (check, e2e, crypto,
  CLI regression) instead of stopping after six test binaries (C8).
- windows-msvc no longer swallows build failures with `|| echo` (C8).
- macos additionally builds the standalone crypto suite.

### Changed — tool binaries renamed to the project name
- `activation-keygen` -> `engrail-keygen`,
  `activation-integrity` -> `engrail-integrity`,
  `activation-bench` -> `engrail-bench` (Makefile, CMake, scripts,
  docs, usage text). The library file keeps its `libactivation` name:
  it is the link/ABI surface referenced by pkg-config, all eight
  bindings and the amalgamation.

### Fixed — field verification of v1.7.2 (Windows/MSYS2 GCC 16.1)
- R1 (release blocker): the restructured CSPRNG left the `health_check`
  label unreferenced in the Windows branch — `-Werror=unused-label`
  broke configure/make/crypto scripts on MinGW. The Windows path now
  jumps to the label explicitly.
- R2: the Python binding and bindings_test.sh still looked for
  `libactivation.so` everywhere while configure now emits
  `activation.dll` / `libactivation.dylib` — both resolve the library
  name per platform now (`import sys` included).
- CI: windows-mingw job additionally runs `make bindings` (R2 was
  invisible without it).

### Added
- `scripts/make_package.sh`: single staging tree for tar.gz + zip with
  identical, verified file lists and strict artifact exclusion (C6/C7).
- docs/BENCHMARKS.md: measured x86-64 (WSL GCC 15.2 / MSYS2 GCC 16.1)
  and WASM (emscripten 3.1.69) tables recorded from the field report.

## [1.7.1] — 2026-10

### Security / correctness (external code review round 2)
- keygen: `--pass VALUE` pairs are now REMOVED from the argument list
  before positional parsing (previously the passphrase value was
  consumed as the first positional path — `keygen --pass s3cret
  out.key` wrote the private key to a file named `s3cret`, leaking the
  passphrase as a filesystem path). All nine passphrase-consuming
  subcommands fixed; `--pass=VALUE` form also accepted; `--pass`
  without a value is now a hard error.
- keygen: encrypted (ACTKEY2) key files without a supplied passphrase
  now offer an echo-off interactive prompt on a TTY (termios /
  SetConsoleMode); pipes and CI behavior unchanged.
- engrail-integrity patch: patches a temp copy and atomically
  renames it over the original — an interrupted patch can no longer
  leave a permanently broken binary (R2/BUG-7).

### Fixed
- issuefile: `--product/--features/--trial/--perpetual` now forwarded
  (was hardcoded to product 1, features 0).
- keygen banner and crack_me branding updated to Engrail.
- C# build script: stray `DOTNET_GCHeapHardLimit=1` removed.
- README language count corrected to nine.

### Added
- Release artifacts now include `engrail-crypto.tar.gz` (the standalone
  single-file crypto library) alongside the amalgamation.

## [1.7.0] — 2026-10

### Added
- **`crypto/` — standalone single-file crypto library** (`engrail_crypto.{h,c}`):
  SM2/SM3/Ed25519/SHA-512/HMAC/HKDF/PBKDF2/ChaCha20 in one translation
  unit, zero dependencies, usable entirely without the licensing layer.
  Own conformance suite (official vectors) via `crypto/build.sh`.
- **Standalone benchmark suite**: `crypto/bench.sh` (native, fixed
  iterations, `--json` mode) and `bindings/wasm/bench.mjs` (wasm);
  methodology + measured numbers in `docs/BENCHMARKS.md` (ARM64 data
  in, x86/WASM columns reserved for measured submissions).
- **C# binding** (`bindings/csharp/`): single-file netstandard2.0 P/Invoke
  wrapper (works on .NET 6+, .NET Framework 4.6.2+, Unity); full
  vendor-issue -> activate -> verify demo.
- **WebAssembly binding** (`bindings/wasm/`): emcc build of the crypto
  suite + license engine, clean ES-module wrapper, node demo and an
  in-browser demo page; verification fully client-side, zero network.
- **Integration manual** (`docs/INTEGRATION.md`): complete docking guide
  (Chinese) — build modes, full CLI reference, API tables, error codes,
  hardening deployment, per-language binding quick reference, FAQ.
- `bindings_test.sh` now covers C# and WASM (graceful skip without
  dotnet/emsdk) and the standalone crypto suite.

### Changed
- CI expanded: standalone-crypto matrix (Linux/macOS/MinGW), WASM job
  in the emsdk container (build + demo + benchmark), C# job with the
  dotnet SDK; native jobs unchanged.
- CONTRIBUTING.md rewritten for the v1.7 layout (crypto/, 8 bindings,
  benchmark policy, bilingual docs policy).
- ADVERSARIAL.md finalized (v1.7.0): integrity slot size corrected to
  99 bytes, WASM/browser attack surface documented (§3.5), weakness
  list extended, doc frozen with revision policy.
- README.md is now English-only (the front page); Chinese lives in
  README_zh.md; README_en.md removed.
- version bump to 1.7.0.

## [1.6.1] — 2026-10

### Security / correctness (external code review round 1)
- keyfile.c / state.c: files are now created 0600 via explicit fchmod
  (the previous umask-after-fopen had no effect; key/state files could
  land 0644 under a default umask).
- sm2.c: `act_sm2_decrypt` validates C1 on the curve before any scalar
  multiplication (GB/T 32918.4 input validation).
- sm2.c: module initialization is now thread-safe (C11 atomics /
  GCC __atomic / MSVC intrinsics / benign-volatile fallback).
- New error code `ACT_ERR_ENTROPY` (-15): CSPRNG failures in SM2
  sign/encrypt no longer masquerade as state-I/O errors.
- `act_days_remaining` returns `INT64_MAX` for perpetual licenses
  (0 previously collided with "expired"); C++ side mirrored.
- C++ `Verifier::verify_saved(path, revocation_path)` and
  `verify_hardened()` implemented (were declared but missing).
- license verification order is now format -> version -> **signature**
  -> product -> machine -> expiry, matching the documented no-oracle
  property; regression test added.
- kdf.c dead variable removed; audit.c formatting fixed.

### Docs
- ADVERSARIAL.md: `USER` env-var weakness documented honestly (no
  privilege needed); stale PTRACE_TRACEME reference removed (probe was
  dropped in 1.5); forged-slot-append bypass path added to 3.2.
- ed25519.c: TweetNaCl provenance note added; WEBSITE_COPY.md claim
  corrected (7 independent primitives + hardened TweetNaCl port).

## [1.6.0] — 2026-10

### Project renamed
- **ActivationSystem -> Engrail** ("interlocking offline licensing",
  evoking dovetail joints -- crypto primitives that interlock).

### Added
- 4-platform CI matrix: Ubuntu, macOS, Windows/MinGW (full test suite),
  Windows/MSVC (core library compilation).
- Release workflow: tag `v*` publishes amalgamation tarball to GitHub
  Releases with auto-generated notes.
- `docs/ANDROID.md`: NDK standalone + Gradle/CMake + amalgamation +
  JNI/Kotlin integration recipes (the project is developed on Android).
- `docs/WINDOWS.md`: MSYS2/MinGW and MSVC paths, preprocessor branch
  reference table.
- configure: OS-name display with per-platform flavor text; Android
  vs Linux triple-discrimination (`uname -o` / `/system/build.prop` /
  `/system/app + /system/priv-app`).

### Changed
- All decorative `====`/`----` separator comments removed project-wide
  (151+ lines); section titles retained as plain text.
- Minimal-text configure banner (no ASCII art, no emoji): system name,
  arch, kernel, one-line flavor.

## [1.5.2] — 2026-10

### Added — configure sanity suite + post-build self-test
- **configure environment checks** (11 probes, fail-closed): core
  tools, C compiler actually builds AND runs, C99 headers under
  -Werror, C++17 with static runtime, all 27 project sources present
  (incomplete-checkout detection), version.h parseable, python3,
  archiver produces archives, shared-library support (with
  --enable-shared), writable build dir. Missing optional pieces
  downgrade to WARN; broken toolchains abort with a fix hint.
- **Post-build smoke test** (`tests/smoke.c`, 12 checks, <1s):
  version coherence, SHA-512/SM3 known answers, Ed25519 + SM2
  sign/verify, CSPRNG, fingerprint, license round-trip, keyfile
  encryption round-trip. `make` runs it automatically after every
  build and FAILS the build on regression (opt out: NO_SMOKETEST=1;
  manual: make smoke / full: make check).

## [1.5.1] — 2026-10

### Added — enterprise test system
- **10 test suites / 207 check cases** (`make check`, `tests/run_all.sh`
  with a pass/fail matrix):
  - `test_random` (new): CSPRNG quality — uniqueness, degenerate-output
    rejection, 64KiB byte-frequency bounds, serial correlation
  - `test_kdf` (new): HKDF-SHA512 vectors (independent-Python frozen),
    PBKDF2 vectors (hashlib), ChaCha20 RFC 8439 2.4.2 sunscreen vector
  - `test_dual` (new): 31 cases — dual-stack determinism, info
    diversification, cross-stack non-confusion, full vendor story
  - `test_harden` (new): self-integrity state machine
    (fresh/patched/modified/absent) + 512-corruption negative control
  - `test_fuzz` (new): deterministic 24k-input fuzz across 5 parser
    surfaces (license/token/challenge/sm2-decrypt/keyfile) — random,
    mutation and hostile-length phases
  - `test_lifecycle` (new): 3 products x 3 machines matrix, cross-cell
    rejection, feature tiers, trial->paid upgrade, expiry boundary
    semantics, revocation isolation, renewal, audit-chain tamper
  - shared framework `tests/common.h` (check macros, hex fixtures,
    seeded xorshift PRNG), frozen vectors in `tests/vectors_kdf.h`

## [1.5.0] — 2026-10

### Added
- **Dual-stack keys**: one Ed25519 seed derives both key pairs
  (`act_sm2_keypair_from_ed25519_seed`) — single offline backup covers
  Ed25519 + SM2 (dual-compliance: GB/T markets + global). Deterministic,
  purpose-diversifiable via `info`.
- **Chained audit log** (`audit.h`): HMAC-chained, tamper-evident,
  append-only licensing event trail (ISO 27001 A.12.4 / SOC 2 CC7.2);
  any edit, delete or reorder breaks the chain.
- **`examples/crack_me.c`**: five-gate hardened reverse-engineering
  challenge (Ed25519 gate + machine binding + anti-debug + patched
  self-integrity + negative-control verifier check) — machine-bound
  FLAG, write-ups welcome.
- **`ADVERSARIAL.md`**: full attack/defense model write-up (threat
  levels L0–L5, defense matrix, honest weaknesses list) — reference
  material for security researchers.
- **CSPRNG hardened**: getrandom(2) syscall first (no fd dependency,
  sandbox/chroot-safe), EINTR/short-read retries, /dev/urandom
  fallback, degenerate-output health check, fail-closed throughout.
- `examples/c_api_demo.c` (pure C), `examples/python_bindings.py`
  (ctypes), `tools/bench` performance reference, `inspect --json`,
  bilingual CLI (`--lang zh|en`).
- `machine-code` CLI subcommand (script ecosystem).

### Fixed
- Self-integrity: window-slide offset bug (offsets drifted by
  keep-size per buffer refill); now whole-file read with in-memory
  slot zeroing — obviously correct.
- Self-integrity: fresh slots carry a 0xAA fingerprint so .rodata
  padding can never masquerade as a slot; all fresh slots get the
  same digest when patching (macro + literal copies stay consistent).
- Anti-debug: removed the PTRACE_TRACEME self-probe — it left the
  process traced by its parent and hung applications at exit;
  TracerPid is now the sole Linux/Android probe.
- ACT_INTEGRITY_SLOT now compiles as C++ (explicit byte list).

### Design decisions (documented in ADVERSARIAL.md)
- Ed25519+SM2 "cross encryption" evaluated and REJECTED: different
  curves share no secure key mapping; layering ECC-KEM over ECC-KEM
  adds attack surface, not security. Dual SIGNING + unified seed
  derivation adopted instead (real dual-compliance value).

## [1.4.0] — 2026-10

### Added
- **configure build system**: `./configure` generates Makefile and
  CMakeLists.txt from fully-variable templates (Makefile.in /
  CMakeLists.txt.in) — no fixed constants; `clean.sh` resets them.
  Flags: `--prefix --cc --cxx --cflags --cxxflags --ldflags
  --enable-shared --disable-{tests,tools,examples,bench}`.
- **Five language bindings** (`bindings/`), all over the pure-C ABI:
  - Python: ctypes package + example (no build system needed)
  - Rust: zero-dependency crate (build.rs compiles the vendored core
    with the system $CC — no cc crate, no network)
  - Shell: source-able function library + end-to-end demo
  - Java: JNI glue (Activation.java + ActivationJNI.c), Android-ready
  - Kotlin: rides the same JNI library, idiomatic demo
- `make bindings` / `scripts/bindings_test.sh`: unified binding smoke
  test (runs whichever toolchains are installed).
- CLI: `machine-code --pubkey --dsalt [--product]` (script ecosystem).
- Shared library now builds pure-C only (no C++ runtime dependency) —
  dlopen-friendly for every binding.
- Convenience APIs: `days_remaining`, `has_feature`, `is_trial`.

## [1.3.0] — 2026-10

### Added
- **SM2 complete implementation (GB/T 32918)** — key pairs, digital
  signatures (Z_A, custom IDs), public-key encryption (C1C3C2 + KDF),
  over sm2p256v1 with runtime-derived Montgomery constants.
- **SM3 hash (GB/T 32905-2016)** — standard vectors frozen in tests.
- CLI `sm2 keygen|sign|verify|encrypt|decrypt` subcommands.
- C++ `act::sm2` namespace.
- Convenience APIs: `act_days_remaining()`, `act_has_feature()`,
  `LicenseInfo::days_remaining/has_feature/is_trial`.
- `examples/c_api_demo.c` — pure-C integration walkthrough.
- `examples/python_bindings.py` — ctypes bindings (no build system).
- `tools/bench` — indicative performance reference.
- `inspect --json` machine-readable metadata output.
- Bilingual READMEs (`README_zh.md` / `README_en.md`) + nav page.

### Security
- SM2/SM3 cross-validated bidirectionally against an independent
  reference implementation (sign ↔ verify, encrypt ↔ decrypt).

## [1.2.0] — 2026-10

### Added
- **Offline authentication mode**: signed tokens (TTL, arbitrary
  payload) and challenge-response with anti-replay.
- **Key non-replicability model**: per-deployment random salt (dsalt),
  all runtime keys derived via HKDF-SHA512; fingerprint cascade v2.
- **ACTKEY2 passphrase-encrypted vendor key files**
  (PBKDF2-HMAC-SHA512 ×200k + ChaCha20 + HMAC-SHA512, EtM).
- ChaCha20 (RFC 8439), HKDF (RFC 5869), PBKDF2 (RFC 8018) primitives.
- CLI: `export-pub`, `token sign/verify`, `challenge/respond/verify`,
  `--pass` passphrase support throughout.

## [1.1.0] — 2026-10

### Added
- License format v2: 8-byte serials, 16-bit feature mask, trial flag.
- **Vendor-signed revocation lists** (`revoke`/`revokelist`).
- **Hardening module**: anti-debug probing, executable self-integrity
  (`engrail-integrity patch/check`), redundant verification with
  negative controls.
- Single-file amalgamation (`make amalgamation` → `dist/`).
- CMake build + CTest; `make install` + pkg-config.
- `inspect` offline code viewer; batch issuance (`issuefile`).

## [1.0.0] — 2026-10

### Added
- Ed25519 (RFC 8032), SHA-512 (FIPS 180-4), HMAC-SHA512 (RFC 4231) —
  all from scratch, official vectors in tests.
- Activation codes: 36-byte signed payload, Crockford Base32 wire
  format, machine-bound, expiry/perpetual.
- Machine fingerprints: 3-round keyed cascade over platform sources.
- Signed local state store; constant-time comparisons throughout.
- Vendor CLI (`engrail-keygen`), example app, 14-step e2e demo.
- MIT license, CI matrix, Telegram community [@Stack_Traces].
