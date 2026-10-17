#!/usr/bin/env bash
#  bindings_test.sh -- unified smoke test for ALL language
#  bindings. Runs whichever toolchains are installed; skips
#  (and reports) the rest. Exit non-zero only on real FAILURES.
#
#    ./configure --enable-shared && make
#    bash scripts/bindings_test.sh        # or: make bindings
set -uo pipefail
cd "$(dirname "$0")/.."

PASS=(); SKIP=(); FAIL=()
record() { # name status(ok|skip|fail)
    case "$2" in
        ok)   PASS+=("$1") ;;
        skip) SKIP+=("$1") ;;
        *)    FAIL+=("$1"); FAILURES=1 ;;
    esac
}
FAILURES=0
export ACT_LANG=en

case "$(uname -s 2>/dev/null || echo unknown)" in
    MINGW*|MSYS*|CYGWIN*) ACTLIB="build/activation.dll" ;;
    Darwin*)              ACTLIB="build/libactivation.dylib" ;;
    *)                    ACTLIB="build/libactivation.so" ;;
esac
[ -f "$ACTLIB" ] || { ./configure --enable-shared >/dev/null && make >/dev/null; }

# Python
if command -v python3 >/dev/null 2>&1; then
    if ACTIVATION_LIB="$PWD/$ACTLIB" \
        python3 bindings/python/example.py >/dev/null 2>&1 &&
       ACTIVATION_LIB="$PWD/$ACTLIB" \
        PYTHONPATH=bindings/python python3 -m activation.enterprise >/dev/null 2>&1; then
        record python ok
    else
        record python fail
    fi
else
    record python skip
fi

# Shell
if bash bindings/shell/demo.sh >/dev/null 2>&1; then
    record shell ok
else
    record shell fail
fi

# Rust
if command -v cargo >/dev/null 2>&1; then
    if (cd bindings/rust && cargo test --release >/dev/null 2>&1 &&
        cargo run --release --example demo >/dev/null 2>&1); then
        record rust ok
    else
        record rust fail
    fi
else
    record rust skip
fi

# Java (JNI)
if command -v javac >/dev/null 2>&1 && command -v java >/dev/null 2>&1; then
    (
        cd bindings/java
        JH="$(dirname "$(dirname "$(readlink -f "$(which javac)")")")"
        # B4: platform JNI headers live in include/<os>; Windows JDKs
        # ship include/win32, not include/linux.
        JNI_OS="linux"
        [ -d "$JH/include/win32" ] && JNI_OS="win32"
        [ "$(uname -s 2>/dev/null)" = "Darwin" ] && JNI_OS="darwin"
        # B5: produce the name System.loadLibrary() actually probes.
        case "$(uname -s 2>/dev/null || echo unknown)" in
            MINGW*|MSYS*|CYGWIN*) JNI_LIB="activation_jni.dll" ;;
            Darwin)               JNI_LIB="libactivation_jni.dylib" ;;
            *)                    JNI_LIB="libactivation_jni.so" ;;
        esac
        javac Activation.java Demo.java \
              AbstractCrossPlatformOfflineLicenseVerificationAndSm2NationalCryptographyEnterpriseFacadeProviderFactoryBean.java 2>/dev/null &&
        cc -shared -fPIC -O2 -I"$JH/include" -I"$JH/include/$JNI_OS" \
           -I../../include native/ActivationJNI.c \
           ../../src/crypto/*.c ../../src/core/fingerprint.c \
           ../../src/core/kdf.c ../../src/core/license.c \
           ../../src/core/state.c -o "$JNI_LIB" 2>/dev/null &&
        java -Djava.library.path=. Demo >/dev/null 2>&1 &&
        java -Djava.library.path=. \
             AbstractCrossPlatformOfflineLicenseVerificationAndSm2NationalCryptographyEnterpriseFacadeProviderFactoryBean >/dev/null 2>&1
    )
    [ $? -eq 0 ] && record java ok || record java fail
else
    record java skip
fi

# Kotlin (needs kotlinc; reuses the Java JNI lib)
if command -v kotlinc >/dev/null 2>&1; then
    (
        cd bindings/java
        # B7: kotlinc only packs Kotlin classes into the jar; the Java
        # classes must come along via the classpath ('.'), with the
        # platform separator.
        case "$(uname -s 2>/dev/null || echo unknown)" in
            MINGW*|MSYS*|CYGWIN*) CPSEP=";" ;;
            *)                    CPSEP=":" ;;
        esac
        kotlinc ../kotlin/Demo.kt Activation.java -include-runtime \
                -d demo_kt.jar >/dev/null 2>&1 &&
        java -cp "demo_kt.jar$CPSEP." -Djava.library.path=. DemoKt >/dev/null 2>&1
    )
    [ $? -eq 0 ] && record kotlin ok || record kotlin fail
else
    record kotlin skip
fi

# C# (needs dotnet SDK or mono; binding itself is netstandard2.0)
if command -v dotnet >/dev/null 2>&1 || command -v mcs >/dev/null 2>&1; then
    # B10 lesson: exit code alone once reported a false green when the
    # template entry point replaced the demo -- require the demo's own
    # success marker in the output as well.
    OUT="$(cd bindings/csharp && sh build.sh 2>&1)" || OUT=""
    case "$OUT" in
        *"ALL DEMO CHECKS PASSED"*) record csharp ok ;;
        *"csharp: SKIP"*)           record csharp skip ;;
        *)                          echo "$OUT" | tail -5; record csharp fail ;;
    esac
else
    record csharp skip
fi

# WASM (needs emsdk; demo runs under node)
if command -v emcc >/dev/null 2>&1 && command -v node >/dev/null 2>&1; then
    if (cd bindings/wasm && sh build.sh >/dev/null 2>&1); then
        record wasm ok
    else
        record wasm fail
    fi
else
    record wasm skip
fi

# Standalone crypto distribution (pure C, always available)
if (cd crypto && sh build.sh >/dev/null 2>&1); then
    record crypto ok
else
    record crypto fail
fi

# report
echo
echo "================ BINDINGS SMOKE TEST ================"
for n in ${PASS[@]+"${PASS[@]}"}; do echo "  [PASS] $n"; done
for n in ${SKIP[@]+"${SKIP[@]}"}; do echo "  [SKIP] $n (toolchain not installed)"; done
for n in ${FAIL[@]+"${FAIL[@]}"};  do echo "  [FAIL] $n"; done
echo "======================================================"
if [ "$FAILURES" -ne 0 ]; then
    echo "FAILURES detected"
    exit 1
fi
echo "all available bindings healthy"
