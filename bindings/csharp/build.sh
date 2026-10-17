#!/bin/sh
# bindings/csharp/build.sh -- build the native shared library, then
# compile & run the C# demo.
#
# Requirements: a C compiler (always present in this repo's flow) plus
# the dotnet SDK (or mono's mcs). Missing dotnet => graceful skip.
#
# The binding targets netstandard2.0 -- works on .NET Framework 4.6.2+,
# .NET 6/7/8+, Unity (2018.4+ with .NET 4.x profile), and IL2CPP.

set -e
cd "$(dirname "$0")"

ROOT="../.."
CC="${CC:-cc}"

# Platform library name: DllImport("activation") resolves
# libactivation.so on Unix, activation.dll on Windows (B13).
case "$(uname -s 2>/dev/null || echo unknown)" in
    MINGW*|MSYS*|CYGWIN*)
        LIBNAME="activation.dll" ;;
    Darwin)
        LIBNAME="libactivation.dylib" ;;
    *)
        LIBNAME="libactivation.so" ;;
esac

echo "== native shared library ($LIBNAME) =="
mkdir -p build
"$CC" -O2 -std=c99 -fPIC -shared -I"$ROOT/include" \
      "$ROOT"/src/crypto/*.c "$ROOT"/src/core/kdf.c \
      "$ROOT"/src/core/fingerprint.c "$ROOT"/src/core/license.c \
      "$ROOT"/src/core/state.c "$ROOT"/src/core/token.c \
      -o "build/$LIBNAME"

if command -v dotnet >/dev/null 2>&1; then
    echo "== dotnet =="
    if [ ! -d build/cs ]; then
        dotnet new console -o build/cs --force >/dev/null
    fi
    # B10: the template's Program.cs (top-level statements) would win
    # the entry point and silently never run our Demo -> remove it.
    rm -f build/cs/Program.cs
    # B11: copy sources EVERY run so code changes take effect.
    cp Engrail.cs Demo.cs build/cs/
    # B9: Engrail.cs uses unsafe pointers; enable it in the csproj.
    if ! grep -q AllowUnsafeBlocks build/cs/*.csproj; then
        sed -i 's|</PropertyGroup>|  <AllowUnsafeBlocks>true</AllowUnsafeBlocks>\n  </PropertyGroup>|' \
            build/cs/*.csproj
    fi
    cd build/cs
    dotnet build -v q >/dev/null
    # B13: put the native lib where .NET probes for it (output dir).
    for d in bin/Debug/*/; do
        cp "../$LIBNAME" "$d" 2>/dev/null || true
    done
    dotnet run --no-build
elif command -v mcs >/dev/null 2>&1; then
    echo "== mono (mcs) =="
    mcs -out:build/demo.exe Engrail.cs Demo.cs
    LIBRARY_PATH=build:$LIBRARY_PATH \
        LD_LIBRARY_PATH=build:${LD_LIBRARY_PATH:-} mono build/demo.exe
else
    echo "csharp: SKIP (no dotnet SDK or mono found; binding source is"
    echo "        ready at bindings/csharp/Engrail.cs for any .NET project)"
fi
