#!/bin/sh
# crypto/build.sh -- regenerate + build + test the standalone
# Engrail Crypto distribution (two-file drop-in, zero dependencies).
#
# Usage:  sh crypto/build.sh [cc]
# Out:    crypto/dist/engrail_crypto.{h,c}  +  crypto/build/vectors

set -e
cd "$(dirname "$0")"

CC="${1:-${CC:-cc}}"
PY="${PYTHON:-python3}"
command -v "$PY" >/dev/null 2>&1 || PY=python
command -v "$PY" >/dev/null 2>&1 || PY=python3

echo "== regenerating amalgamation =="
"$PY" tools/amalgamate.py dist

echo
echo "== compiling standalone (single TU, -Wall -Wextra -Werror) =="
mkdir -p build
"$CC" -O2 -std=c99 -Wall -Wextra -Werror -Idist \
      dist/engrail_crypto.c test/vectors.c -o build/vectors

echo
echo "== conformance vectors =="
./build/vectors
