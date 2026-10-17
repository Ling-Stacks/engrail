#!/bin/sh
# crypto/bench.sh -- standalone benchmark for the Engrail Crypto
# single-file library (same binary runs on x86 / ARM64 / anything C99).
#
# Usage:  sh crypto/bench.sh [cc] [--json]
#
# Results go to docs/BENCHMARKS.md -- paste actual output, never
# hand-edit numbers.

set -e
cd "$(dirname "$0")"

CC="${CC:-cc}"
JSON=""
for a in "$@"; do
    [ "$a" = "--json" ] && JSON="--json"
done
# first non-flag arg = compiler
for a in "$@"; do
    case "$a" in
        -*) ;;
        *) CC="$a"; break ;;
    esac
done

PY="${PYTHON:-python3}"
command -v "$PY" >/dev/null 2>&1 || PY=python
"$PY" tools/amalgamate.py dist
mkdir -p build
"$CC" -O2 -std=c99 -Wall -Wextra -Werror -Idist \
      dist/engrail_crypto.c bench/bench.c -o build/bench

./build/bench $JSON
