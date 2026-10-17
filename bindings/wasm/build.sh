#!/bin/sh
# bindings/wasm/build.sh -- compile Engrail (crypto suite + license
# engine) to WebAssembly with Emscripten, then run the node demo.
#
# Requirements: emsdk (emcc) on PATH; node >= 18 for the demo.
# Output: dist/engrail_wasm.js + dist/engrail_wasm.wasm
#
# No emcc? The binding is skipped gracefully -- see scripts/bindings_test.sh

set -e
cd "$(dirname "$0")"

if ! command -v emcc >/dev/null 2>&1; then
    echo "wasm: SKIP (emcc not found; install emsdk to build)"
    exit 0
fi

ROOT="../.."
SRC="$ROOT/src"
INC="-I$ROOT/include"

SOURCES="$SRC/crypto/sha512.c $SRC/crypto/hmac.c $SRC/crypto/ed25519.c \
$SRC/crypto/random.c $SRC/crypto/chacha20.c $SRC/crypto/sm3.c \
$SRC/crypto/sm2.c $SRC/core/kdf.c $SRC/core/license.c $SRC/core/token.c"

# Single line on purpose: backslash-newline inside single quotes is a
# literal (B14) and emcc would treat "\\\n..." as a symbol name.
EXPORTS='["_malloc","_free","_act_sha512","_act_hmac_sha512","_act_ed25519_keypair","_act_ed25519_sign","_act_ed25519_verify","_act_sm3","_act_sm2_keypair","_act_sm2_sign","_act_sm2_verify","_act_sm2_encrypt","_act_sm2_decrypt","_act_chacha20_xor","_act_hkdf_sha512","_act_pbkdf2_hmac_sha512","_act_license_make","_act_license_encode","_act_license_decode","_act_license_verify","_act_license_verify_payload","_act_days_remaining","_act_has_feature","_act_token_create","_act_token_verify"]'

mkdir -p dist
echo "== emcc =="
emcc -O2 -std=c99 -Wall $INC $SOURCES -o dist/engrail_wasm.js \
    -s MODULARIZE=1 \
    -s EXPORT_NAME=EngrailWasm \
    -s ENVIRONMENT=web,node \
    -s ALLOW_MEMORY_GROWTH=1 \
    -s WASM_BIGINT=1 \
    -s EXPORTED_RUNTIME_METHODS=['UTF8ToString','stringToUTF8','lengthBytesUTF8','HEAPU8'] \
    -s EXPORTED_FUNCTIONS="$EXPORTS"

echo "== node demo =="
node demo.mjs

# bench: sh build.sh --bench  (or run directly once dist exists)
if [ "${1:-}" = "--bench" ] && command -v node >/dev/null 2>&1; then
    echo
    echo "== wasm benchmark =="
    node bench.mjs
fi
