#!/usr/bin/env bash
# e2e.sh -- full vendor + customer end-to-end demonstration
#
# Simulates the real workflow:
#   1. vendor generates a key pair
#   2. example app is rebuilt with the vendor public key embedded
#   3. app prints its machine code
#   4. vendor issues an activation code for that machine
#   5. app activates and persists the state
#   6. app re-verifies the saved state at next "startup"
#   7. tampering with the state file is detected
#   8. a code issued for another machine is rejected
set -euo pipefail

CXX="${CXX:-c++}"
CXXFLAGS="${CXXFLAGS:--O2}"
case "$(uname -s 2>/dev/null || echo unknown)" in
    MINGW*|MSYS*|CYGWIN*) EXESUF=".exe"; STATIC_CXX="-static-libstdc++" ;;   # paths handed to native tools
    Darwin*)              EXESUF="";    STATIC_CXX="" ;;
    *)                    EXESUF="";    STATIC_CXX="-static-libstdc++" ;;
esac
export ACT_LANG=en  # e2e 输出稳定性

cd "$(dirname "$0")/.."

BUILD=build
KEY="$BUILD/demo.key"
PUBKEY_HEX="$BUILD/demo_pubkey.hex"
STATE="$BUILD/demo_state.act"

echo "== 1. vendor: generate key pair =="
rm -f "$KEY" "$PUBKEY_HEX" "$STATE" "$BUILD/revoke.dat"
./build/engrail-keygen keygen "$KEY" | grep -oE '[0-9a-f]{64}' | head -1 > "$PUBKEY_HEX"
PUBKEY=$(cat "$PUBKEY_HEX")
echo "   pubkey: $PUBKEY"

echo "== 2. rebuild example with the embedded public key =="
$CXX $CXXFLAGS -Wall -Wextra -Werror -std=c++17 -Iinclude \
    -DACT_PUBKEY_HEX=\"$PUBKEY\" -DACT_PRODUCT_ID=1 -DACT_STATE_PATH=\"build/demo_state.act\" \
    examples/simple_check.cpp build/libactivation.a $STATIC_CXX -o build/simple_check

echo "== 3. customer: app shows machine code =="
MC=$((./build/simple_check || true) | sed -n "s/^machine code: //p")
echo "   machine code: $MC"

echo "== 4. vendor: issue a 365-day activation code =="
CODE=$(./build/engrail-keygen issue "$KEY" --product 1 --machine "$MC" --days 365)
echo "   code: ${CODE:0:48}..."

echo "== 5. customer: activate =="
./build/simple_check "$CODE"
[ -f "$STATE" ] && echo "   state file created: $STATE"

echo "== 6. customer: restart & re-verify saved state =="
./build/simple_check

echo "== 7. tamper with the state file (flip one byte) =="
python3 - "$STATE" <<'EOF'
import sys
p = sys.argv[1]
with open(p, 'r+b') as f:
    f.seek(10)
    b = f.read(1)
    f.seek(10)
    f.write(bytes([b[0] ^ 0x01]))
EOF
if ./build/simple_check; then
    echo "FAIL: tampered state accepted"; exit 1
else
    echo "   tampered state correctly rejected"
fi

echo "== 8. code issued for another machine =="
CODE2=$(./build/engrail-keygen issue "$KEY" --product 1 --machine 0123456789ABCDEF-0123456789ABCDEF --days 365)
if ./build/simple_check "$CODE2"; then
    echo "FAIL: foreign machine code accepted"; exit 1
else
    echo "   foreign machine code correctly rejected"
fi

echo "== 9. offline code inspection (no keys needed) =="
./build/engrail-keygen inspect "$CODE" | sed -n '1,9p'

echo "== 10. revocation flow =="
SERIAL=$(./build/engrail-keygen inspect "$CODE" | sed -n 's/^  serial     : //p')
./build/engrail-keygen revoke "$KEY" "$BUILD/revoke.dat" "$SERIAL"
echo "   revoked serial: $SERIAL"

echo "== 11. executable self-integrity =="
./build/engrail-integrity patch build/simple_check$EXESUF
./build/engrail-integrity check build/simple_check$EXESUF
echo "   (app can now gate on act_harden_selfcheck / act_verify_hardened)"

echo "== 12. offline auth: token sign/verify =="
TOK=$(./build/engrail-keygen token sign "$KEY" --ttl 3600 --payload "cmd=open-vault" 2>/dev/null)
./build/engrail-keygen export-pub "$KEY" "$BUILD/deploy.pub" >/dev/null
./build/engrail-keygen token verify "$BUILD/deploy.pub" "$TOK"

echo "== 13. offline auth: challenge-response =="
CHAL=$(./build/engrail-keygen challenge --machine "$MC" --product 1)
RESP=$(./build/engrail-keygen respond "$KEY" "$CHAL")
./build/engrail-keygen verify "$BUILD/deploy.pub" "$CHAL" "$RESP" --machine "$MC"

echo "== 14. passphrase-encrypted key file (ACTKEY2) =="
ACT_PASSPHRASE="demo-pass-123" ./build/engrail-keygen keygen "$BUILD/enc.key" >/dev/null
if head -c 7 "$BUILD/enc.key" | grep -q ACTKEY2; then
    echo "   key file is encrypted (ACTKEY2); plaintext seed absent"
fi
if ACT_PASSPHRASE="wrong" ./build/engrail-keygen pubkey "$BUILD/enc.key" 2>/dev/null; then
    echo "FAIL: wrong passphrase accepted"; exit 1
else
    echo "   wrong passphrase correctly rejected"
fi
ACT_PASSPHRASE="demo-pass-123" ./build/engrail-keygen pubkey "$BUILD/enc.key" | grep -qE '^[0-9a-f]{64}$' \
    && echo "   correct passphrase recovers the key"

rm -f "$STATE"
echo
echo "END-TO-END: ALL CHECKS PASSED"
echo "community: https://t.me/Stack_Traces"
