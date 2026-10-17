#!/usr/bin/env bash
#  demo.sh -- shell bindings end-to-end walkthrough.
#
#    ./configure && make          # prerequisites
#    bash bindings/shell/demo.sh
set -euo pipefail
cd "$(dirname "$0")/../.."

source bindings/shell/activation.sh

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
KEY="$WORK/vendor.key"
STATE="$WORK/app.act"

echo "== 1. vendor: create key pair =="
rm -f "$KEY"
"$ACT_KEYGEN" keygen "$KEY" >/dev/null

echo "== 2. load deployment =="
act_init "$KEY"
echo "   pubkey: ${ACT_PUBKEY:0:32}..."

echo "== 3. customer: machine code =="
MC="$(act_machine_code 1)"
echo "   $MC"

echo "== 4. vendor: issue 30-day code =="
CODE="$(act_issue "$MC" --days 30)"
echo "   ${CODE:0:30}..."
[ "${#CODE}" -ge 100 ] || { echo "FAIL: code too short"; exit 1; }

echo "== 5. inspect as JSON =="
act_inspect_json "$CODE" | head -4

echo "== 6. offline token =="
TOK="$(act_token_sign 'cmd=demo' 600)"
act_token_verify "$TOK" && echo "   token valid"

echo "== 7. revoke flow =="
SERIAL="$(act_inspect_json "$CODE" | sed -n 's/.*"serial": "\([0-9a-f]*\)".*/\1/p')"
act_revoke "$SERIAL" "$WORK/revoke.dat" | head -1

echo
echo "SHELL BINDINGS: ALL CHECKS PASSED"
