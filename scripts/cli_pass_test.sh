#!/usr/bin/env bash
#  cli_pass_test.sh -- regression test for the R2/BUG-1 argument fix:
#  the VALUE of `--pass` must never be consumed as a positional path.
#
#  Quadrant under test: flag position (front/back) x collision file
#  (a file named like the passphrase exists / does not).
#
#  Usage: bash scripts/cli_pass_test.sh    (needs ./configure && make)

set -uo pipefail
cd "$(dirname "$0")/.."

KEYGEN="$(cd "$(dirname "$0")/.." && pwd)/build/engrail-keygen"
FAIL=0
T=$(mktemp -d)
trap 'rm -rf "$T"' EXIT

[ -x "$KEYGEN" ] || { echo "cli_pass: $KEYGEN missing (run make)"; exit 1; }

check() { # name cond
    if eval "$2"; then echo "  [PASS] $1"; else
        echo "  [FAIL] $1"; FAIL=1; fi
}

export ACT_LANG=en

echo "cli_pass_test: --pass value isolation (R2/BUG-1 regression)"

# Q1: --pass VALUE in front, no collision file -- key must land in the
#     named path and NOT in a file called "s3cret"
rm -f "$T"/s3cret "$T"/front.key
"$KEYGEN" keygen --pass s3cret "$T"/front.key >/dev/null 2>&1
check "front: key written to requested path" '[ -f "$T/front.key" ]'
check "front: no file named after passphrase" '[ ! -f "$T/s3cret" ] && [ ! -f s3cret ]'

# Q2: --pass VALUE at the back
rm -f "$T"/s3cret "$T"/back.key
"$KEYGEN" keygen "$T"/back.key --pass s3cret >/dev/null 2>&1
check "back: key written to requested path" '[ -f "$T"/back.key ]'
check "back: no file named after passphrase" '[ ! -f "$T/s3cret" ] && [ ! -f s3cret ]'

# Q3: collision -- a file named "s3cret" ALREADY exists in cwd; the
#     tool must not touch it, and the key must still go to out.key
mkdir -p "$T/cwd" && cd "$T/cwd"
echo "sentinel" > s3cret
"$KEYGEN" keygen --pass s3cret out.key >/dev/null 2>&1
check "collision: key written to requested path" '[ -f out.key ]'
check "collision: pre-existing passphrase-named file untouched" \
      '[ "$(cat s3cret)" = "sentinel" ]'

# Q4: --pass=VALUE form
"$KEYGEN" keygen --pass=eqpass eq.key >/dev/null 2>&1
check "--pass=VALUE form works" '[ -f eq.key ] && [ ! -f eqpass ] && [ ! -f "=eqpass" ]'

# Q5: --pass with no value is a hard error, writes nothing
rm -f dangle.key
if "$KEYGEN" keygen dangle.key --pass >/dev/null 2>&1; then
    check "--pass without value errors" 'false'
else
    check "--pass without value errors" 'true'
fi
check "--pass without value writes nothing" '[ ! -f dangle.key ]'

# Q6: encrypted round-trip still works with the extracted passphrase
if "$KEYGEN" pubkey --pass s3cret out.key >/dev/null 2>&1; then
    check "pubkey reads encrypted key with --pass" 'true'
else
    check "pubkey reads encrypted key with --pass" 'false'
fi

# Q7: issuefile forwards the new options (R2/BUG-6)
printf 'AAAAAAAAAAAAAAAA-BBBBBBBBBBBBBBBB\n' > machines.txt
"$KEYGEN" issuefile --pass s3cret out.key machines.txt codes.txt \
          --days 30 --product 7 --features 0x0003 --trial >/dev/null 2>&1
CODE=$(sed 's/.*;//' codes.txt 2>/dev/null | head -1)
if [ -n "$CODE" ]; then
    JSON=$("$KEYGEN" inspect --json "$CODE")
    check "issuefile --product forwarded" \
          "echo \"\$JSON\" | grep -q '\"product_id\": *7'"
    check "issuefile --features forwarded" \
          "echo \"\$JSON\" | grep -q '\"features\": *3'"
    check "issuefile --trial forwarded" \
          "echo \"\$JSON\" | grep -q '\"trial\": *true'"
else
    check "issuefile produced a code" 'false'
fi

if [ "$FAIL" -eq 0 ]; then
    echo "cli_pass_test: ALL CHECKS PASSED"
else
    echo "cli_pass_test: FAILURES DETECTED"
fi
exit "$FAIL"
