#!/usr/bin/env bash
#  run_all.sh -- unified test-suite runner with summary.
#
#    bash tests/run_all.sh            (or: make check)
#
#  Runs every suite, collects pass/fail, prints a final matrix.
set -u
cd "$(dirname "$0")/.."

[ -f build/libactivation.a ] || { ./configure >/dev/null && make >/dev/null; }

# Fallback-build environment (only used when a test binary is missing;
# normal `make check` prebuilds everything). Read config.vars when it
# exists so the link flags match the configured build (C10).
CC="${CC:-cc}"
CFLAGS="${CFLAGS:--O2}"
LDFLAGS="${LDFLAGS:-}"
if [ -f config.vars ]; then
    # shellcheck disable=SC1091
    . ./config.vars 2>/dev/null || true
fi
case "$(uname -s 2>/dev/null || echo unknown)" in
    MINGW*|MSYS*|CYGWIN*) EXESUF=".exe" ;;
    *)                    EXESUF="" ;;
esac

SUITES="test_hmac test_ed25519 test_license test_sm2 test_random test_kdf test_dual test_harden test_fuzz test_lifecycle"
PASS=(); FAIL=(); MISSING=()

for t in $SUITES; do
    bin="build/$t$EXESUF"
    if [ ! -x "$bin" ]; then
        $CC $CFLAGS -std=c99 -Iinclude "tests/$t.c" build/libactivation.a \
            $LDFLAGS -o "build/$t$EXESUF" 2>/dev/null || { MISSING+=("$t"); continue; }
    fi
    out=$(./"$bin" 2>&1)
    rc=$?
    line=$(echo "$out" | tail -1)
    if [ $rc -eq 0 ]; then
        PASS+=("$t")
        printf '  [PASS] %-16s %s\n' "$t" "$line"
    else
        FAIL+=("$t")
        printf '  [FAIL] %-16s (exit %d)\n' "$t" "$rc"
        echo "$out" | grep '^\[FAIL\]' | head -5 | sed 's/^/         /'
    fi
done

echo
echo "==================== TEST MATRIX ===================="
printf '  passed : %d   %s\n' "${#PASS[@]}" "${PASS[*]:-}"
printf '  failed : %d   %s\n' "${#FAIL[@]}" "${FAIL[*]:-}"
printf '  missing: %d   %s\n' "${#MISSING[@]}" "${MISSING[*]:-}"
echo "====================================================="

total=$((${#PASS[@]} + ${#FAIL[@]}))
cases=$(./build/test_hmac$EXESUF 2>/dev/null | grep -c PASS || true)
[ "${#FAIL[@]}" -eq 0 ] && [ "${#MISSING[@]}" -eq 0 ] && echo "ALL $total SUITES GREEN" && exit 0
exit 1
