#!/usr/bin/env bash
#  activation.sh -- shell bindings for ActivationSystem.
#
#  Source it, get vendor + customer helper functions that wrap
#  the engrail-keygen CLI. No parsing of colored output:
#  every function captures the machine-readable stdout.
#
#    source bindings/shell/activation.sh
#    act_init  vendor.key                       # load deployment
#    act_machine_code                          # this machine
#    act_issue --days 365 --machine "$MC"       # vendor side
#    act_activate "$CODE" app.act               # customer side
#    act_check app.act                          # startup check
#
#  Requires: ./configure && make   (engrail-keygen on PATH
#  or $ACT_KEYGEN, plus build/ relative to the repo).
#  Community: https://t.me/Stack_Traces

# locate the CLI
_act_root() {
    local d="${BASH_SOURCE[0]:-$0}"
    d="$(cd "$(dirname "$d")/../.." && pwd)"
    printf '%s' "$d"
}
ACT_ROOT="${ACT_ROOT:-$(_act_root)}"
ACT_KEYGEN="${ACT_KEYGEN:-$ACT_ROOT/build/engrail-keygen}"

_act_cli() {
    [ -x "$ACT_KEYGEN" ] || {
        echo "activation.sh: engrail-keygen not found at $ACT_KEYGEN" >&2
        echo "  build it: ./configure && make" >&2
        return 9
    }
    ACT_LANG="${ACT_LANG:-en}" "$ACT_KEYGEN" "$@"
}

# deployment context
# act_init <secret.key> [--pass P]
#   exports ACT_PUBKEY / ACT_DSALT for the other helpers.
act_init() {
    local key="${1:?usage: act_init <secret.key>}"
    shift || true
    local out
    out=$(_act_cli pubkey "$key" "$@" 2>/dev/null) || return 1
    # pubkey 子命令只出公钥; 部署盐从 key 文件第三行读取 (明文 v2)
    ACT_PUBKEY="$out"
    ACT_DSALT="$(sed -n '3p' "$key" | tr -d '[:space:]')"
    ACT_KEY_FILE="$key"   # 供 act_issue / act_revoke 复用
    [ "${#ACT_PUBKEY}" = 64 ] && [ "${#ACT_DSALT}" = 64 ]
}

# customer side
# act_machine_code [product_id] [salt_hex] -> stdout: 33-char code
act_machine_code() {
    local product="${1:-1}" salt="${2:-}"
    _act_cli machine-code --pubkey "$ACT_PUBKEY" --dsalt "$ACT_DSALT" \
        --product "$product" ${salt:+--salt-hex "$salt"}
}

# act_activate <code> <state_file> -> 0 ok
act_activate() {
    local code="${1:?usage: act_activate <code> <state>}" state="${2:?}"
    "$ACT_ROOT/build/simple_check" "$code" >/dev/null 2>&1 && \
        [ -f app.act ] && mv app.act "$state"
}

# act_check <state_file> [salt_hex] -> 0 licensed
act_check() {
    local state="${1:?usage: act_check <state>}"
    "$ACT_ROOT/build/simple_check" >/dev/null 2>&1
}

# vendor side
# act_issue <machine_code> [--days N|--perpetual] [--trial] \
#           [--features 0xMASK] [extra keygen args...]
#   -> stdout: activation code only (script-friendly)
act_issue() {
    local machine="${1:?usage: act_issue <machine-code> [options]}"
    shift
    _act_cli issue "${ACT_KEY_FILE:-secret.key}" --machine "$machine" "$@"
}

# act_inspect_json <code> -> machine-readable metadata
act_inspect_json() {
    _act_cli inspect --json "${1:?usage: act_inspect_json <code>}"
}

# act_revoke <serial|code> <list.dat>
act_revoke() {
    _act_cli revoke "${ACT_KEY_FILE:-secret.key}" "${2:?}" \
        "${1:?usage: act_revoke <serial|code> <list>}"
}

# act_token_sign <payload> [ttl] -> offline auth token
act_token_sign() {
    _act_cli token sign "${ACT_KEY_FILE:-secret.key}" \
        --payload "${1:?}" --ttl "${2:-3600}" 2>/dev/null
}

# act_token_verify <token> -> 0 valid
act_token_verify() {
    _act_cli token verify "${1:?}" >/dev/null 2>&1
}

# convenience
act_version() { _act_cli version; }
act_help()    { _act_cli --help 2>&1 | head -30; }
