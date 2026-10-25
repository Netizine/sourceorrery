#!/usr/bin/env bash
# Smoke test of this machine's key in the OS credential store, for macOS
# (Keychain) and Linux (Secret Service: GNOME Keyring, KWallet, KeePassXC).
# Everything the CLI does with the credential store is exercised once, in
# an isolated home, and the store itself is inspected after each step, so
# the result says whether this machine's store behaves as the vault expects.
#
#   bash scripts/dev/keyring-smoke.sh [PATH-TO-sourceorrery]
#
# Exit 0: every check passed. 1: a check failed. 2: the credential store
# is not available here (the vault then opens with its recovery key only,
# which CI covers everywhere else). Nothing it prints is a secret value: the
# one value it stores is a canary it generates itself, compared in memory,
# and the recovery keys go to files in the isolated home.
#
# CI runs this against a temporary macOS keychain and a GNOME Keyring under
# dbus-run-session (ci.yml, job `keyring`); a desktop session is validated
# by running it by hand (docs/threat-model.md).
set -uo pipefail

cli="${1:-}"
if [[ -z "$cli" ]]; then
  repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
  for candidate in "$repo/target/release/sourceorrery" "$repo/target/debug/sourceorrery" "$(command -v sourceorrery || true)"; do
    if [[ -n "$candidate" ]] && [[ -x "$candidate" ]]; then cli="$candidate"; break; fi
  done
fi
if [[ -z "$cli" ]] || [[ ! -x "$cli" ]]; then
  echo "keyring-smoke: no sourceorrery binary; pass its path or build the CLI" >&2
  exit 2
fi

export SOURCEORRERY_HOME
SOURCEORRERY_HOME="$(mktemp -d)"
unset SOURCEORRERY_RECOVERY_KEY SOURCEORRERY_RECOVERY_KEY_FILE SOURCEORRERY_KEYRING SOURCEORRERY_VAULT
passed=0
failed=0
pass() { passed=$((passed + 1)); echo "PASS  $1"; }
fail() { failed=$((failed + 1)); echo "FAIL  $1" >&2; }
# No check has a terminal to prompt on: a vault that cannot be opened fails
# instead of asking for its recovery key.
check() { # <description> <command...>: PASS when the command succeeds
  local what="$1"; shift
  if "$@" >/dev/null 2>&1 </dev/null; then pass "$what"; else fail "$what"; fi
}
check_not() { # <description> <command...>: PASS when the command fails
  local what="$1"; shift
  if "$@" >/dev/null 2>&1 </dev/null; then fail "$what"; else pass "$what"; fi
}
json() { python3 -c 'import json,sys; d=json.load(sys.stdin); print(eval(sys.argv[1], {"d": d}))' "$1"; }
# The id of the this-machine key in `vault create -o json`'s report.
machine_key() { json '([k["id"] for k in d["keys"] if k["kind"] == "this-machine"] or [""])[0]'; }
# What a machine without this store does: no credential store at all.
elsewhere() { env SOURCEORRERY_KEYRING=off "$@"; }

cleanup() {
  # Leave nothing behind: vaults still present are destroyed (which also
  # removes their keyring entries), then the home directory goes.
  for name in smoke smoke-copy keep keep-copy; do
    if [[ -e "$SOURCEORRERY_HOME/vaults/$name.sorvault" ]]; then
      "$cli" vault destroy "$name" --yes >/dev/null 2>&1 </dev/null || true
    fi
  done
  rm -rf "$SOURCEORRERY_HOME"
}
trap cleanup EXIT

# How the store is inspected on this platform. On Linux the check is only
# as good as `secret-tool` (libsecret-tools); without it the store checks
# are reported as SKIP and the functional checks still count.
os="$(uname -s)"
store_has() { # <account>
  case "$os" in
    Darwin) security find-generic-password -s sourceorrery -a "$1" >/dev/null 2>&1 ;;
    *) secret-tool search --all service sourceorrery 2>/dev/null | grep -qF "$1" ;;
  esac
}
store_checks=true
if [[ "$os" != "Darwin" ]] && ! command -v secret-tool >/dev/null 2>&1; then
  store_checks=false
  echo "SKIP  store inspection: secret-tool (libsecret-tools) is not installed; functional checks only"
fi
store_check() { # <description> <account> <present|absent>
  if [[ "$store_checks" != true ]]; then echo "SKIP  $1"; return; fi
  if [[ "$3" = present ]]; then check "$1" store_has "$2"; else check_not "$1" store_has "$2"; fi
}

echo "keyring-smoke: $("$cli" --version) on $(uname -srm)"
case "$os" in
  Darwin) echo "  macOS $(sw_vers -productVersion 2>/dev/null); default keychain: $(security default-keychain 2>/dev/null | tr -d ' "')" ;;
  *) echo "  $(. /etc/os-release 2>/dev/null && echo "$PRETTY_NAME"); desktop: ${XDG_CURRENT_DESKTOP:-none}; session bus: $([[ -n "${DBUS_SESSION_BUS_ADDRESS:-}" ]] && echo set || echo unset)" ;;
esac
echo "  home: $SOURCEORRERY_HOME"

# 1. A vault this machine opens through its credential store, or a clear
#    verdict that the store is unavailable here.
key_file="$SOURCEORRERY_HOME/smoke.key"
if ! created="$("$cli" -o json vault create smoke --recovery-key-out "$key_file" 2>"$SOURCEORRERY_HOME/create.err" </dev/null)"; then
  sed 's/^/  /' "$SOURCEORRERY_HOME/create.err"
  fail "vault create"
  exit 1
fi
if [[ "$(echo "$created" | json 'd["this_machine"]')" != "True" ]]; then
  echo "keyring-smoke: the OS credential store is not available in this session" >&2
  exit 2
fi
pass "vault create keeps this machine's key in the store"

vault_id="$(echo "$created" | json 'd["vault"]["id"]')"
wrap_id="$(echo "$created" | machine_key)"
account="vault/$vault_id/$wrap_id"
check "vault create reports this machine's key" test -n "$wrap_id"
store_check "the store holds the vault's entry ($account)" "$account" present

# 2. A value goes in and comes back, in a fresh process each time and with
#    no terminal to prompt on.
canary="smoke-$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')"
check "secret set through this machine's key" bash -c 'printf "%s" "$1" | "$2" secret set canary --vault smoke --stdin' _ "$canary" "$cli"
got="$("$cli" secret get canary --vault smoke --reveal --raw </dev/null 2>/dev/null || true)"
if [[ "$got" = "$canary" ]]; then pass "secret get returns the stored value"; else fail "secret get returns the stored value"; fi
check "a second process opens the vault without a prompt" "$cli" secret list --vault smoke

# 3. Where this machine's key cannot be used the vault needs its recovery
#    key, and opening it that way leaves this machine's entry alone.
check_not "elsewhere, without the recovery key, the vault stays locked" elsewhere "$cli" secret list --vault smoke
check "elsewhere the recovery key opens it" elsewhere env SOURCEORRERY_RECOVERY_KEY_FILE="$key_file" "$cli" secret list --vault smoke
store_check "this machine's entry is unchanged" "$account" present
check "this machine still opens the vault without a prompt" "$cli" secret list --vault smoke

# 4. Destroying a vault removes its entry, unless another vault file in the
#    home still references it.
cp "$SOURCEORRERY_HOME/vaults/smoke.sorvault" "$SOURCEORRERY_HOME/vaults/smoke-copy.sorvault"
destroy_out="$("$cli" vault destroy smoke --yes 2>&1 </dev/null)" && pass "vault destroy with a copy present" || fail "vault destroy with a copy present"
if echo "$destroy_out" | grep -q "kept OS-keyring entry"; then pass "destroy reports the entry kept for the copy"; else fail "destroy reports the entry kept for the copy"; fi
store_check "the entry survives while the copy references it" "$account" present
check "destroying the copy" "$cli" vault destroy smoke-copy --yes
store_check "the entry is removed with the last file" "$account" absent

# 5. --keep-os-key leaves the entry alone; the copy's destruction cleans up.
if kept="$("$cli" -o json vault create keep --recovery-key-out "$SOURCEORRERY_HOME/keep.key" </dev/null 2>/dev/null)"; then pass "vault create keep"; else fail "vault create keep"; fi
keep_account="vault/$(echo "$kept" | json 'd["vault"]["id"]')/$(echo "$kept" | machine_key)"
cp "$SOURCEORRERY_HOME/vaults/keep.sorvault" "$SOURCEORRERY_HOME/vaults/keep-copy.sorvault"
check "vault destroy --keep-os-key" "$cli" vault destroy keep --yes --keep-os-key
store_check "the entry is kept on request" "$keep_account" present
check "destroying the copy removes it" "$cli" vault destroy keep-copy --yes
store_check "no entry is left behind" "$keep_account" absent

echo
echo "keyring-smoke: $passed passed, $failed failed"
[[ "$failed" -eq 0 ]]
