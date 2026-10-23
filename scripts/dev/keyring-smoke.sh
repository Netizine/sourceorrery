#!/usr/bin/env bash
# Smoke test of the OS-keyring protector path, for macOS (Keychain) and
# Linux (Secret Service: GNOME Keyring, KWallet, KeePassXC). Everything the
# CLI does with the credential store is exercised once, in an isolated
# home, and the store itself is inspected after each step, so the result
# says whether this machine's store behaves as the vault expects.
#
#   bash scripts/dev/keyring-smoke.sh [PATH-TO-sourceorrery]
#
# Exit 0: every check passed. 1: a check failed. 2: the credential store
# is not available here (the CLI falls back to a passphrase, which CI
# covers everywhere else). Nothing it prints is a secret value: the one
# value it stores is a canary it generates itself, compared in memory.
#
# CI runs this against a temporary macOS keychain and a GNOME Keyring under
# dbus-run-session (ci.yml, job `keyring`); a desktop session is validated
# by running it by hand (docs/threat-model.md).
set -uo pipefail

cli="${1:-}"
if [ -z "$cli" ]; then
  repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
  for candidate in "$repo/target/release/sourceorrery" "$repo/target/debug/sourceorrery" "$(command -v sourceorrery || true)"; do
    if [ -n "$candidate" ] && [ -x "$candidate" ]; then cli="$candidate"; break; fi
  done
fi
if [ -z "$cli" ] || [ ! -x "$cli" ]; then
  echo "keyring-smoke: no sourceorrery binary; pass its path or build the CLI" >&2
  exit 2
fi

export SOURCEORRERY_HOME
SOURCEORRERY_HOME="$(mktemp -d)"
unset SOURCEORRERY_PASSPHRASE SOURCEORRERY_PASSPHRASE_FILE SOURCEORRERY_VAULT
passed=0
failed=0
pass() { passed=$((passed + 1)); echo "PASS  $1"; }
fail() { failed=$((failed + 1)); echo "FAIL  $1" >&2; }
check() { # <description> <command...>: PASS when the command succeeds
  local what="$1"; shift
  if "$@" >/dev/null 2>&1; then pass "$what"; else fail "$what"; fi
}
check_not() { # <description> <command...>: PASS when the command fails
  local what="$1"; shift
  if "$@" >/dev/null 2>&1; then fail "$what"; else pass "$what"; fi
}
json() { python3 -c 'import json,sys; d=json.load(sys.stdin); print(eval(sys.argv[1], {"d": d}))' "$1"; }

cleanup() {
  # Leave nothing behind: vaults still present are destroyed (which also
  # removes their keyring entries), then the home directory goes.
  for name in smoke smoke-copy keep keep-copy; do
    if [ -e "$SOURCEORRERY_HOME/vaults/$name.sorvault" ]; then
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
if [ "$os" != "Darwin" ] && ! command -v secret-tool >/dev/null 2>&1; then
  store_checks=false
  echo "SKIP  store inspection: secret-tool (libsecret-tools) is not installed; functional checks only"
fi
store_check() { # <description> <account> <present|absent>
  if [ "$store_checks" != true ]; then echo "SKIP  $1"; return; fi
  if [ "$3" = present ]; then check "$1" store_has "$2"; else check_not "$1" store_has "$2"; fi
}

echo "keyring-smoke: $("$cli" --version) on $(uname -srm)"
case "$os" in
  Darwin) echo "  macOS $(sw_vers -productVersion 2>/dev/null); default keychain: $(security default-keychain 2>/dev/null | tr -d ' "')" ;;
  *) echo "  $(. /etc/os-release 2>/dev/null && echo "$PRETTY_NAME"); desktop: ${XDG_CURRENT_DESKTOP:-none}; session bus: $([ -n "${DBUS_SESSION_BUS_ADDRESS:-}" ] && echo set || echo unset)" ;;
esac
echo "  home: $SOURCEORRERY_HOME"

# 1. A vault with an OS-keyring protector, or a clear verdict that the
#    store is unavailable here.
if ! create_out="$("$cli" vault create smoke --protector os-keyring 2>&1 </dev/null)"; then
  echo "$create_out" | sed 's/^/  /'
  if echo "$create_out" | grep -qi "not available\|unsupported\|refused access"; then
    echo "keyring-smoke: the OS credential store is not available in this session" >&2
    exit 2
  fi
  fail "vault create --protector os-keyring"
  exit 1
fi
pass "vault create --protector os-keyring"

vault_id="$("$cli" -o json vault info --vault smoke </dev/null | json 'd["vault"]["id"]')"
protector_id="$("$cli" -o json vault protector list --vault smoke </dev/null | json '[p["id"] for p in d if p["kind"] == "os-keyring"][0]')"
account="vault/$vault_id/$protector_id"
check "protector list shows an os-keyring protector" test -n "$protector_id"
store_check "the store holds the vault's entry ($account)" "$account" present

# 2. A value goes in and comes back, in a fresh process each time and with
#    no terminal to prompt on.
canary="smoke-$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')"
check "secret set through the keyring protector" bash -c 'printf "%s" "$1" | "$2" secret set canary --vault smoke --stdin' _ "$canary" "$cli"
got="$("$cli" secret get canary --vault smoke --reveal --raw </dev/null 2>/dev/null || true)"
if [ "$got" = "$canary" ]; then pass "secret get returns the stored value"; else fail "secret get returns the stored value"; fi
check "a second process opens the vault without a prompt" "$cli" secret list --vault smoke </dev/null

# 3. Protectors change: a passphrase joins, the keyring protector leaves and
#    its entry with it, the vault still opens, the keyring protector returns.
export SOURCEORRERY_PASSPHRASE="smoke-passphrase-$$"
check "protector add --kind passphrase" "$cli" vault protector add --kind passphrase --vault smoke
check "protector remove <os-keyring id>" "$cli" vault protector remove "$protector_id" --vault smoke
store_check "the entry is gone after the protector is removed" "$account" absent
check "the vault opens with the passphrase alone" "$cli" secret list --vault smoke
check "protector add --kind os-keyring" "$cli" vault protector add --kind os-keyring --vault smoke
unset SOURCEORRERY_PASSPHRASE
protector_id="$("$cli" -o json vault protector list --vault smoke </dev/null | json '[p["id"] for p in d if p["kind"] == "os-keyring"][0]')"
account="vault/$vault_id/$protector_id"
store_check "the store holds the new entry" "$account" present
check "the vault opens through the new keyring protector" "$cli" secret list --vault smoke

# 4. Destroying a vault removes its entry, unless another vault file in the
#    home still references it.
cp "$SOURCEORRERY_HOME/vaults/smoke.sorvault" "$SOURCEORRERY_HOME/vaults/smoke-copy.sorvault"
destroy_out="$("$cli" vault destroy smoke --yes 2>&1 </dev/null)" && pass "vault destroy with a copy present" || fail "vault destroy with a copy present"
if echo "$destroy_out" | grep -q "kept OS-keyring entry"; then pass "destroy reports the entry kept for the copy"; else fail "destroy reports the entry kept for the copy"; fi
store_check "the entry survives while the copy references it" "$account" present
check "destroying the copy" "$cli" vault destroy smoke-copy --yes
store_check "the entry is removed with the last file" "$account" absent

# 5. --keep-os-key leaves the entry alone; the copy's destruction cleans up.
check "vault create keep --protector os-keyring" "$cli" vault create keep --protector os-keyring
keep_id="$("$cli" -o json vault info --vault keep </dev/null | json 'd["vault"]["id"]')"
keep_protector="$("$cli" -o json vault protector list --vault keep </dev/null | json '[p["id"] for p in d if p["kind"] == "os-keyring"][0]')"
keep_account="vault/$keep_id/$keep_protector"
cp "$SOURCEORRERY_HOME/vaults/keep.sorvault" "$SOURCEORRERY_HOME/vaults/keep-copy.sorvault"
check "vault destroy --keep-os-key" "$cli" vault destroy keep --yes --keep-os-key
store_check "the entry is kept on request" "$keep_account" present
check "destroying the copy removes it" "$cli" vault destroy keep-copy --yes
store_check "no entry is left behind" "$keep_account" absent

echo
echo "keyring-smoke: $passed passed, $failed failed"
[ "$failed" -eq 0 ]
