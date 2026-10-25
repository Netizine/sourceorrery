#!/usr/bin/env bash
# Creates the vault every SDK test suite and example reads in CI, using the
# CLI only (no OS credential store: the vault opens with its recovery key,
# SOURCEORRERY_RECOVERY_KEY in the job environment), and exports the
# variables the suites look for.
#
#   bash scripts/ci/fixture-vault.sh [HOME_DIR [CONNECTION FLAGS...]]
#
# CONNECTION FLAGS are one provider's `vault create` flags, for example
# `--hashicorp-vault http://127.0.0.1:8200 --hashicorp-vault-mount harness
# --hashicorp-vault-token-file token.txt`. The provider jobs give them: the
# vault then has that connection, and the remote fixture below is stored at
# the provider through it.
#
# Exports (to $GITHUB_ENV when set, otherwise printed as `export` lines you
# can `eval`):
#   SOURCEORRERY_HOME               home directory holding the vault
#   SOURCEORRERY_RECOVERY_KEY       recovery key of the `ci` vault
#   SOURCEORRERY_TEST_VAULT         "ci"
#   SOURCEORRERY_TEST_MANIFEST      a sourceorrery.toml bound to that vault
#   SOURCEORRERY_TEST_OLD_VERSION   id of the oldest database-password version
#   SOURCEORRERY_NATIVE_DIR         directory holding the C ABI shared library
#   SOURCEORRERY_CLI                the CLI binary that created the fixture
#   SOURCEORRERY_TEST_REMOTE_MANIFEST  with a connection only: a
#                                   sourceorrery.toml naming database-password
#                                   and remote-password
#
# Fixture contents (the suites assert exactly these):
#   database-password  v1 "first-version", v2 "ci-secret-value" (text/plain, env=ci)
#   rotated-key        v1 "old", v2 "new" (disabled)  -> latest accessible is "old"
#   expired-token      "x", expired 2020-01-01         -> expired
#   future-token       "x", not before 2100-01-01      -> not_yet_valid
#   deleted-secret     "x", then deleted               -> deleted
# and a byte-for-byte copy of the vault filed as `ci-copy`, which opens with
# the same recovery key but must be refused as vault_mismatch. With a
# connection, kept at the provider (`secret set --storage`):
#   remote-password    "remote-secret-value" (text/plain, env=remote)
#   remote-rotated-key v1 "old", v2 "new" (disabled), only where the provider
#                      keeps properties per version (not AWS Secrets Manager)
set -euo pipefail

# `pwd -W` gives a C:/... path on Git Bash, which every toolchain understands.
repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && (pwd -W 2>/dev/null || pwd))"
exe=""
case "$(uname -s)" in MINGW*|MSYS*|CYGWIN*|Windows_NT) exe=".exe" ;; esac

cli="${SOURCEORRERY_CLI:-}"
if [[ -z "$cli" ]]; then
  for candidate in "$repo/target/release/sourceorrery$exe" "$repo/target/debug/sourceorrery$exe"; do
    if [[ -x "$candidate" ]]; then cli="$candidate"; break; fi
  done
fi
if [[ -z "$cli" ]] || [[ ! -x "$cli" ]]; then
  echo "fixture-vault: no CLI found; build it with 'cargo build --release -p sourceorrery-cli' or set SOURCEORRERY_CLI" >&2
  exit 1
fi
native_dir="${SOURCEORRERY_NATIVE_DIR:-$(dirname "$cli")}"

home="${1:-$(mktemp -d)}"
connection=("${@:2}")
# The connection's provider is where `--storage` puts the remote fixture.
storage=""
for flag in ${connection[@]+"${connection[@]}"}; do
  provider=""
  case "$flag" in
    --hashicorp-vault|--hashicorp-vault=*) provider=hashicorp-vault ;;
    --aws-secrets-manager|--aws-secrets-manager=*) provider=aws-secrets-manager ;;
    --azure-key-vault|--azure-key-vault=*) provider=azure-key-vault ;;
  esac
  if [[ -n "$provider" ]]; then
    if [[ -n "$storage" ]]; then
      echo "fixture-vault: give one provider's connection flags, not $storage and $provider" >&2
      exit 1
    fi
    storage="$provider"
  fi
done
if [[ ${#connection[@]} -gt 0 ]] && [[ -z "$storage" ]]; then
  echo "fixture-vault: the flags after HOME_DIR name no provider (--hashicorp-vault, --aws-secrets-manager or --azure-key-vault)" >&2
  exit 1
fi

mkdir -p "$home"
# A path with forward slashes is understood by every toolchain on Windows too.
home="$(cd "$home" && pwd -W 2>/dev/null || pwd)"
export SOURCEORRERY_HOME="$home"
# The fixture never touches the runner's OS credential store.
export SOURCEORRERY_KEYRING=off
vault="ci"

key_file="$home/$vault.recovery-key"
"$cli" vault create "$vault" --no-keyring --recovery-key-out "$key_file" ${connection[@]+"${connection[@]}"}
SOURCEORRERY_RECOVERY_KEY="$(tr -d '\r\n' < "$key_file")"
export SOURCEORRERY_RECOVERY_KEY
rm -f "$key_file"
set_secret() { # name value [extra args...]
  local name="$1" value="$2"; shift 2
  printf '%s' "$value" | "$cli" secret set "$name" --vault "$vault" --stdin "$@"
}
set_secret database-password "first-version"
set_secret database-password "ci-secret-value" --content-type text/plain --tag env=ci
set_secret rotated-key "old"
set_secret rotated-key "new"
"$cli" secret update rotated-key --vault "$vault" --disable
set_secret expired-token "x" --expires 2020-01-01T00:00:00Z
set_secret future-token "x" --not-before 2100-01-01T00:00:00Z
set_secret deleted-secret "x"
"$cli" secret delete deleted-secret --vault "$vault"

if [[ -n "$storage" ]]; then
  set_secret remote-password "remote-secret-value" --storage "$storage" --content-type text/plain --tag env=remote
  case "$storage" in
    # Properties are per secret there: one version cannot be disabled alone.
    aws-secrets-manager) ;;
    *)
      set_secret remote-rotated-key "old" --storage "$storage"
      set_secret remote-rotated-key "new"
      "$cli" secret update remote-rotated-key --vault "$vault" --disable
      ;;
  esac
fi

# The same vault under another vault's name (renamed, copied or swapped in).
cp "$home/vaults/$vault.sorvault" "$home/vaults/$vault-copy.sorvault"

# Oldest version id of database-password (`versions` lists newest first).
old_version="$("$cli" secret versions database-password --vault "$vault" -o json \
  | tr -d '\n' | grep -o '"version": *"[0-9a-f]*"' | tail -1 | grep -o '[0-9a-f]*"$' | tr -d '"')"
if [[ -z "$old_version" ]]; then
  echo "fixture-vault: could not read the version list" >&2
  exit 1
fi

project_dir="$home/project"
mkdir -p "$project_dir"
cat > "$project_dir/sourceorrery.toml" <<EOF
[project]
name = "ci-project"
vault = "$vault"

[secrets.database-password]
purpose = "Read by every SDK test suite"

[secrets.rotated-key]
env = "ROTATED"

[secrets.missing-optional]
required = false

[secrets.expired-token]
required = false
EOF

"$cli" check --manifest "$project_dir/sourceorrery.toml" >/dev/null

vars=(
  "SOURCEORRERY_HOME=$home"
  "SOURCEORRERY_RECOVERY_KEY=$SOURCEORRERY_RECOVERY_KEY"
  "SOURCEORRERY_TEST_VAULT=$vault"
  "SOURCEORRERY_TEST_MANIFEST=$project_dir/sourceorrery.toml"
  "SOURCEORRERY_TEST_OLD_VERSION=$old_version"
  "SOURCEORRERY_NATIVE_DIR=$native_dir"
  "SOURCEORRERY_CLI=$cli"
)

if [[ -n "$storage" ]]; then
  # One secret from the vault file and one from the provider: the manifest
  # names neither place.
  remote_dir="$home/remote-project"
  mkdir -p "$remote_dir"
  cat > "$remote_dir/sourceorrery.toml" <<EOF
[project]
name = "remote-project"
vault = "$vault"

[secrets.database-password]

[secrets.remote-password]
EOF
  "$cli" check --manifest "$remote_dir/sourceorrery.toml" >/dev/null
  vars+=("SOURCEORRERY_TEST_REMOTE_MANIFEST=$remote_dir/sourceorrery.toml")
fi

if [[ -n "${GITHUB_ENV:-}" ]]; then
  printf '%s\n' "${vars[@]}" >> "$GITHUB_ENV"
  echo "fixture-vault: vault '$vault' created under $home; variables written to GITHUB_ENV"
else
  for v in "${vars[@]}"; do printf 'export %s\n' "$v"; done
fi
