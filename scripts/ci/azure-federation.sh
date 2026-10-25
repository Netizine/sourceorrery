#!/usr/bin/env bash
# Proves, against an Azure Key Vault emulator with role-based access
# enforced, that the Azure provider signs in as the identity the
# environment gives it and nothing else:
#
#   * a service principal from AZURE_CLIENT_ID and AZURE_CLIENT_SECRET
#     reads the secret, with nothing in the vault's connection but its URL;
#   * another principal, without a role on the vault, is refused as
#     permission_denied;
#   * no identity at all is unauthenticated before any request.
#
# The emulator does not exchange federated tokens for a managed identity,
# so workload identity federation is covered by the SDK's own tests only.
#
#   SOURCEORRERY_CLI=target/release/sourceorrery \
#   SOURCEORRERY_AZURE_TEST_ENDPOINT=https://azure.localhost.localstack.cloud:4566 \
#   AZURE_TENANT_ID=00000000-0000-0000-0000-000000000000 AZURE_CLIENT_ID=ci AZURE_CLIENT_SECRET=ci \
#     bash scripts/ci/azure-federation.sh
set -euo pipefail

cli="${SOURCEORRERY_CLI:?set SOURCEORRERY_CLI to the sourceorrery binary}"
endpoint="${SOURCEORRERY_AZURE_TEST_ENDPOINT:?set SOURCEORRERY_AZURE_TEST_ENDPOINT to the emulator}"
tenant="${AZURE_TENANT_ID:?set AZURE_TENANT_ID}"
client="${AZURE_CLIENT_ID:?set AZURE_CLIENT_ID}"
secret="${AZURE_CLIENT_SECRET:?set AZURE_CLIENT_SECRET}"
repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
python_command="${SOURCEORRERY_COVERAGE_PYTHON:-python3}"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
export SOURCEORRERY_HOME="$work/home"
# The vault opens with its recovery key; nothing touches the OS credential
# store. The job's SOURCEORRERY_RECOVERY_KEY is the fixture vault's, and the
# CLI would try it first.
unset SOURCEORRERY_RECOVERY_KEY
export SOURCEORRERY_KEYRING=off SOURCEORRERY_RECOVERY_KEY_FILE="$work/remote.key"
mkdir -p "$SOURCEORRERY_HOME" "$work/empty-home" "$work/azure-cli" "$work/project"
pass() { echo "PASS  $1"; }
fail() { echo "FAIL  $1"; exit 1; }
run_as() { # VAR=value... -- args
  local vars=()
  while [[ "$1" != "--" ]]; do vars+=("$1"); shift; done; shift
  # No Azure CLI sign-in and no ambient variables: only what each case gives.
  (cd "$work/project" && env -u AZURE_TENANT_ID -u AZURE_CLIENT_ID -u AZURE_CLIENT_SECRET \
     -u AZURE_FEDERATED_TOKEN_FILE -u AZURE_AUTHORITY_HOST -u IDENTITY_ENDPOINT -u MSI_ENDPOINT \
     HOME="$work/empty-home" AZURE_CONFIG_DIR="$work/azure-cli" AZURE_CORE_COLLECT_TELEMETRY=false \
     NO_COLOR=1 "${vars[@]}" "$cli" "$@")
}

vault_url="$("$python_command" "$repo/scripts/ci/azure-vault.py" "fed$$")"
# A connection without a stored service principal: every identity below is
# the environment's.
run_as -- vault create remote --no-keyring --recovery-key-out "$work/remote.key" \
  --azure-key-vault "$vault_url" > /dev/null
cat > "$work/project/sourceorrery.toml" <<TOML
[project]
name = "federation"
vault = "remote"

[secrets.database-password]
TOML
principal=(AZURE_TENANT_ID="$tenant" AZURE_CLIENT_ID="$client" AZURE_CLIENT_SECRET="$secret"
  AZURE_AUTHORITY_HOST="$endpoint")
printf 'federation-fixture-value' | run_as "${principal[@]}" -- secret set database-password --vault remote --stdin --storage azure-key-vault > /dev/null

out="$(run_as "${principal[@]}" -- secret get database-password --vault remote --reveal -o json)"
if grep -q '"value": *"federation-fixture-value"' <<<"$out"; then
  pass "a service principal from the environment reads the secret"
else
  fail "service principal: $out"
fi

if run_as AZURE_TENANT_ID="$tenant" AZURE_CLIENT_ID="sourceorrery-unprivileged" AZURE_CLIENT_SECRET="$secret" \
    AZURE_AUTHORITY_HOST="$endpoint" -- secret get database-password --vault remote -o json > /dev/null 2> "$work/denied.json"; then
  fail "a principal without a role on the vault read the secret"
fi
if grep -q '"code": *"permission_denied"' "$work/denied.json"; then
  pass "a principal without a role is refused as permission_denied"
else
  fail "no role: $(cat "$work/denied.json")"
fi

if run_as -- secret get database-password --vault remote -o json > /dev/null 2> "$work/err.json"; then
  fail "a process with no identity read the secret"
fi
if grep -q '"code": *"unauthenticated"' "$work/err.json"; then
  pass "no identity is unauthenticated"
else
  fail "no identity: $(cat "$work/err.json")"
fi
echo "azure-federation: every check passed"
