#!/usr/bin/env bash
# Proves, against a Vault dev server, that the HashiCorp Vault provider
# authenticates with a platform identity and honours Vault's decisions:
#
#   * AppRole login (VAULT_ROLE_ID / VAULT_SECRET_ID), no stored token;
#   * JWT login (VAULT_AUTH_ROLE / VAULT_JWT_FILE) with a token minted here
#     and validated by a public key configured on the server, the path a
#     GitHub Actions or Kubernetes workload identity takes;
#   * a policy that allows metadata but not values: `check` says ok,
#     `check --access` and `secret get` say permission_denied;
#   * a revoked token: unauthenticated.
#
#   SOURCEORRERY_CLI=target/release/sourceorrery VAULT_ADDR=http://127.0.0.1:8200 VAULT_TOKEN=root \
#     bash scripts/ci/vault-federation.sh
#
# Every secret value here is a fixture; nothing is printed but outcomes.
set -euo pipefail

cli="${SOURCEORRERY_CLI:?set SOURCEORRERY_CLI to the sourceorrery binary}"
addr="${VAULT_ADDR:-http://127.0.0.1:8200}"
root="${VAULT_TOKEN:?set VAULT_TOKEN to the dev server root token}"
mount="federation-$$"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
export SOURCEORRERY_HOME="$work/home"   # no local vaults; HOME keeps ~/.vault-token out
export HOME="$work/empty-home"
mkdir -p "$SOURCEORRERY_HOME" "$HOME" "$work/project"

api() { # METHOD PATH [JSON]
  local method="$1" path="$2" body="${3:-}"
  if [ -n "$body" ]; then
    curl -sS -f -o /dev/null -X "$method" -H "X-Vault-Token: $root" -d "$body" "$addr/v1/$path"
  else
    curl -sS -f -o /dev/null -X "$method" -H "X-Vault-Token: $root" "$addr/v1/$path"
  fi
}
json() { # METHOD PATH [JSON] -> stdout
  local method="$1" path="$2" body="${3:-}"
  if [ -n "$body" ]; then
    curl -sS -f -X "$method" -H "X-Vault-Token: $root" -d "$body" "$addr/v1/$path"
  else
    curl -sS -f -X "$method" -H "X-Vault-Token: $root" "$addr/v1/$path"
  fi
}
field() { python3 -I -c 'import json,sys; d=json.load(sys.stdin)
for k in sys.argv[1].split("."): d=d[k]
print(d)' "$1"; }
pass() { echo "PASS  $1"; }
fail() { echo "FAIL  $1"; exit 1; }
# Run the CLI with only the named environment, in the project directory.
run_as() { # VAR=value... -- args
  local vars=()
  while [ "$1" != "--" ]; do vars+=("$1"); shift; done; shift
  (cd "$work/project" && env -u VAULT_TOKEN -u VAULT_ROLE_ID -u VAULT_SECRET_ID -u VAULT_AUTH_ROLE -u VAULT_JWT_FILE -u VAULT_JWT \
     NO_COLOR=1 "${vars[@]}" "$cli" "$@")
}

api POST "sys/mounts/$mount" '{"type":"kv","options":{"version":"2"}}'
cat > "$work/project/sourceorrery.toml" <<TOML
[project]
name = "federation"
vault = "remote"

[secrets.database-password]

[vaults.remote]
provider = "hashicorp-vault"
address = "$addr"
mount = "$mount"
TOML
printf 'federation-fixture-value' | run_as VAULT_TOKEN="$root" -- secret set database-password --vault remote --stdin > /dev/null

reader_policy="path \"$mount/data/*\" { capabilities = [\"read\"] }
path \"$mount/metadata/*\" { capabilities = [\"read\", \"list\"] }
path \"$mount/metadata\" { capabilities = [\"list\"] }
path \"sys/internal/ui/mounts/$mount\" { capabilities = [\"read\"] }"
metadata_policy="path \"$mount/metadata/*\" { capabilities = [\"read\", \"list\"] }
path \"sys/internal/ui/mounts/$mount\" { capabilities = [\"read\"] }"
api PUT "sys/policies/acl/$mount-reader" "$(python3 -I -c 'import json,sys; print(json.dumps({"policy": sys.argv[1]}))' "$reader_policy")"
api PUT "sys/policies/acl/$mount-metadata" "$(python3 -I -c 'import json,sys; print(json.dumps({"policy": sys.argv[1]}))' "$metadata_policy")"

# --- AppRole --------------------------------------------------------------
api POST "sys/auth/approle-$mount" '{"type":"approle"}'
api POST "auth/approle-$mount/role/ci" "{\"token_policies\":[\"$mount-reader\"],\"token_ttl\":\"1h\"}"
role_id="$(json GET "auth/approle-$mount/role/ci/role-id" | field data.role_id)"
secret_id="$(json POST "auth/approle-$mount/role/ci/secret-id" | field data.secret_id)"
out="$(run_as VAULT_ROLE_ID="$role_id" VAULT_SECRET_ID="$secret_id" VAULT_AUTH_MOUNT="approle-$mount" -- secret get database-password --vault remote --reveal -o json)"
grep -q '"value": *"federation-fixture-value"' <<<"$out" && pass "AppRole login reads the secret" || fail "AppRole login: $out"

# --- JWT with a key minted here -------------------------------------------
openssl genrsa -out "$work/jwt.key" 2048 2>/dev/null
openssl rsa -in "$work/jwt.key" -pubout -out "$work/jwt.pub" 2>/dev/null
api POST "sys/auth/jwt-$mount" '{"type":"jwt"}'
api POST "auth/jwt-$mount/config" "$(python3 -I -c 'import json,sys; print(json.dumps({"jwt_validation_pubkeys": [open(sys.argv[1]).read()]}))' "$work/jwt.pub")"
api POST "auth/jwt-$mount/role/ci" "{\"role_type\":\"jwt\",\"bound_audiences\":[\"sourceorrery-ci\"],\"user_claim\":\"sub\",\"token_policies\":[\"$mount-reader\"],\"token_ttl\":\"1h\"}"
b64() { openssl base64 -A | tr '+/' '-_' | tr -d '='; }
header="$(printf '{"alg":"RS256","typ":"JWT"}' | b64)"
now="$(date +%s)"
payload="$(printf '{"sub":"repo:example/app:ref:refs/heads/main","aud":"sourceorrery-ci","iat":%d,"exp":%d}' "$now" "$((now + 3600))" | b64)"
signature="$(printf '%s.%s' "$header" "$payload" | openssl dgst -sha256 -sign "$work/jwt.key" | b64)"
printf '%s.%s.%s' "$header" "$payload" "$signature" > "$work/token.jwt"
out="$(run_as VAULT_AUTH_ROLE=ci VAULT_JWT_FILE="$work/token.jwt" VAULT_AUTH_MOUNT="jwt-$mount" -- secret get database-password --vault remote --reveal -o json)"
grep -q '"value": *"federation-fixture-value"' <<<"$out" && pass "JWT login reads the secret" || fail "JWT login: $out"
# The same token with a wrong audience is refused as unauthenticated.
bad_payload="$(printf '{"sub":"x","aud":"someone-else","iat":%d,"exp":%d}' "$now" "$((now + 3600))" | b64)"
bad_signature="$(printf '%s.%s' "$header" "$bad_payload" | openssl dgst -sha256 -sign "$work/jwt.key" | b64)"
printf '%s.%s.%s' "$header" "$bad_payload" "$bad_signature" > "$work/bad.jwt"
if run_as VAULT_AUTH_ROLE=ci VAULT_JWT_FILE="$work/bad.jwt" VAULT_AUTH_MOUNT="jwt-$mount" -- secret get database-password --vault remote -o json > /dev/null 2> "$work/err.json"; then
  fail "a JWT for another audience was accepted"
fi
grep -q '"code": *"unauthenticated"' "$work/err.json" && pass "a JWT for another audience is unauthenticated" || fail "wrong audience: $(cat "$work/err.json")"

# --- Policy decides: metadata allowed, value denied ------------------------
denied="$(json POST "auth/token/create" "{\"policies\":[\"$mount-metadata\"],\"ttl\":\"1h\"}" | field auth.client_token)"
run_as VAULT_TOKEN="$denied" -- check > /dev/null && pass "check (metadata only) passes for an identity that may inspect" || fail "check with metadata access"
if run_as VAULT_TOKEN="$denied" -- check --access -o json > "$work/check.json" 2> /dev/null; then
  fail "check --access passed for an identity that may not read values"
fi
grep -q '"status": *"permission_denied"' "$work/check.json" && pass "check --access reports permission_denied per secret" || fail "check --access: $(cat "$work/check.json")"
# `secret get` without --reveal reads metadata only, which this policy allows.
if run_as VAULT_TOKEN="$denied" -- secret get database-password --vault remote --reveal -o json > /dev/null 2> "$work/err.json"; then
  fail "a denied read succeeded"
fi
grep -q '"code": *"permission_denied"' "$work/err.json" && pass "a denied read is permission_denied" || fail "denied read: $(cat "$work/err.json")"

# --- Revocation takes effect on the next request --------------------------
api POST "auth/token/revoke" "{\"token\":\"$denied\"}"
if run_as VAULT_TOKEN="$denied" -- secret get database-password --vault remote -o json > /dev/null 2> "$work/err.json"; then
  fail "a revoked token was accepted"
fi
grep -q '"code": *"unauthenticated"' "$work/err.json" && pass "a revoked token is unauthenticated" || fail "revoked: $(cat "$work/err.json")"

api DELETE "sys/mounts/$mount"
api DELETE "sys/auth/approle-$mount"
api DELETE "sys/auth/jwt-$mount"
echo "vault-federation: every check passed"
