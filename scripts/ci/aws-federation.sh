#!/usr/bin/env bash
# Proves, against a Secrets Manager emulator, that the AWS provider takes
# its credentials from the SDK's default chain and nothing else:
#
#   * web identity (AWS_WEB_IDENTITY_TOKEN_FILE and AWS_ROLE_ARN, the path a
#     GitHub Actions or Kubernetes workload identity takes) is exchanged at
#     STS and reads the secret, with no access key anywhere;
#   * no credentials at all is unauthenticated before any request.
#
#   SOURCEORRERY_CLI=target/release/sourceorrery SOURCEORRERY_AWS_TEST_ENDPOINT=http://127.0.0.1:4566 \
#     bash scripts/ci/aws-federation.sh
set -euo pipefail

cli="${SOURCEORRERY_CLI:?set SOURCEORRERY_CLI to the sourceorrery binary}"
endpoint="${SOURCEORRERY_AWS_TEST_ENDPOINT:?set SOURCEORRERY_AWS_TEST_ENDPOINT to the emulator}"
region="${AWS_REGION:-us-east-1}"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
export SOURCEORRERY_HOME="$work/home"
export HOME="$work/empty-home"           # no ~/.aws files
# The vault opens with its recovery key; nothing touches the OS credential
# store. The job's SOURCEORRERY_RECOVERY_KEY is the fixture vault's, and the
# CLI would try it first.
unset SOURCEORRERY_RECOVERY_KEY
export SOURCEORRERY_KEYRING=off SOURCEORRERY_RECOVERY_KEY_FILE="$work/remote.key"
mkdir -p "$SOURCEORRERY_HOME" "$HOME" "$work/project"
pass() { echo "PASS  $1"; }
fail() { echo "FAIL  $1"; exit 1; }
run_as() { # VAR=value... -- args
  local vars=()
  while [[ "$1" != "--" ]]; do vars+=("$1"); shift; done; shift
  (cd "$work/project" && env -u AWS_ACCESS_KEY_ID -u AWS_SECRET_ACCESS_KEY -u AWS_SESSION_TOKEN -u AWS_PROFILE \
     -u AWS_WEB_IDENTITY_TOKEN_FILE -u AWS_ROLE_ARN -u AWS_ENDPOINT_URL \
     NO_COLOR=1 AWS_REGION="$region" AWS_EC2_METADATA_DISABLED=true "${vars[@]}" "$cli" "$@")
}

# A connection without a stored access key: every identity below is the
# environment's.
run_as -- vault create remote --no-keyring --recovery-key-out "$work/remote.key" \
  --aws-secrets-manager "$region" --aws-secrets-manager-prefix "federation-$$/" \
  --aws-secrets-manager-endpoint "$endpoint" > /dev/null
cat > "$work/project/sourceorrery.toml" <<TOML
[project]
name = "federation"
vault = "remote"

[secrets.database-password]
TOML
printf 'federation-fixture-value' | run_as AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test -- secret set database-password --vault remote --stdin --storage aws-secrets-manager > /dev/null

# A web identity token: the emulator's STS accepts any JWT shape. The role is
# in the account the `test` access key maps to (LocalStack's default): the
# emulator keeps accounts apart, so a role elsewhere would see no secrets.
printf 'eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJyZXBvOmV4YW1wbGUvYXBwIn0.sig' > "$work/web-identity.jwt"
out="$(run_as AWS_WEB_IDENTITY_TOKEN_FILE="$work/web-identity.jwt" AWS_ROLE_ARN="arn:aws:iam::000000000000:role/sourceorrery-ci" AWS_ENDPOINT_URL="$endpoint" -- secret get database-password --vault remote --reveal -o json)"
grep -q '"value": *"federation-fixture-value"' <<<"$out" && pass "web identity exchanged at STS reads the secret" || fail "web identity: $out"

if run_as -- secret get database-password --vault remote -o json > /dev/null 2> "$work/err.json"; then
  fail "a process with no credentials read the secret"
fi
grep -q '"code": *"unauthenticated"' "$work/err.json" && pass "no credentials is unauthenticated" || fail "no credentials: $(cat "$work/err.json")"
echo "aws-federation: every check passed"
