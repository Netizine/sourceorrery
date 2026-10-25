#!/usr/bin/env bash
# LocalStack for the remote provider jobs (ci.yml provider-aws and
# provider-azure, coverage.yml), through lstk installed from
# scripts/ci/lstk's lock file.
#
#   bash scripts/ci/localstack.sh select [aws|azure]  # is the auth token there?
#   bash scripts/ci/localstack.sh start  [aws|azure]  # lstk start; returns once ready
#   bash scripts/ci/localstack.sh stop   [aws|azure]
#   bash scripts/ci/localstack.sh logs   [aws|azure]  # $RUNNER_TEMP/localstack/*.log
#
# The emulator defaults to aws (.lstk/config.toml); azure is .lstk/azure.toml.
# LOCALSTACK_AUTH_TOKEN holds the token for the one being started: the
# repository secret LOCALSTACK_AUTH_TOKEN for AWS, LOCALSTACK_AZURE_AUTH_TOKEN
# for Azure. `select` writes `available=true|false` to $GITHUB_OUTPUT and,
# when the token is there, the test endpoint (and, for Azure, the emulator's
# placeholder identity) to $GITHUB_ENV; `stop` clears them again. A pull
# request from a fork (FORK=true) gets no repository secrets: its emulator
# tests are skipped with a warning. Any other run without the token fails.
# Every start is fresh: no persistence, no snapshot. The two emulators bind
# the same ports and cannot run at once.
set -euo pipefail
repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
lstk="$repo/scripts/ci/lstk/node_modules/.bin/lstk"
action="${1:-}"
emulator="${2:-aws}"

case "$emulator" in
  aws)
    config=()
    secret=LOCALSTACK_AUTH_TOKEN
    environment=(SOURCEORRERY_AWS_TEST_ENDPOINT=http://127.0.0.1:4566)
    ;;
  azure)
    config=(--config "$repo/.lstk/azure.toml")
    secret=LOCALSTACK_AZURE_AUTH_TOKEN
    endpoint=https://azure.localhost.localstack.cloud:4567
    # The emulator accepts any client and secret in its one tenant
    # (https://docs.localstack.cloud/azure/connecting/credentials/); any-app
    # is the principal its examples use, which may create vaults.
    environment=(SOURCEORRERY_AZURE_TEST_ENDPOINT="$endpoint" AZURE_AUTHORITY_HOST="$endpoint"
      AZURE_TENANT_ID=00000000-0000-0000-0000-000000000000 AZURE_CLIENT_ID=any-app
      AZURE_CLIENT_SECRET=emulator-placeholder)
    ;;
  *)
    echo "usage: $0 select|start|stop|logs [aws|azure]" >&2
    exit 2
    ;;
esac

case "$action" in
  select)
    if [[ -n "${LOCALSTACK_AUTH_TOKEN:-}" ]]; then
      printf '%s\n' "${environment[@]}" >> "$GITHUB_ENV"
      echo 'available=true' >> "$GITHUB_OUTPUT"
    elif [[ "${FORK:-false}" == true ]]; then
      message="$secret is not given to pull requests from forks, so the $emulator emulator tests did not run; they run after merge"
      echo "::warning title=$emulator emulator tests skipped::$message"
      echo "$message." >> "$GITHUB_STEP_SUMMARY"
      echo 'available=false' >> "$GITHUB_OUTPUT"
    else
      echo "::error title=$secret is missing::add a LocalStack CI auth token as the repository secret $secret"
      exit 1
    fi
    ;;
  start)
    npm ci --ignore-scripts --no-fund --no-audit --prefix "$repo/scripts/ci/lstk"
    # From the repository root, so lstk finds .lstk/config.toml for AWS.
    cd "$repo"
    "$lstk" "${config[@]}" start --non-interactive --no-snapshot
    ;;
  stop)
    cd "$repo"
    "$lstk" "${config[@]}" stop --non-interactive
    if [[ -n "${GITHUB_ENV:-}" ]]; then
      for entry in "${environment[@]}"; do echo "${entry%%=*}=" >> "$GITHUB_ENV"; done
    fi
    ;;
  logs)
    out="${RUNNER_TEMP:?}/localstack"
    mkdir -p "$out"
    cd "$repo"
    if [[ -x "$lstk" ]]; then
      "$lstk" "${config[@]}" logs --verbose --non-interactive > "$out/$emulator-localstack.log" 2>&1 \
        || echo 'lstk logs failed; its output is in the log file'
    fi
    if [[ -f .lstk/lstk.log ]]; then cp .lstk/lstk.log "$out/lstk.log"; fi
    # An artifact is not masked like the job log: never upload the token.
    python3 -c '
import os, pathlib, sys
token = os.environ.get("LOCALSTACK_AUTH_TOKEN", "")
for path in pathlib.Path(sys.argv[1]).glob("*.log"):
    text = path.read_text(encoding="utf-8", errors="replace")
    if token and token in text:
        path.write_text(text.replace(token, "***"), encoding="utf-8")
' "$out"
    if [[ -f "$out/$emulator-localstack.log" ]]; then tail -n 200 "$out/$emulator-localstack.log"; fi
    ;;
  *)
    echo "usage: $0 select|start|stop|logs [aws|azure]" >&2
    exit 2
    ;;
esac
