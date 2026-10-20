#!/usr/bin/env bash
# Local helper: create the fixture vault once (into target/fixture.env) and
# run a command with its environment. Mirrors what the CI jobs do.
#
#   bash scripts/ci/run-local.sh <command...>
#
# Delete target/fixture.env to start from a fresh vault.
set -euo pipefail
repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
env_file="$repo/target/fixture.env"
if [ ! -f "$env_file" ]; then
  mkdir -p "$repo/target"
  bash "$repo/scripts/ci/fixture-vault.sh" > "$env_file"
fi
# shellcheck disable=SC1090
source "$env_file"
exec "$@"
