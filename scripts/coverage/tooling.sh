#!/usr/bin/env bash
# Measure the existing repository-tool tests without invoking real publishers.
set -euo pipefail
repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo"
python_command="${SOURCEORRERY_COVERAGE_PYTHON:-python3}"
config="$repo/scripts/coverage/tooling.coveragerc"
mkdir -p coverage/tooling-python
"$python_command" -m coverage erase --rcfile="$config"
for suite in scripts/ci scripts/coverage scripts/release scripts/sonar; do
  "$python_command" -m coverage run --append --rcfile="$config" \
    -m unittest discover -s "$suite" -p '*test*.py'
done
"$python_command" -m coverage run --append --rcfile="$config" scripts/sonar/check-scope.py
"$python_command" -m coverage xml --rcfile="$config"
node scripts/coverage/node_modules/c8/bin/c8.js --all --src scripts \
  --include 'scripts/**/*.mjs' --exclude '**/*.test.mjs' \
  --reporter=lcovonly --reporter=text-summary \
  --reports-dir coverage/tooling-node --temp-directory coverage/tooling-node/tmp \
  node --test scripts/coverage/*.test.mjs
