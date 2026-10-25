#!/usr/bin/env bash
# Run from any directory after installing the SDK dependencies and creating the
# shared fixture. Native extensions must already be built; instrumentation
# variables supplied by cargo-llvm-cov are deliberately preserved.
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo"
python_command="${SOURCEORRERY_COVERAGE_PYTHON:-python}"
mode="${1:-}"
case "$mode" in
  python|node|go|php)
    for name in SOURCEORRERY_HOME SOURCEORRERY_RECOVERY_KEY SOURCEORRERY_TEST_VAULT SOURCEORRERY_TEST_MANIFEST SOURCEORRERY_TEST_OLD_VERSION; do
      if [[ -z "${!name:-}" ]]; then
        echo "coverage: $name is missing; run scripts/ci/fixture-vault.sh first" >&2
        exit 2
      fi
    done
    ;;
  site) ;;
  *) echo 'usage: bash scripts/coverage/sdk.sh python|node|site|go|php' >&2; exit 2 ;;
esac
mkdir -p coverage

case "$mode" in
  python)
    # A regular wheel would measure site-packages rather than the checked-in API.
    "$python_command" -c 'from pathlib import Path; import sourceorrery; expected = Path("bindings/python/python/sourceorrery").resolve(); actual = Path(sourceorrery.__file__).resolve().parent; assert actual == expected, "coverage requires the checked-in Python SDK source; use native.sh python or an editable install, not an installed wheel"'
    mkdir -p coverage/python
    "$python_command" -m coverage run --rcfile=scripts/coverage/python.coveragerc -m pytest bindings/python/tests -v
    "$python_command" -m coverage xml --rcfile=scripts/coverage/python.coveragerc
    ;;
  node|site)
    c8="$repo/scripts/coverage/node_modules/c8/bin/c8.js"
    if [[ ! -f "$c8" ]]; then
      echo 'coverage: install the isolated tools with npm ci --prefix scripts/coverage' >&2
      exit 2
    fi
    if [[ "$mode" == node ]]; then
      node "$c8" --all --src bindings/node/lib --include 'bindings/node/lib/**/*.js' \
        --reporter=lcovonly --reporter=text-summary --reports-dir coverage/node --temp-directory coverage/node/tmp \
        node --test bindings/node/__test__/*.test.mjs
    else
      site_options=(--all --src site/plugins --src site/src/lib --src site/scripts
        --include 'site/plugins/**/*.mjs' --include 'site/src/lib/**/*.mjs' --include 'site/scripts/**/*.mjs'
        --exclude '**/*.test.mjs' --reporter=lcovonly --reporter=text-summary
        --reports-dir coverage/site --temp-directory coverage/site/tmp)
      node "$c8" "${site_options[@]}" node --test site/scripts/*.test.mjs
      # The existing build checks sync, Astro plugins and rendered local links.
      # Preserve the unit-test execution data when adding this integration run.
      ASTRO_TELEMETRY_DISABLED=1 node "$c8" "${site_options[@]}" --clean=false npm --prefix site run build
    fi
    ;;
  go)
    : "${SOURCEORRERY_NATIVE_DIR:?Build the C ABI and create the SDK fixture first}"
    export CGO_ENABLED=1
    # Go only recognizes quoting around a whole argument, not after -L.
    export CGO_LDFLAGS="${CGO_LDFLAGS:-} \"-L$SOURCEORRERY_NATIVE_DIR\""
    export LD_LIBRARY_PATH="$SOURCEORRERY_NATIVE_DIR${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
    (
      cd bindings/go
      go test -count=1 -covermode=atomic -coverpkg=github.com/netizine/sourceorrery/bindings/go \
        -coverprofile="$repo/coverage/go.raw.out" ./...
    )
    # Keep the native Go format, but resolve source names from Sonar's repo root.
    sed 's|^github.com/netizine/sourceorrery/bindings/go/|bindings/go/|' coverage/go.raw.out > coverage/go.out
    ;;
  php)
    : "${SOURCEORRERY_NATIVE_DIR:?Build the C ABI and create the SDK fixture first}"
    XDEBUG_MODE=coverage php -d ffi.enable=1 -d opcache.enable_cli=0 \
      -d auto_prepend_file="$repo/scripts/coverage/php-prepend.php" bindings/php/tests/run.php
    "$python_command" -m coverage run --append --rcfile=scripts/coverage/tooling.coveragerc \
      scripts/coverage/php-report.py coverage/php.json coverage/php.xml
    ;;
esac
