#!/usr/bin/env bash
# Collect local reports; publishing remains the CI workflow's responsibility.
set -euo pipefail
repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo"
stage=all
check_only=false
no_build=false
while [ "$#" -gt 0 ]; do
  case "$1" in
    --check) check_only=true ;;
    --stage) if [ "$#" -lt 2 ]; then echo '--stage needs a value' >&2; exit 2; fi; shift; stage="$1" ;;
    --no-build) no_build=true ;;
    --help|-h)
      echo 'Usage: bash scripts/coverage/run.sh [--check] [--stage all|collect|dotnet|verify] [--no-build]'
      echo 'Default: create a disposable fixture and collect all reports on Ubuntu. No Sonar token or upload.'
      echo 'CI uses collect, then dotnet after the scanner build, then verify.'
      exit 0 ;;
    *) echo "Unknown argument: $1" >&2; exit 2 ;;
  esac
  shift
done
case "$stage" in all|collect|dotnet|verify) ;; *) echo 'Invalid coverage stage; use --help' >&2; exit 2 ;; esac
if "$no_build" && [ "$stage" != dotnet ]; then echo '--no-build is only valid with --stage dotnet' >&2; exit 2; fi
if [ "$(uname -s)" != Linux ]; then
  echo 'Full coverage requires Ubuntu/Linux. On Windows: pwsh scripts/coverage/run.ps1 -Check' >&2
  echo 'GitHub Actions generates all reports automatically after a push; local coverage is optional.' >&2
  exit 2
fi
python_command="${SOURCEORRERY_COVERAGE_PYTHON:-python3}"
export SOURCEORRERY_COVERAGE_PYTHON="$python_command"
missing=()
need() { command -v "$1" >/dev/null || missing+=("$1: $2"); }
need "$python_command" 'install Python 3.12 or set SOURCEORRERY_COVERAGE_PYTHON'
if [ "$stage" != verify ]; then
  need dotnet 'install the .NET 10 SDK'
fi
if [ "$stage" = all ] || [ "$stage" = collect ]; then
  for tool in cargo rustc rustup node npm go java mvn php gcc g++ gcov gcovr lcov pkg-config; do
    need "$tool" 'see docs/coverage.md for the Ubuntu prerequisites'
  done
fi
if [ "${#missing[@]}" -gt 0 ]; then
  printf 'Missing prerequisite: %s\n' "${missing[@]}" >&2
  exit 2
fi
if [ "$stage" != verify ]; then
  dotnet --list-sdks | grep -q '^10\.' || missing+=('the .NET 10 SDK')
fi
if [ "$stage" = all ] || [ "$stage" = collect ]; then
  node scripts/coverage/check-node.mjs || missing+=('resolve the Node/dependency checks above')
  "$python_command" -c 'import sys, coverage, pytest; assert sys.version_info >= (3, 11); assert hasattr(coverage, "Coverage")' 2>/dev/null || missing+=('Python coverage/pytest: pip install --require-hashes --only-binary :all: -r scripts/coverage/requirements.txt')
  "$python_command" - <<'PY' || missing+=('resolve the language toolchain versions above')
import pathlib
import re
import subprocess
import sys
import tomllib

def version(value):
    return tuple((list(map(int, value.split("."))) + [0, 0])[:3])

rust_min = tomllib.loads(pathlib.Path("Cargo.toml").read_text())["workspace"]["package"]["rust-version"]
go_min = re.search(r"^go ([\d.]+)$", pathlib.Path("bindings/go/go.mod").read_text(), re.M)[1]
checks = [(["rustc", "--version"], r"rustc ([\d.]+)", rust_min),
          (["go", "env", "GOVERSION"], r"go([\d.]+)", go_min),
          (["java", "-version"], r'(?:version "|openjdk )([\d.]+)', "25")]
ok = True
for command, pattern, minimum in checks:
    result = subprocess.run(command, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False)
    found = re.search(pattern, result.stdout)
    if result.returncode or not found or version(found[1]) < version(minimum):
        print(f"{command[0]} >= {minimum} is required", file=sys.stderr)
        ok = False
sys.exit(0 if ok else 1)
PY
  cargo llvm-cov --version >/dev/null 2>&1 || missing+=('cargo-llvm-cov 0.9.1')
  rustup component list --installed | grep -q '^llvm-tools' || missing+=('LLVM tools: rustup component add llvm-tools-preview')
  pkg-config --exists dbus-1 || missing+=('libdbus-1-dev')
  XDEBUG_MODE=coverage php -d ffi.enable=1 -r 'exit(PHP_VERSION_ID >= 80200 && extension_loaded("ffi") && extension_loaded("xdebug") && in_array("coverage", xdebug_info("mode"), true) ? 0 : 1);' || missing+=('PHP >=8.2 with FFI and Xdebug coverage')
  [ -f bindings/node/node_modules/@napi-rs/cli/package.json ] || missing+=('run npm ci --ignore-scripts --prefix bindings/node')
fi
if [ "${#missing[@]}" -gt 0 ]; then
  printf 'Missing prerequisite: %s\n' "${missing[@]}" >&2
  exit 2
fi
if "$check_only"; then
  echo "Prerequisites ready for coverage stage: $stage. No tests or uploads were run."
  exit 0
fi
mkdir -p coverage
if [ "$stage" = all ]; then
  # Always create a new test vault, independent of the caller's personal vault.
  CARGO_TARGET_DIR="$repo/target/coverage-fixture" cargo build --locked -p sourceorrery-cli -p sourceorrery-ffi
  fixture="$(mktemp -d "$repo/coverage/fixture.XXXXXX")"
  fixture_env="$fixture/environment"
  SOURCEORRERY_CLI="$repo/target/coverage-fixture/debug/sourceorrery" SOURCEORRERY_NATIVE_DIR="$repo/target/coverage-fixture/debug" \
    GITHUB_ENV="$fixture_env" bash scripts/ci/fixture-vault.sh "$fixture/home"
  while IFS= read -r entry; do
    case "$entry" in SOURCEORRERY_*=*) export "$entry" ;; *) echo 'Unexpected SDK fixture environment entry' >&2; exit 1 ;; esac
  done < "$fixture_env"
fi
if [ "$stage" = all ] || [ "$stage" = collect ]; then
  if [ -z "${SOURCEORRERY_VAULT_TEST_ADDR:-}" ] || [ -z "${SOURCEORRERY_AWS_TEST_ENDPOINT:-}" ]; then
    echo 'Provider server tests need disposable Vault/Moto endpoints; absent endpoints leave those paths uncovered.'
    echo 'The GitHub coverage job supplies both services. See docs/coverage.md for local options.'
  fi
  npm run sync --prefix site
  npm run astro --prefix site -- sync
  "$python_command" -m unittest discover -s scripts/coverage -p 'test_*.py'
  node --test scripts/coverage/*.test.mjs
  "$python_command" scripts/sonar/check-scope.py
  bash scripts/coverage/native.sh
  bash scripts/coverage/native.sh python
  bash scripts/coverage/native.sh node
  npm run typecheck --prefix bindings/node
  lcov --add-tracefile coverage/rust.lcov --add-tracefile coverage/rust-python.lcov \
    --add-tracefile coverage/rust-node.lcov --output-file coverage/rust-combined.lcov
  bash scripts/coverage/sdk.sh site
  bash scripts/coverage/sdk.sh go
  bash scripts/coverage/sdk.sh php
  mvn --batch-mode --no-transfer-progress -f bindings/java/pom.xml -Pcoverage clean verify
  mvn --batch-mode --no-transfer-progress -f bindings/java/pom.xml \
    org.apache.maven.plugins:maven-dependency-plugin:3.8.1:copy-dependencies \
    -DincludeScope=test -DoutputDirectory=target/sonar-libraries
fi
if [ "$stage" = all ] || [ "$stage" = dotnet ]; then
  : "${SOURCEORRERY_HOME:?Create the SDK test fixture first}"
  : "${SOURCEORRERY_NATIVE_DIR:?Build the SDK test C ABI first}"
  options=()
  if "$no_build"; then options=(--no-build --no-restore); fi
  dotnet test bindings/dotnet/SourceOrrery.Tests/SourceOrrery.Tests.csproj \
    -c Release -p:CollectCoverage=true "${options[@]}"
fi
if [ "$stage" = all ] || [ "$stage" = verify ]; then
  "$python_command" scripts/sonar/check-reports.py
  echo 'Coverage reports are ready in coverage/ and bindings/java/target/site/jacoco/. Nothing was uploaded.'
fi
