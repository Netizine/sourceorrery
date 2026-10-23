#!/usr/bin/env bash
# Ubuntu coverage entry points (run after .github/actions/sdk-fixture):
#   bash scripts/coverage/native.sh          # Rust workspace, C ABI and C++
#   bash scripts/coverage/native.sh python   # PyO3 + Python wrapper coverage
#   bash scripts/coverage/native.sh node     # N-API + JavaScript wrapper coverage
#
# Install cargo-llvm-cov, llvm-tools-preview, gcc/g++/gcov, gcovr and python3
# beforehand. The extension modes also need the dependencies of sdk.sh;
# Node needs `npm ci` in bindings/node. This script installs no tools.
#
# Rust reports: coverage/rust{,-python,-node}.lcov. C++ executable header
# coverage: coverage/cpp.xml (Sonar generic format). The C ABI implementation
# is Rust, so the declaration-only C header must not receive invented coverage.
# coverage/compile_commands.json contains compiler arguments, never environment
# variables. Run the scanner in this checkout while the build files still exist.
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo"
mode="${1:-workspace}"
case "$mode" in
  workspace|python|node) ;;
  *) echo "usage: $0 [workspace|python|node]" >&2; exit 2 ;;
esac
if [ "$#" -gt 1 ] || [ "$(uname -s)" != Linux ]; then
  echo "native coverage requires Ubuntu/Linux and at most one mode argument" >&2
  exit 2
fi

require() {
  command -v "$1" >/dev/null || { echo "native coverage: install $1 first" >&2; exit 1; }
}
python_command="${SOURCEORRERY_COVERAGE_PYTHON:-python3}"
export SOURCEORRERY_COVERAGE_PYTHON="$python_command"
require cargo
require "$python_command"
cargo llvm-cov --version >/dev/null

# Fail instead of silently skipping SDK tests or using a developer's own vault.
for variable in SOURCEORRERY_HOME SOURCEORRERY_PASSPHRASE SOURCEORRERY_TEST_VAULT \
  SOURCEORRERY_TEST_MANIFEST SOURCEORRERY_TEST_OLD_VERSION; do
  if [ -z "${!variable:-}" ]; then
    echo "native coverage: $variable is missing; run the SDK fixture action first" >&2
    exit 1
  fi
done
if [ ! -d "$SOURCEORRERY_HOME" ] || [ ! -f "$SOURCEORRERY_TEST_MANIFEST" ]; then
  echo "native coverage: the exported SDK fixture paths do not exist" >&2
  exit 1
fi

coverage="$repo/coverage"
mkdir -p "$coverage" "$repo/target"
# show-env reads Cargo metadata and exports its target directory for reporting.
# Ordinary cargo/napi builds read CARGO_TARGET_DIR, not CARGO_LLVM_COV_TARGET_DIR.
export CARGO_TARGET_DIR="$repo/target/coverage-rust-$mode"
export CARGO_LLVM_COV_TARGET_DIR="$CARGO_TARGET_DIR"
# Do not let cargo-llvm-cov download missing toolchain components in this script.
export CARGO_LLVM_COV_SETUP=no
# Coverage requires symbols even if a caller sets release-profile overrides.
export CARGO_PROFILE_DEV_STRIP=none
export CARGO_PROFILE_DEV_DEBUG=2

if [ "$mode" != workspace ]; then
  cd "$repo/bindings/$mode"
fi
coverage_target=()
if [ "$mode" = node ]; then
  # napi always passes --target, including for a native build. Use that same
  # target when configuring and finding coverage objects under target/<triple>.
  rust_host="$(rustc -vV | awk '/^host: / { print $2 }')"
  coverage_target=(--target "$rust_host")
fi
# show-env is the supported interface for tests run by an external runtime.
# Capture first so an unsuccessful show-env cannot be hidden by process substitution.
coverage_env="$(cargo llvm-cov show-env --sh "${coverage_target[@]}")"
eval "$coverage_env"
cargo llvm-cov clean --workspace

verify_rust_report() {
  "$python_command" - "$1" "$2" <<'PY'
import pathlib
import sys

report, expected = pathlib.Path(sys.argv[1]), sys.argv[2]
records = report.read_text(encoding="utf-8").split("end_of_record")
for record in records:
    lines = record.splitlines()
    if any(line.startswith("SF:") and line.replace("\\", "/").endswith(expected) for line in lines):
        if any(line.startswith("DA:") and int(line.split(",")[1]) > 0 for line in lines):
            break
else:
    raise SystemExit(f"native coverage: no executed lines for {expected} in {report}")
PY
}

# Match the workspace's fast development KDF settings in the separate binding
# workspaces. The SourceOrrery crates themselves remain unoptimized.
extension_build_flags=(--locked --config 'profile.dev.package.argon2.opt-level=3'
  --config 'profile.dev.package.blake2.opt-level=3')

if [ "$mode" = python ]; then
  # This crate is outside the root workspace. Build the debug cdylib directly
  # so maturin's packaging-time `strip = true` cannot remove coverage metadata.
  # PyO3 exports PyInit__native; the standard interpreter suffix makes this the
  # local package's preferred extension, ahead of any previously built abi3 file.
  PYO3_PYTHON="$(command -v "$python_command")"
  export PYO3_PYTHON
  cargo build "${extension_build_flags[@]}"
  extension_suffix="$("$python_command" -c 'import sysconfig; print(sysconfig.get_config_var("EXT_SUFFIX"))')"
  cp "$CARGO_TARGET_DIR/debug/libsourceorrery_python.so" \
    "$repo/bindings/python/python/sourceorrery/_native$extension_suffix"
  export PYTHONPATH="$repo/bindings/python/python${PYTHONPATH:+:$PYTHONPATH}"
  bash "$repo/scripts/coverage/sdk.sh" python
  cargo llvm-cov report --lcov --output-path "$coverage/rust-python.lcov"
  verify_rust_report "$coverage/rust-python.lcov" bindings/python/src/lib.rs
  exit 0
fi

if [ "$mode" = node ]; then
  require node
  require npm
  if [ ! -x node_modules/.bin/napi ]; then
    echo "native coverage: run npm ci in bindings/node first" >&2
    exit 1
  fi
  # napi preserves the coverage flags and generates the normal local JS loader.
  # Arguments after the second -- are passed through to cargo by napi.
  npm run build:debug -- -- "${extension_build_flags[@]}"
  bash "$repo/scripts/coverage/sdk.sh" node
  cargo llvm-cov report "${coverage_target[@]}" --lcov --output-path "$coverage/rust-node.lcov"
  verify_rust_report "$coverage/rust-node.lcov" bindings/node/src/lib.rs
  exit 0
fi

require "${CC:-gcc}"
require "${CXX:-g++}"
require gcov
require gcovr
cc="$(command -v "${CC:-gcc}")"
cxx="$(command -v "${CXX:-g++}")"

# Preserve normal workspace features and tests. Stable Rust does not collect
# doctest coverage; ordinary cargo test still executes those doctests.
cargo test --workspace --locked
cargo build --locked -p sourceorrery-cli -p sourceorrery-ffi
cargo build --locked -p sourceorrery --example conformance
export SOURCEORRERY_NATIVE_DIR="$CARGO_TARGET_DIR/debug"
export SOURCEORRERY_CLI="$CARGO_TARGET_DIR/debug/sourceorrery"
export LD_LIBRARY_PATH="$SOURCEORRERY_NATIVE_DIR${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"

# A new directory prevents old .gcda counters contaminating repeated runs.
native_build="$(mktemp -d "$repo/target/coverage-native.XXXXXX")"
commands="$native_build/compile-commands.jsonl"
: > "$commands"

compile_native() {
  local compiler="$1" source="$2" name="$3"
  shift 3
  local object="$native_build/$name.o"
  local args=("$compiler" -Wall -Wextra -Werror -O0 -g
    -I "$repo/crates/sourceorrery-ffi/include" -I "$repo/bindings/cpp/include"
    "$@" -c "$repo/$source" -o "$object")
  "${args[@]}"
  "$python_command" - "$commands" "$repo" "$repo/$source" "${args[@]}" <<'PY'
import json
import sys

path, directory, source, *arguments = sys.argv[1:]
with open(path, "a", encoding="utf-8") as stream:
    stream.write(json.dumps({"directory": directory, "file": source, "arguments": arguments}) + "\n")
PY
  "$compiler" "$@" "$object" -L "$SOURCEORRERY_NATIVE_DIR" \
    -lsourceorrery_ffi -o "$native_build/$name"
}

# C driver execution contributes to the instrumented Rust FFI implementation.
compile_native "$cc" crates/sourceorrery-ffi/examples/smoke.c smoke_c
compile_native "$cc" crates/sourceorrery-ffi/examples/get_secret.c get_secret_c
compile_native "$cc" crates/sourceorrery-ffi/examples/conformance.c conformance_c
# GCC instrumentation measures the actual inline C++ wrapper implementation.
cpp_flags=(-std=c++17 --coverage -pthread -fprofile-update=atomic)
compile_native "$cxx" bindings/cpp/tests/reader_test.cpp reader_cpp "${cpp_flags[@]}"
compile_native "$cxx" bindings/cpp/examples/get_secret.cpp get_secret_cpp "${cpp_flags[@]}"
compile_native "$cxx" bindings/cpp/conformance/run.cpp conformance_cpp "${cpp_flags[@]}"

mkdir -p "$native_build/smoke-home"
"$native_build/smoke_c" "$native_build/smoke-home"
"$native_build/reader_cpp"
"$native_build/get_secret_c" "$SOURCEORRERY_TEST_VAULT" database-password >/dev/null
"$native_build/get_secret_cpp" "$SOURCEORRERY_TEST_VAULT" database-password >/dev/null
for language in c cpp rust; do
  binary="$native_build/conformance_$language"
  if [ "$language" = rust ]; then binary="$CARGO_TARGET_DIR/debug/examples/conformance"; fi
  runner_command="$("$python_command" -c 'import shlex, sys; print(shlex.quote(sys.argv[1]))' "$binary")"
  "$python_command" tests/conformance/sdk/harness.py --runner "$language" --command "$runner_command"
done

cargo llvm-cov report --lcov --output-path "$coverage/rust.lcov"
verify_rust_report "$coverage/rust.lcov" crates/sourceorrery-ffi/src/reader.rs
gcovr --root "$repo" --filter 'bindings/cpp/include/sourceorrery\.hpp$' \
  --sonarqube "$coverage/cpp.xml" "$native_build"

"$python_command" - "$commands" "$coverage/compile_commands.json" "$coverage/cpp.xml" <<'PY'
import json
import pathlib
import sys
import xml.etree.ElementTree as ET

commands, output, report = map(pathlib.Path, sys.argv[1:])
output.write_text(json.dumps([json.loads(line) for line in commands.read_text(encoding="utf-8").splitlines()], indent=2) + "\n", encoding="utf-8")
root = ET.parse(report).getroot()
files = [file for file in root.findall("file") if file.attrib["path"].replace("\\", "/").endswith("bindings/cpp/include/sourceorrery.hpp")]
if root.tag != "coverage" or not any(line.attrib.get("covered") == "true" for file in files for line in file.findall("lineToCover")):
    raise SystemExit("native coverage: cpp.xml contains no executed C++ wrapper lines")
PY
echo "Native coverage: coverage/rust.lcov, coverage/cpp.xml, coverage/compile_commands.json"
