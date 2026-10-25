#!/usr/bin/env bash
# The feature combinations SourceOrrery supports, each built (and the
# headless ones tested) with whatever toolchain is selected: CI's `msrv`
# job runs this on the declared minimum Rust (REC09, B30).
#
#   RUSTUP_TOOLCHAIN=1.91.1 bash scripts/ci/feature-matrix.sh
#
# A bounded list, not every subset: the headless build of each crate that
# has features, each feature on its own on top of it, and the defaults
# (which the other jobs build and test). A combination missing here is not
# supported; add it here before documenting it.
set -euo pipefail

run() {
	echo "::group::$*"
	"$@"
	echo "::endgroup::"
}

# The CLI: headless, each feature alone, and every provider.
for features in "" os-keyring ui otlp provider-vault provider-aws provider-azure remote; do
	run cargo check --locked -p sourceorrery-cli --all-targets --no-default-features ${features:+--features "$features"}
done

# The C ABI over the read-only client: headless, and each feature alone.
# It builds `sourceorrery` with the same features.
for features in "" os-keyring provider-vault provider-aws provider-azure; do
	run cargo check --locked -p sourceorrery-ffi --all-targets --no-default-features ${features:+--features "$features"}
done

# The adapters with no provider (their default), and each provider alone.
for features in "" provider-vault provider-aws provider-azure; do
	run cargo check --locked -p sourceorrery-provider --all-targets ${features:+--features "$features"}
done

# Storage without the OS credential store.
run cargo check --locked -p sourceorrery-storage --all-targets --no-default-features

# The headless builds behave, not only compile: their tests run.
run cargo test --locked -p sourceorrery-storage --no-default-features
run cargo test --locked -p sourceorrery --no-default-features
run cargo test --locked -p sourceorrery-cli --no-default-features

# The native extensions, outside the workspace: their defaults and headless.
for root in bindings/python bindings/node; do
	run cargo check --locked --manifest-path "$root/Cargo.toml" --all-targets
	run cargo check --locked --manifest-path "$root/Cargo.toml" --all-targets --no-default-features
done
