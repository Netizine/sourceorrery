# ADR 0007: Versioning and compatibility

**Status:** accepted, amended for 0.3.0 · **Date:** 2026-10-22 · **Amended:** 2026-10-25

## Context

One SourceOrrery release uses one version across the CLI, public Rust
crates, C ABI and language SDKs. An application can accidentally load a
native library from another release, and a vault can outlive the binary
that wrote it. Version and format checks must reject combinations whose
meaning or layout differs.

## Decision

SourceOrrery follows Semantic Versioning. Before 1.0, a minor release may
change or remove APIs and file formats; patch releases preserve the
current minor's supported surfaces. There is no cross-minor deprecation
window or legacy compatibility layer promised before 1.0. Changes must be
described in the changelog and current documentation.

The 0.3.0 baseline is **vault schema 5**, **C ABI 2**, **contract 2**.
Older vault formats are refused and left unchanged. There is no `vault
migrate` command or automatic conversion. [Supported files](../upgrading.md)

| Surface | Versioned behaviour |
|---------|---------------------|
| CLI | Commands, flags, exit codes, JSON output and environment variables. |
| Rust API | Public `sourceorrery` and `sourceorrery-core` APIs; `cargo semver-checks` validates the proposed release bump. |
| C ABI | Header declarations and `SO_ABI_VERSION`. An incompatible change bumps the ABI; bindings reject a different ABI with `abi_mismatch`. |
| Contract | Shared conformance semantics, identified by `CONTRACT_VERSION`. An incompatible semantic change bumps it. |
| SDK API | Public methods, option types, values and error mapping in each language. |
| Vault file | Authenticated `schema_version` and the [format reference](../vault-format.md). Only the supported schema opens; no implicit migration. |
| Error/audit names | Stable, append-only code and operation labels. Retaining a label does not make a removed command available. |
| Manifest | Accepted fields and their meanings; unsupported or unknown fields are refused. |

## Checks

- `scripts/ci/abi-check.py` compares the current header with the release
  baseline and requires an ABI bump when an existing declaration changes.
- `abi-compat` runs the earlier contract against the current library only
  when the ABI matches. A bumped ABI deliberately ends that compatibility.
- C ABI wrappers check `so_abi_version()` before opening a vault. Python
  and Node native extensions embed the Rust client instead.
- The release workflow runs Rust semver checks and the exact-commit CI
  gate. It does not make a breaking patch acceptable merely because local
  tests passed.
- Conformance tests check contract semantics. Storage tests establish that
  unsupported files are refused without conversion or destructive cleanup.

## Consequences

Use packages from the same release. Matching ABI checks protect the
native call boundary; they do not authenticate a library or establish that
code is safe. Minor releases can require fresh provisioning or application
changes, while published versions and release assets remain immutable.

ADR 0009 changes the unlock/check/storage model, and ADR 0010 introduces
authenticated key-wrap inventory in schema 5. The prior proposal for an
explicit migration command and a mandatory pre-1.0 deprecation interval
is superseded by this amendment.
