# ADR 0007: Versioning and compatibility

**Status:** accepted · **Date:** 2026-10-22

## Context

One release of SourceOrrery is one version number stamped into every
package: the CLI, the `sourceorrery` client crate, `sourceorrery-core`, the
C ABI library and each SDK (ADR 0006). Users combine them: an SDK built
against one release loads the C ABI library of another, a vault file
written by one release is opened by the next, a script parses the CLI's
JSON. Until now the repository said that the C ABI version "is bumped only
for incompatible changes" and nothing else about what a version number
promises or how a promise is checked.

## Decision

Releases follow [Semantic Versioning](https://semver.org). Before 1.0 a
**minor** release (`0.x` → `0.(x+1)`) may change behaviour and remove or
alter API; a **patch** release (`0.x.y` → `0.x.(y+1)`) may add but never
breaks. From 1.0 the usual rules apply. One number covers every surface,
so the release takes the largest bump any surface needs:

| Surface | What is covered | Compatible change | Incompatible change |
|---------|-----------------|-------------------|---------------------|
| CLI | commands, flags, exit codes, `-o json` output, environment variables | a new command, flag or JSON field | a removed or renamed command or flag, a changed JSON field, a changed exit code |
| Rust API | the public items of `sourceorrery` and `sourceorrery-core` (the crates SDKs and applications build on) | a new item, a new trait method with a default | anything `cargo semver-checks` reports as needing a bigger bump |
| C ABI | every declaration in `crates/sourceorrery-ffi/include/sourceorrery.h` | a new function, enum member or constant | a changed or removed function, struct, enum member or constant. **`SO_ABI_VERSION` is bumped** at the same time, and the bindings refuse the library |
| Contract | the semantics the conformance suite checks, named by `CONTRACT_VERSION` | a new operation or option | a changed outcome, code, message or hint for an existing scenario. **`CONTRACT_VERSION` is bumped** |
| SDK API | the public API of each binding | a new method or type | a removed or changed method; a changed exception hierarchy |
| Vault file | `schema_version` and the format in `docs/vault-format.md` | none: a newer schema is written only by `vault migrate` | a new schema, read only after an explicit migration; an older release refuses the file |
| Error codes and audit operations | `SecretError::code()` strings and `AuditOperation` labels | a new code or label | never: both lists are append-only |
| Manifest | `sourceorrery.toml` | a new optional key | a removed key or a changed meaning |

Rules that follow:

* **Deprecation before removal.** A surface slated for removal is marked
  deprecated in one minor release (a doc note, a compiler or runtime
  warning where the language has one) and removed in the next at the
  earliest.
* **Bindings check the ABI they load.** Every binding over the C ABI (Go,
  Java, .NET, PHP, C++) compares `so_abi_version()` with the
  `SO_ABI_VERSION` it was built against before it opens anything, and
  refuses a mismatch with its base error type and the code
  `abi_mismatch`. That code is produced by the bindings, never by the
  core, and is reserved alongside the core's codes. The Python and Node
  extensions build the core in, so they cannot mismatch.
* **Additions never bump the ABI.** A new C function, enum member or
  constant is a compatible change; existing declarations do not move.
  Anything else bumps `SO_ABI_VERSION`, in the same commit.
* **The previous release must keep working.** The C ABI library of the
  current commit must pass the conformance contract of the latest
  release (its runner, its harness, its scenarios) unless
  `SO_ABI_VERSION` was bumped, in which case the old runner must refuse
  it.
* **Internal crates make no promise.** `sourceorrery-storage`,
  `sourceorrery-crypto` and `sourceorrery-ffi`'s Rust API are published
  because the public crates depend on them; only the surfaces above are
  versioned.

## How it is checked

* `scripts/ci/abi-check.py` (the `ffi-header` CI job) parses the committed
  header and the header of the latest `v*` tag and fails when a function,
  struct, enum member or constant that existed before changed or
  disappeared while `SO_ABI_VERSION` stayed the same.
* The `abi-compat` CI job checks out the latest `v*` tag, builds its C
  conformance runner against its own header, and drives it with its own
  harness and scenarios against the library built from the current
  commit. It is skipped when `SO_ABI_VERSION` differs between the two.
* Each binding has a unit test for the `abi_mismatch` error it would raise.
* The release workflow runs `cargo semver-checks` on `sourceorrery` and
  `sourceorrery-core` against the crates.io baseline with the version the
  maintainer typed, in dry runs too, so a patch release whose Rust API
  needs a minor bump fails before anything is built.
* `CONTRACT_VERSION` and `schema_version` are judged by the conformance
  suite and the migration tests, as before.

## Consequences

* Pre-1.0 users can rely on patch releases: upgrading `0.x.y` to
  `0.x.(y+1)` in any package never requires a code change, and a mixed
  deployment (an older SDK with a newer library, or the reverse, within
  one minor) keeps working.
* A release that touches the C ABI shows the change in CI before it is
  cut, and a mismatched library fails fast with one message in every
  language instead of a crash or a wrong result.
* The compatibility checks look one release back. A change that would
  break a release two minors ago is allowed once it has gone through a
  deprecation; nothing enforces the deprecation window itself except
  review.
* `CONTRACT_VERSION` stays `"1"` through the listing additions of this
  release: new operations are compatible.

## Amendment — 2026-10-25

The vault-file rule above ("a new schema, read only after an explicit
migration") was set aside once, for the next release, by
[ADR 0009](0009-local-vaults-checks-and-storage.md): earlier files are
refused with `migration_required` and recreated. [ADR 0010](0010-authenticated-key-wraps-and-private-files.md)
moves that release's format from schema 4 to schema 5 before it ships,
under the same exception, rather than redefining schema 4 in place. The C
ABI and `CONTRACT_VERSION` are not affected by that change.
