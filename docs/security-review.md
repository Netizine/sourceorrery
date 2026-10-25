# Security review status — 0.3.0

SourceOrrery 0.3.0 has local engineering reviews, regression tests and a
recorded release rehearsal. It has **not received an independent security
audit**. The [threat model](threat-model.md) defines the supported
boundaries; this page records the review scope and remaining acceptance.

## Current design reviewed

The current build uses schema 5, C ABI 2 and contract 2. The local vault
has authenticated key wraps and state checkpoints, this-machine and
recovery-key access, an optional view check, provider connections and
export/import. Read-only SDKs and the metadata-only browser use the same
local vault and provider routing; they do not provide same-user isolation.

| Surface | Review and regression coverage |
|---------|--------------------------------|
| Keys and files | Authenticated wrap inventory, recovery-key replacement limits, exclusive vault creation, private recovery-key files, import/export verification and old-format refusal. |
| Local integrity | Authenticated metadata/settings, audit-chain linkage and head checks, state checkpoints, quarantine and explicit truncation acknowledgment. |
| Provider writes | Recorded attempts, fail-closed publication, interruption handling and `outcome_unknown` instead of automatic mutation retries. |
| CLI and manifests | Value-free diagnostics, bounded discovery, child environment restrictions, endpoint validation and explicit reveal/confirmation paths. |
| Terminal screens | Stable target identities, fresh-press transitions, cached metadata operations, capability checks, secret-state ownership and idle-lock clearing. |
| SDKs and C ABI | Read-only application surface, strict open options, guarded values, typed errors, ABI mismatch checks and shared conformance scenarios. |
| Build and release | Minimum Rust/features, dependency audits, provenance verification, exact-commit CI gates, SDK/platform packaging and parser fuzz regression tests. |

The detailed findings and batch evidence are retained in the
[25 October review](../SECURITY-REVIEW-2026-10-25.md),
[remediation plan](../SECURITY-REMEDIATION-PLAN-2026-10-25.md) and
[validation ledger](security-remediation-validation.md). The
[earlier review](security-review-archive-2026-10.md) describes the design
before the 0.3.0 redesign; its removed commands and key model are historical.

## Evidence and its limits

The local checks recorded for the completed UI tree are 610 workspace
tests passing, 172 targeted UI tests passing, formatting and workspace
Clippy passing, and a successful UI build without default features.
One snapshot writer is intentionally ignored by the ordinary suite and
was run explicitly; representative generated screens were inspected in
all six looks. [UI validation record](UI-IMPLEMENTATION-STATUS.md)

These totals are runner results, not a claim that live-service tests ran.
Provider tests that need a service can return early without one. The
release's CI provider jobs require their services, and their evidence must
be checked separately. A Vault development server and AWS/Azure emulators
also do not establish every production-provider behaviour.

The remediation ledger records additional local SDK, minimum-toolchain,
Linux packaging and release-helper checks at their stated commits. Later
documentation edits do not rerun or extend that historical evidence.

## Required before a release

- Full hosted CI for the exact release commit, including jobs skipped by
  documentation-only push classification. A green aggregate with skipped
  platform tests is insufficient for release validation.
- A hosted dry run of the release workflow and installation checks of its
  resulting packages. The local rehearsal is not that dry run.
- Outstanding platform and credential-store tests, including macOS,
  applicable Linux/macOS SDK suites and the real keyring jobs.
- A second Windows account checking the recovery-key file's access
  restrictions, plus real-provider tests where production-service claims
  are needed.
- Physical terminal key-repeat/F2, screen-reader, authenticator-scanning
  and first-time-user acceptance. Static snapshots do not establish those.

[Releasing](release.md) describes the enforced gates and the separate
registry/repository controls to inspect. Pushing the branch for CI is not
publishing a release or establishing production readiness.

## Boundaries that remain

- Code running as the same OS user can use the same credential store and
  application interfaces. There is no authenticated broker or OS process
  isolation in this release.
- The view check is for interactive viewing, not encryption or application
  authorisation. A recovery key satisfies it; SDKs never ask it.
- Replacing a recovery key does not rotate the vault data-encryption key.
  Old copies and exposed keys require credential rotation and a new vault.
- A complete old snapshot needs an external checkpoint for rollback
  detection. Audit acknowledgment accepts surviving history; it does not
  reconstruct missing events.
- SDK-exposed copies, process environments, caller-written files and
  application logs are outside vault encryption and native-buffer wiping.
- Provider identity, metadata permissions, retention and revocation remain
  the provider's responsibility. Revocation cannot recall a value already
  copied by an application.

These are design limits, not unresolved claims that the product currently
provides those guarantees. See the full [threat model](threat-model.md).
