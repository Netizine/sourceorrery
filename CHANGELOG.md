# Changelog

All notable changes to SourceOrrery are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project
uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Changed

* PyPI and crates.io are published by trusted publishing, like npm and
  NuGet: the release jobs exchange the workflow's GitHub identity token
  for a short-lived credential (`rust-lang/crates-io-auth-action` for
  crates.io), and no `PYPI_API_TOKEN` or `CARGO_REGISTRY_TOKEN` is read
  any more. PyPI files now carry a signed attestation. Both jobs run in
  every real release and fail rather than skip if the registry does not
  trust the workflow; `ReleasePackages.yaml` does the same.
* Every registry page explains its package: each of the six crates has a
  README on crates.io; the PyPI, npm, NuGet, Go and PHP READMEs, the Maven
  description and javadoc overview say what the SDK is, that vaults are
  created and secrets stored with the `sourceorrery` CLI (which no SDK
  installs and which need not be present where the application runs), and
  link to sourceorrery.ai. The six npm platform packages say which
  platform their addon is for and to install `@sourceorreryai/sdk`
  instead (`scripts/release/npm-platform-packages.py`, run after
  `napi create-npm-dirs`).
* The CLI archives carry the CLI's README, the C ABI archives a README of
  their own (what is inside, who needs it, how to link it), and the
  GitHub Release notes list what each file is for.

### Security

* A vault is only served under its own name. Opening vault `X` used to
  load `<home>/vaults/X.sorvault` without checking that the file holds
  the vault `X`, so a file renamed, copied or swapped in from another
  vault that unlocks with the same passphrase or credential store was
  served under the wrong name. Every open by name (the CLI, `ui`,
  `audit`, `vault migrate`, the SDKs and the C ABI) now compares the
  requested name with the authenticated name in the file and refuses a
  mismatch with the new, append-only code `vault_mismatch`, recording
  the refusal in that file's audit log. A legacy file under the wrong
  name is refused before it is migrated. Every SDK has a typed error for
  the code (`VaultMismatchError`, `VaultMismatchException`,
  `ErrVaultMismatch`), and the SDK conformance harness checks it.

### Fixed

* The Linux and macOS C ABI archives no longer include Cargo's
  `libsourceorrery_ffi.rlib` and `libsourceorrery_ffi.d` next to the
  libraries.

## [0.1.3] - 2026-10-21

The first release: an encrypted local secrets vault with an Azure Key
Vault–style lifecycle, a CLI and an interactive vault manager, read-only
SDKs for ten languages over one Rust core, and a release pipeline to every
package registry.

### Added — core and encrypted vault

* `sourceorrery-core`: the `SecretClient` contract modelled on Azure Key
  Vault (set → a new immutable version, get the newest accessible version,
  metadata-only listing, property updates, soft delete, recover, purge,
  audit), stable append-only error codes, Azure Key Vault naming rules,
  enforced `not_before` / `expires_on`, `SecretBytes` (zeroising, redacted,
  never serialisable), `sourceorrery://` references and the
  `sourceorrery.toml` manifest, which cannot hold a value and whose errors
  never echo what they rejected.
* `sourceorrery-crypto`: XChaCha20-Poly1305 with AAD binding, Argon2id
  (caller-owned, zeroised working memory; parameters read from a vault are
  capped at 1 GiB, 64 passes and 16 lanes), envelope key wrapping, HKDF and
  HMAC-SHA256, OS randomness.
* `sourceorrery-storage`: one encrypted SQLite file per vault (on-disk
  schema 3).
  * Key protectors: the OS credential store and Argon2id passphrases,
    several per vault, at most eight passphrase protectors. A keyring
    entry is deleted only when it provably belongs to this vault and no
    sibling references it.
  * Every value is encrypted on its own, bound to vault, name and version;
    a read decrypts only the version it returns.
  * Soft delete with retention (7–90 days) and automatic purge;
    `secure_delete` on purge.
  * Integrity: every mutable row carries an HMAC under a key derived from
    the vault key; the audit log is a keyed hash chain with a keyed head
    record; every change records the row's new tag as a checkpoint in its
    audit event, so an older authentic copy of a row is refused; vault
    settings are authenticated, and the wrapped vault key's AAD names the
    format, so a rolled-back schema marker cannot unwrap.
  * Audit: every operation, success or failure, including failed unlocks
    and refused input, with metadata reads recorded as `secret_inspect`
    and never a value.
  * A detected truncation of the audit log blocks the vault: every unlock
    and operation is refused until its owner reviews the surviving history
    and acknowledges it (`audit --acknowledge`).
  * `vault migrate` upgrades a file written in an earlier on-disk format,
    by explicit command only. Vault files are created exclusively, so
    concurrent creators cannot remove each other's file.

### Added — CLI

* `sourceorrery vault create|list|info|protector|destroy|migrate`,
  `secret set|get|list|versions|update|delete|recover|purge`,
  `audit [--verify|--acknowledge]`, `init`, `check`, `run -- <command>`,
  `completions` and `ui`; `-o json` everywhere, with stable error codes.
* Values are read interactively, from stdin or a file — never as an
  argument — and shown only with `secret get --reveal`.
* `run` injects the manifest's secrets into a child's environment,
  removes `SOURCEORRERY_PASSPHRASE` and `SOURCEORRERY_PASSPHRASE_FILE`
  from it, and exits with the child's status whole.
* Human-readable output shows control and bidirectional-formatting
  characters as escapes (`\u{1b}`), so text planted in a vault file cannot
  move the cursor, erase lines or set the clipboard; JSON and revealed
  values are byte-exact.
* With no arguments, the SourceOrrery wordmark in Unicode half blocks
  (plain text when piped) and a quick start.

### Added — `sourceorrery ui`, the vault manager

* A Ratatui browser, the `ui` cargo feature of `sourceorrery-cli` (on by
  default). Views: Overview (secrets by status and expiry, what expires or
  activates next, the audit chain as `audit --verify` reports it, 14 days
  of audit activity, the last value read and failed unlock, protectors),
  Secrets with details (every field, every version, recent activity),
  Deleted, Audit log and Vaults (a picker that needs no unlock).
* `/` searches the current view: words anywhere; `tag:`, `status:`,
  `type:` and `expires:<30d` for secrets, `op:`, `outcome:`, `secret:` and
  `actor:` for the audit log.
* Changes, each checked with the vault's own rules and confirmed first:
  enable or disable a version, edit its metadata, a new version or secret,
  delete, recover. A new value is typed at the CLI's hidden prompt with the
  screen suspended and goes straight to the vault; deleting for good in a
  purgeable vault means typing the name. `--read-only` refuses every
  change. Purge, protectors, destroy, migrate and acknowledgement stay in
  the CLI.
* Metadata only: the views read through an interface with no operation
  that returns a value; changes go through a separate one. Every metadata
  read is audited, so each thing is read once, when first shown, and again
  on `r`. Vaults open for inspection, so a blocked vault shows its audit
  log and is never asked for secrets.
* `--theme dark|light|terminal`: the documentation site's palettes (with
  the nearest xterm 256 colours where there is no 24-bit colour) or the
  terminal's own; `NO_COLOR` honoured.
* Idle lock: after `--lock-after` minutes without a key (default 10) and
  on `L`, the vault is dropped and its key zeroised.

### Added — SDKs and the C ABI

* `sourceorrery`, the read-only Rust client every SDK is built on:
  `SecretReader` opens a vault in the CLI's unlock order (OS credential
  store, an explicit passphrase, `SOURCEORRERY_PASSPHRASE`,
  `SOURCEORRERY_PASSPHRASE_FILE`, never a prompt), reads the newest
  accessible or an explicit version, properties and references;
  `Project::load` resolves a `sourceorrery.toml` like `sourceorrery run`.
  Every error carries its stable code, a kind and a hint saying what to do.
* `sourceorrery-ffi`: a stable C ABI (cbindgen header, checked in CI):
  read-only `so_reader_*` and `so_project_*` handles for SDKs,
  `so_vault_*` for tooling, values in caller-owned buffers that
  `so_bytes_free` zeroises, errors as code, message and hint.
* Ten read-only SDKs (ADR 0005, technologies in ADR 0006), each with typed
  errors, guarded values that print as `[REDACTED]`, a project loader, a
  tested example and a guide under `docs/sdks/`: Python (`sourceorrery`,
  abi3 wheels), JavaScript/TypeScript (`@sourceorreryai/sdk` with platform
  packages), Rust, Java (`ai.sourceorrery:sourceorrery`, Foreign Function
  and Memory API), .NET (`SourceOrrery`, `LibraryImport`), Go
  (`github.com/netizine/sourceorrery/bindings/go`), C, C++ (header-only)
  and PHP (`sourceorrery/sourceorrery`, FFI).
* A cross-language conformance harness (`tests/conformance/sdk/`): one
  list of scenarios, a runner per SDK and one judge. CI runs every SDK's
  tests, example and the harness on Ubuntu, Windows and macOS against a
  vault the CLI creates in the job.

### Added — releases

* `release.yml` (`workflow_dispatch` with `version` and `dry_run`): the CLI
  and the C ABI for six targets, Python wheels, npm, Maven and NuGet
  packages with the native libraries embedded, a GitHub Release with
  `SHA256SUMS`, and publish jobs for crates.io, PyPI, npm, NuGet, Maven
  Central, Packagist and pkg.go.dev that run once each registry is set up.
  npm and NuGet use trusted publishing. The npm main package is installed
  and loaded in the run before anything ships.
* `ReleasePackages.yaml` publishes an existing release's packages to a
  registry set up after it ran.
* `scripts/release/set-version.py` stamps the version into every manifest;
  the Composer manifest is at the repository root, where Packagist reads
  it. Procedure and per-registry setup: `docs/release.md`.

[Unreleased]: https://github.com/Netizine/sourceorrery/compare/v0.1.3...HEAD
[0.1.3]: https://github.com/Netizine/sourceorrery/releases/tag/v0.1.3
