# Changelog

All notable changes to SourceOrrery are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project
uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Security — fixes from the 20 October 2026 review

* **Schema rollback no longer launders edits through migration.** The vault
  key is wrapped under an AAD that names the on-disk schema, `open` refuses
  older schemas with `migration_required`, and the explicit
  `vault migrate` aborts when any key proves the file was already in the
  current format. Migration re-wraps every key it holds.
* **Vault settings are authenticated** (`settings_tag` over schema, name,
  id, created time, recovery level and retention) and re-validated on every
  unlock, so retention can no longer be shortened to force a purge.
* **Removing the whole audit history and its head is detected** and recorded
  as a truncation instead of being accepted as a fresh log.
* **Manifest errors no longer echo rejected values**: diagnostics name keys
  and positions only. `env` names are compared case-insensitively and may
  not start with `SOURCEORRERY_`.
* **`run` strips `SOURCEORRERY_PASSPHRASE` and `SOURCEORRERY_PASSPHRASE_FILE`**
  from the child's environment, and an optional secret whose vault is
  missing no longer blocks startup.
* **Keyring cleanup checks ownership**: `vault destroy` and
  `vault protector remove` delete an OS-keyring entry only when its account
  is this vault's own and no sibling vault references it (`--keep-os-key`
  opts out); protector removal deletes the entry after the database commit
  and protector creation validates labels before storing a key.
* **Metadata reads are audited** as `secret_inspect`; invalid-name failures
  are audited without recording the name.
* **Argon2 parameters read from a vault are capped** (1 GiB, 64 passes,
  16 lanes) and at most eight passphrase protectors are tried per attempt.
* `SetSecretOptions` and `UpdateSecretProperties` reject unknown fields;
  keys returned by the OS credential store are zeroised after use.
* Release profile no longer sets `panic = "abort"`, so the C ABI's
  `SO_STATUS_PANIC` contract holds in release builds; the release matrix
  uses `macos-15-intel` instead of the retired `macos-13` runner.

### Added — milestone 1: core, encrypted vault and CLI

* `sourceorrery-core`: `SecretClient` contract modelled on Azure Key Vault
  (set → new immutable version, get latest accessible, metadata-only
  listing, property updates, soft delete, recover, purge, audit). Stable
  error codes, name validation, enforced `not_before`/`expires_on`,
  `SecretBytes` (zeroising, redacted, non-serialisable), `SecretReference`
  URIs and the `sourceorrery.toml` manifest that rejects values.
* `sourceorrery-crypto`: XChaCha20-Poly1305 with AAD binding, Argon2id
  passphrase KDF, envelope key wrapping, OS randomness.
* `sourceorrery-storage`: single-file encrypted SQLite vault with multiple
  key protectors (OS credential store via `keyring-core`, passphrase),
  per-version encryption bound to vault/name/version, soft-delete
  retention with automatic purge, metadata-only audit log with failed
  unlock attempts, `secure_delete` on purge.
* `sourceorrery` CLI: `vault create|list|info|protector|destroy`,
  `secret set|get|list|versions|update|delete|recover|purge`, `audit`,
  `init`, `check`, `run -- <command>`, `completions`. Values are read
  interactively, from stdin or a file — never as an argument — and are
  shown only with `get --reveal`.
* Conformance and security test suites; CI on Ubuntu, Windows and macOS.

### Added — CLI banner

* `sourceorrery` with no arguments shows the SourceOrrery wordmark rendered
  with Unicode half blocks (plain text when piped), a clickable
  `sourceorrery.ai` link and a quick start. Colours are chosen to stay
  legible on dark and light terminals; `NO_COLOR` and `SOURCEORRERY_BANNER`
  are honoured.

### Added — metadata and audit-log integrity (vault schema 2)

* `sourceorrery-crypto`: `derive_subkey` (HKDF-SHA256) and `mac` /
  `verify_mac` (HMAC-SHA256, constant-time comparison).
* `sourceorrery-storage`: a metadata key derived from the vault DEK
  authenticates every `secrets` and `secret_versions` row (enabled flag,
  time window, content type, tags, deletion state). Tampered rows are
  refused with error code `crypto` and an audit `failure`; a forged
  deletion is neither honoured nor purged. The audit log is a keyed hash
  chain (`prev_hash`, `hash`, `keyed`) with a keyed head record in
  `vault_meta`; rows removed from the end of the log are detected on the
  next keyed write and recorded as `audit_verify` / `failure`.
  `SqliteVault::verify_audit_chain()` reports breaks, truncations and
  unkeyed (pre-unlock) rows. Writes use `BEGIN IMMEDIATE` and a busy
  timeout, and failed operations keep their audit row.
* `sourceorrery-core`: audit operations `vault_migrate` and `audit_verify`.
* CLI: `sourceorrery audit --verify` (table or JSON; exit 1 when not
  intact).
* Schema version 1 vaults are migrated to schema 2 in one transaction on
  first unlock (`vault_migrate` audit row); a newer schema is still refused
  cleanly.

### Added — milestone 2 (in progress): C ABI and language bindings

* `sourceorrery-ffi`: a stable C ABI over the encrypted vault for language
  bindings, with the header `crates/sourceorrery-ffi/include/sourceorrery.h`
  generated by cbindgen on every build and checked for staleness in CI.
  Opaque vault handles usable from several threads, UTF-8 `(ptr, len)`
  strings, metadata as JSON, secret values as caller-owned `so_bytes`
  buffers that `so_bytes_free` zeroises, and stable error codes through
  per-thread `so_last_error_code()`. It is the only crate allowed to use
  `unsafe`; every block states its invariant. Covered by Rust smoke tests
  that call the exported functions and by a C example compiled in CI.
