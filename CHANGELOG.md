# Changelog

All notable changes to SourceOrrery are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project
uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

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
