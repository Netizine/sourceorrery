# ADR 0002: Encrypted SQLite vault with the key in the OS credential store

**Status:** accepted · **Date:** 2026-10-20

## Context

Two obvious designs: (a) store each secret directly in the OS credential
store (Credential Manager, Keychain, Secret Service); (b) store secrets in
our own encrypted file and use the OS store only to protect the file's key.

(a) gives platform at-rest protection for free but none of the Key Vault
semantics: no versions, retention, policy fields, audit, or consistent
cross-platform behaviour (Credential Manager limits blob size; Secret Service
may be absent on servers). Each platform would behave differently.

## Decision

(b). A vault is one SQLite file with versioned, individually encrypted values
(XChaCha20-Poly1305, AAD-bound to vault/name/version), metadata, soft-delete
state and an audit log. One data-encryption key per vault is wrapped by one
or more *key protectors*: a random key in the OS credential store, and/or an
Argon2id-derived key from a passphrase. Several protectors can wrap the same
key, so one vault serves Windows (Credential Manager) and WSL/Docker/CI
(passphrase).

## Consequences

* Identical semantics on every platform; headless machines work with a
  passphrase protector and never fall back to plaintext.
* Values are protected by our crypto, not by the platform's; the platform
  protects only the key. Metadata integrity is a known gap to close.
* SQLite is a C dependency (bundled). Acceptable for Tier 1 targets; musl and
  exotic targets are Tier 2 until validated.
