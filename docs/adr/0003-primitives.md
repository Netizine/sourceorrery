# ADR 0003: XChaCha20-Poly1305, Argon2id, random nonces

**Status:** accepted · **Date:** 2026-10-20

## Context

Values are written by many short-lived CLI processes with no shared counter
state, so nonce management must be stateless. Passphrase protectors must
resist offline guessing of a stolen vault file.

## Decision

* **XChaCha20-Poly1305** (RustCrypto `chacha20poly1305`) with a fresh random
  192-bit nonce per message. The extended nonce makes random nonces safe
  without coordination. AES-256-GCM was rejected for the 96-bit nonce and the
  need for hardware acceleration to be constant-time.
* **Argon2id v1.3** (RustCrypto `argon2`), default 64 MiB / 3 passes / 1 lane,
  per-protector 16-byte random salt, parameters stored with the protector so
  defaults can be raised later.
* **AAD on every ciphertext** naming its location, so records cannot be
  swapped.
* **No cryptography implemented in this repository.** Primitives are wrapped
  in `sourceorrery-crypto` only.

## Consequences

* Simple, reviewable crypto surface: `seal`, `open`, `derive_key`,
  `wrap_key`, `unwrap_key`.
* Unlock with a passphrase costs ~0.3–0.6 s on developer hardware by design.
* Future FIPS requirements would need an alternative AEAD behind the same
  interface; the format records nothing that prevents that.
