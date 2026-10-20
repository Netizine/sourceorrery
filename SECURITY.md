# Security policy

## Reporting a vulnerability

Please **do not** open a public issue for security problems.

Email **security@sourceorrery.ai** with a description, reproduction steps and
the affected version. You will receive an acknowledgement within three
working days. Coordinated disclosure is preferred; we will agree a timeline
with you and credit you in the advisory unless you ask otherwise.

## Scope

In scope: anything that lets a party who cannot unlock a vault learn a secret
value, lets a value reach a place it should not (logs, audit records, error
messages, metadata output, the manifest), lets a ciphertext be substituted or
tampered with undetected, or bypasses enforced policy (disabled versions,
activation and expiry windows, soft-delete state).

Out of scope for milestone 1, by design and documented in the
[threat model](docs/threat-model.md):

* Code already running as the same OS user with access to an unlocked vault
  or to the OS credential store. Agent isolation is milestone 3.
* Memory disclosure by a debugger or kernel-level attacker.
* A compromised operating-system credential store.

## Supported versions

Pre-1.0: only the latest release receives fixes.

## Cryptography

SourceOrrery implements no algorithms. It uses the RustCrypto
`chacha20poly1305` (XChaCha20-Poly1305) and `argon2` (Argon2id) crates, OS
randomness via `getrandom`, and the `keyring-core` ecosystem for credential
stores. Details: [docs/vault-format.md](docs/vault-format.md).
