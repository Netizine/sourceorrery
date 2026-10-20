# Threat model

SourceOrrery makes three different promises and keeps them separate. Users,
documentation and marketing must never blur them.

## The three guarantees

| # | Guarantee | Meaning | Milestone 1 |
|---|-----------|---------|-------------|
| 1 | **At-rest protection** | No plaintext secret on disk, in the repository, in shell history, in agent context windows, in logs or in audit records. | **Provided.** |
| 2 | **Access control** | Only authorised identities can retrieve a given secret; access is per secret, revocable and audited. | **Local only.** Whoever can unlock the vault is its administrator. Per-secret policy against verified identities arrives with the broker. |
| 3 | **Agent isolation** | An untrusted agent or process running as the *same OS user* cannot impersonate an authorised application or modify it to disclose secrets. | **Not provided.** Requires an independently authenticated broker plus OS-level isolation (milestone 3). SourceOrrery will never claim this without an external boundary. |

## Assets

* Secret values (highest).
* The vault data-encryption key (DEK) and key-encryption keys (KEKs).
* Passphrases.
* Integrity of ciphertext-to-record binding (which value belongs to which
  secret/version).
* Integrity of the audit log and policy state (enabled flags, time windows,
  deletion state). Authenticated since vault schema version 2.

Secret *names*, tags, version ids, timestamps and audit metadata are **not**
treated as secrets. Users are told not to put sensitive information in them.

## Adversaries

| Adversary | Capability | Milestone 1 outcome |
|-----------|------------|---------------------|
| **Repository reader** — anyone with the git history, a leaked archive, a code-indexing service, an LLM fed the repo | Reads every committed file | Nothing to find: no `.env`, manifest cannot hold values, references contain no material. |
| **Offline disk reader** — stolen laptop, backup, cloud sync of the data directory | Reads the vault file and (if synced) OS-store artefacts | Values are XChaCha20-Poly1305 ciphertext. Passphrase KEK needs Argon2id (64 MiB, 3 passes). OS-keyring KEK is protected by the platform store's own at-rest protection (DPAPI / Keychain / login keyring). |
| **Tamperer** — can modify the vault file but cannot unlock it | Swaps or edits ciphertext, flips `enabled`, edits timestamps or tags, undeletes a secret, edits or deletes audit rows | Ciphertext swap/edit is detected (AAD binding + AEAD tag). Mutable metadata carries an HMAC under a key derived from the DEK, checked on every read: a re-enabled version, extended expiry, cleared `not_before`, edited tags or forged deletion state is refused with `crypto` and audited. The audit log is a keyed hash chain with a keyed head record: edits, gaps and reordering break the chain; rows removed from the end are detected and recorded at the next unlock. Rows written before unlock (failed attempts) are chained with a public key: forgeable, but not silently removable. |
| **Careless operator / agent reading output** | Sees stdout/stderr of CLI commands, logs, JSON | Metadata commands never show values; `--reveal` is explicit; prompts never echo; `-v` never prints values. |
| **Same-user malicious process or agent** | Runs code as you, reads your memory, calls the CLI, reads the OS credential store under your login | **Not defended.** Can call `secret get --reveal` exactly as you can. This is the honest boundary of a local-first tool and the reason the broker exists. |
| **Root / kernel / debugger** | Everything | Out of scope. Memory hygiene (zeroisation, short-lived plaintext) reduces residue; it does not resist a privileged attacker. |

## Controls

| Control | Where |
|---------|-------|
| No plaintext `.env` | Manifest + `run` replace it |
| Values encrypted individually, bound to vault/name/version | `sourceorrery-crypto::aead`, `storage::sqlite` |
| Vault key never on disk in the clear | Envelope encryption; KEK in OS store or derived from passphrase |
| Passphrase hardening | Argon2id, per-protector random salt, parameters stored for upgrade |
| No value in arguments | CLI has no `--value` |
| No value in logs, errors, audit, Debug | `SecretBytes` design + conformance tests |
| No value serialisable by accident | `SecretBytes` has no `Serialize` |
| Enforced policy | `enabled`, `not_before`, `expires_on` evaluated in core on every retrieval |
| Soft delete + recovery | Default 90-day retention; explicit privileged purge |
| Audit without values, including failed unlocks | `audit_events` table; `vault_open` denied/failure rows |
| Metadata integrity | HMAC-SHA256 tag on every `secrets` / `secret_versions` row under an HKDF sub-key of the DEK; verified on every read, written on every insert/update; forged deletion state is neither honoured nor purged (`storage::integrity`, `storage::sqlite`) |
| Audit log integrity | Keyed hash chain over `audit_events` plus a keyed head record; truncation detected on every keyed write and recorded as `audit_verify` / `failure`; `sourceorrery audit --verify` reports breaks, truncations and unkeyed rows (`storage::integrity`, `storage::sqlite`) |
| Secure deletion on purge | SQLite `secure_delete = ON` |
| File permissions | `0700` dir / `0600` file on Unix; profile ACLs on Windows |
| Memory hygiene | `zeroize` on `SecretBytes`, `SymmetricKey`, decrypted buffers |

## Known gaps (milestone 1)

1. **Agent isolation.** See guarantee 3.
2. **Process environment exposure.** `run` delivers secrets as environment
   variables of the child process, visible to anything that can read that
   process's environment (`/proc/<pid>/environ`, Process Explorer). This is
   the pragmatic bridge from `.env`; the SDK path (milestone 2) avoids it.
3. **Side channels.** Argon2id, HMAC and the AEAD implementations are
   RustCrypto's; no additional constant-time guarantees are claimed beyond
   theirs.
4. **No signed releases yet.** Release artefacts carry SHA-256 checksums;
   signing (Sigstore / minisign) is on the roadmap.
5. **Integrity, not availability.** A tamperer can still destroy data
   (delete rows, corrupt the file) and can forge or remove the *unkeyed*
   audit rows written by failed unlock attempts. Tampering is detected and
   recorded, not prevented or repaired; keep backups. The chain is only as
   trustworthy as the key: anyone who can unlock the vault can rewrite its
   history, which is the same-user boundary above.

## Planned (milestone 3): the hard problem

Suppose an authorised .NET application may read a production secret. If an
agent can execute arbitrary code as the same OS user, it can invoke that
application, use the same broker credentials or modify the application to
disclose the secret. Checking the executable name, PID, project directory or a
caller-supplied application id does not reliably prevent this.

The broker will therefore:

* authenticate callers with capabilities that are short-lived and scoped to
  secrets, not with reusable tokens;
* support independently verified workload identities (OS-level isolation,
  separate service accounts, containers, workload identity federation) and
  state plainly when only a weak label is available;
* give agent sessions an **agent profile**: no production secrets, scoped
  test credentials, limited lifetime, every access audited;
* evaluate policy on the broker side, never trust the manifest's claims.

Until then, SourceOrrery's claim is precise: **your secrets are not in your
repository, not in plaintext on disk, and every access is on the record.**
