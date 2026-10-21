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
  deletion state). Authenticated since vault schema version 2 and bound to
  the audit chain since version 3.

Secret *names*, tags, version ids, timestamps and audit metadata are **not**
treated as secrets. Users are told not to put sensitive information in them.

## Adversaries

| Adversary | Capability | Milestone 1 outcome |
|-----------|------------|---------------------|
| **Repository reader** — anyone with the git history, a leaked archive, a code-indexing service, an LLM fed the repo | Reads every committed file | Nothing to find: no `.env`, manifest cannot hold values, references contain no material. |
| **Offline disk reader** — stolen laptop, backup, cloud sync of the data directory | Reads the vault file and (if synced) OS-store artefacts | Values are XChaCha20-Poly1305 ciphertext. Passphrase KEK needs Argon2id (64 MiB, 3 passes). OS-keyring KEK is protected by the platform store's own at-rest protection (DPAPI / Keychain / login keyring). |
| **Tamperer** — can modify the vault file but cannot unlock it | Swaps or edits ciphertext, flips `enabled`, edits timestamps or tags, undeletes a secret, edits or deletes audit rows | Ciphertext swap/edit is detected (AAD binding + AEAD tag). Mutable metadata carries an HMAC under a key derived from the DEK, checked on every read: a re-enabled version, extended expiry, cleared `not_before`, edited tags or forged deletion state is refused with `crypto` and audited. The audit log is a keyed hash chain with a keyed head record: edits, gaps and reordering break the chain; rows removed from the end are detected and recorded at the next unlock, and the vault then refuses every unlock and operation until its owner has reviewed the surviving history and acknowledged the truncation. Rows written before unlock (failed attempts) are chained with a public key: forgeable, but not silently removable. Vault-wide settings (schema, name, recovery level, retention) carry their own HMAC, so retention cannot be shortened to force a purge. A schema marker rolled back to the legacy format is refused: the vault key is wrapped under an AAD that names the format, and migration is only ever an explicit command. Removing the whole audit history together with its head is recorded, not accepted as a fresh log. |
| **Careless operator / agent reading output** | Sees stdout/stderr of CLI commands, logs, JSON | Metadata commands never show values; `--reveal` is explicit; prompts never echo; `-v` never prints values; the `ui` browser cannot read a value at all. |
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
| Row state bound to the audit chain | Every change records the changed row's new tag (or its removal) as a checkpoint in its own keyed audit event; a row is honoured only when its tag equals the newest checkpoint, so an authentic *older* copy of a row (re-enabled, undeleted, resurrected after purge) or a version removed out of band is refused with `crypto` (`storage::sqlite::rows`, [vault-format.md](vault-format.md#checkpoints)) |
| Audit log integrity | Keyed hash chain over `audit_events` plus a keyed head record; a stale head (rows removed from the end, head missing or invalid) refuses the unlock or operation that finds it and is recorded as `audit_verify` / `failure`; `sourceorrery audit --verify` reports breaks, truncations and unkeyed rows (`storage::integrity`, `storage::sqlite`) |
| Truncation blocks the vault until acknowledged | A recorded truncation that no later keyed `audit_verify` / `success` acknowledgement covers refuses every unlock and operation with `crypto`, naming the event; only `sourceorrery audit` unlocks such a vault, for reading the log, verifying the chain and `audit --acknowledge`, which prints the truncation events, asks for confirmation and appends the acknowledgement under the vault key. Refusals and the acknowledgement are themselves on the chain; removing the acknowledgement is another truncation that un-acknowledges what it covered (`storage::sqlite::audit`, [vault-format.md](vault-format.md#audit-chain)) |
| Every rejected operation is audited | Invalid names, rejected time windows and tags, empty updates and refused protector changes go through the same failure path as any other error: the operation body is rolled back and one `failure` row is committed (an invalid name is not recorded, since it is arbitrary input) |
| Exclusive vault creation | The vault file is created with `O_EXCL` / `CREATE_NEW`; concurrent creators get `vault_exists` and never remove the winner's file |
| Accepted credentials can unlock | At most 8 passphrase protectors can be installed, matching what unlock will try |
| KDF residue | Argon2's working memory and output buffer are caller-owned and zeroised when the derivation ends |
| Secure deletion on purge | SQLite `secure_delete = ON` |
| File permissions | `0700` dir / `0600` file on Unix; profile ACLs on Windows |
| Memory hygiene | `zeroize` on `SecretBytes`, `SymmetricKey`, decrypted buffers |
| Authenticated vault settings | HMAC over schema, name, recovery level and retention, verified on every unlock |
| Format bound into key wrapping | The wrapped vault key's AAD names the schema; a rolled-back marker cannot unwrap as legacy |
| Explicit, one-way legacy migration | `vault migrate` only; plain `open` refuses older schemas |
| Audit history must exist | An existing vault with no rows and no head is a detected truncation, never a fresh start |
| Resource ceilings before authentication | Argon2 parameters from the file are capped (1 GiB, 64 passes, 16 lanes); at most 8 passphrase protectors are tried |
| Keyring entries deleted only when provably this vault's | Account must match the vault's own identity and no sibling vault may reference it; `--keep-os-key` opts out |
| No secret echoes in diagnostics | Manifest parse errors report a category and position, never the offending text |
| Terminal output sanitised | Text read from the vault file can be planted by a tamperer: protector labels and keyring accounts are not authenticated at all, and the vault name is not until unlock. Audit rows written before unlock can be forged too. So table output, status lines, notes, errors and prompts show control characters (C0 including ESC, TAB, CR and LF; DEL; C1) and bidi formatting characters as `\u{..}` escapes. Planted text cannot move the cursor to hide audit rows, write the clipboard (OSC 52) or reorder what is shown. Multi-line messages keep their own line breaks. JSON is left to serde, and revealed values stay byte-exact (`cli::output::sanitize`) |
| Value-free interactive browser | `ui` reaches the vault only through `MetadataSource`, which has no operation returning a value, so no value is drawn, held in its screen buffers or copied anywhere; stored text goes through the same `output::sanitize` as the rest of the CLI (`sourceorrery-cli::ui`) |
| Child environment hygiene | `run` removes `SOURCEORRERY_PASSPHRASE` and `SOURCEORRERY_PASSPHRASE_FILE` from the child; manifests cannot deliver under `SOURCEORRERY_*` names |

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
   recorded, not prevented or repaired; keep backups. A row or checkpoint
   that no longer verifies stays refused until the file is restored from a
   backup; there is no repair command. The chain is only as trustworthy as
   the key: anyone who can unlock the vault can rewrite its history, which
   is the same-user boundary above.
6. **Snapshot rollback.** Restoring an older copy of the entire vault file
   is a consistent, correctly authenticated state; nothing inside the file
   can show that newer history existed. Detecting it needs a checkpoint kept
   outside the file: the id and hash reported by `audit --verify`, or a
   backup to compare with. A *partial* rollback — putting back an older copy
   of a row **and** removing the audit rows that recorded the later change —
   is the same attack in a smaller form, and the file alone cannot tell the
   surviving history from the truth either. What it can do is refuse to be
   quiet about it, and refuse to go on without its owner: the chain head no
   longer matches, so the next unlock is refused with `crypto`, the
   truncation is recorded in the chain for good, and from then on every
   unlock and operation is refused until the owner has reviewed the
   surviving history (`audit`, `audit --verify`, ideally against a backup)
   and acknowledged the truncation (`audit --acknowledge`). The
   acknowledgement is a keyed row, so it cannot be forged, and removing it
   re-opens the question. What the acknowledgement cannot do is recover the
   missing events: after it, the surviving history is what the vault goes
   by, and the replayed row is served. The decision is the owner's, made
   with the evidence in front of them, not the file's. Replay of a row
   *without* touching the log is refused outright (schema 3).
7. **Migration is trusted once.** `vault migrate` takes the rows it finds at
   face value, by explicit command, exactly once: a schema 1 vault has no
   integrity data at all, and a schema 2 vault's rows are authenticated but
   not yet bound to the chain, so a row replayed into either file before the
   migration becomes its checkpoint. A passphrase protector that was not used
   for the migration stays bound to the old format until it next unlocks the
   vault, and until then a rollback attack through that passphrase remains
   possible on that file.
8. **Keyring cleanup sees only this home.** `vault destroy` refuses to delete
   a credential-store entry that another vault file in the same home
   references, but a copy of the vault kept elsewhere is invisible to that
   check; use `--keep-os-key` when a vault file has been copied.

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
