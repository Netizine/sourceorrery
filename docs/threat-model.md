# Threat model

SourceOrrery makes three different promises and keeps them separate. Users,
documentation and marketing must never blur them.

This page describes the 0.2.0 build: the CLI with its vault manager
(`sourceorrery ui`), the encrypted vault, optional AWS Secrets Manager and
HashiCorp Vault providers, and the read-only SDKs for ten languages over
the C ABI and the Rust client. See the [roadmap](roadmap.md) for remaining
work. How the packages themselves are built, published
and checked is in [Supply chain](supply-chain.md).

> [!WARNING]
> SourceOrrery has not been independently audited. The local vault does not
> isolate secrets from code that can use your OS credential store or obtain
> your passphrase. Use development credentials and read the limits below
> before choosing it for a workload.

## The three guarantees

| # | Guarantee | Meaning | Today |
|---|-----------|---------|-------|
| 1 | **At-rest protection** | Values stored by SourceOrrery are encrypted. Its metadata commands, errors and audit records omit values. | **Provided within that boundary.** Input files, exposed copies, child processes and application logs remain the caller's responsibility. |
| 2 | **Access control** | Only authorised identities can retrieve a given secret; access is per secret, revocable and audited. | **Provider-dependent.** Whoever can unlock a local vault is its administrator. Remote providers enforce their own identity and policy controls; SourceOrrery does not add a local isolation boundary. |
| 3 | **Agent isolation** | An untrusted agent or process running as the *same OS user* cannot impersonate an authorised application or modify it to disclose secrets. | **Not provided.** Requires an independently authenticated broker plus OS-level isolation (milestone 3). SourceOrrery will never claim this without an external boundary. |

> [!IMPORTANT]
> Replacing `.env` prevents the vault from creating another plaintext copy;
> it does not remove existing files or revoke credentials. `import` leaves
> the input file intact. Secret names, comments, tags and manifest `purpose`
> fields are plain text, so never put a value in them.

## Assets

* Secret values (highest).
* The vault data-encryption key (DEK) and key-encryption keys (KEKs).
* Passphrases.
* Integrity of ciphertext-to-record binding (which value belongs to which
  secret/version).
* Integrity of the audit log and policy state (enabled flags, time windows,
  deletion state). Authenticated since vault schema version 2 and bound to
  the audit chain since version 3.
* The integrity of the software itself: the CLI, the C ABI library and the
  SDK packages you install ([Supply chain](supply-chain.md)).

Secret *names*, tags, version ids, timestamps and audit metadata are **not**
treated as secrets. Users are told not to put sensitive information in them.

## Adversaries

| Adversary | Capability | Outcome today |
|-----------|------------|---------------|
| **Repository reader** — anyone with the git history, a leaked archive, a code-indexing service, an LLM fed the repo | Reads every committed file | Nothing to find: no `.env`, manifest cannot hold values, references contain no material. |
| **Offline disk reader** — stolen laptop, backup, cloud sync of the data directory | Reads the vault file and (if synced) OS-store artefacts | Values are XChaCha20-Poly1305 ciphertext. Passphrase KEK needs Argon2id (64 MiB, 3 passes). OS-keyring KEK is protected by the platform store's own at-rest protection (DPAPI / Keychain / login keyring). |
| **Tamperer** — can modify the vault file but cannot unlock it | Swaps or edits ciphertext, flips `enabled`, edits timestamps or tags, undeletes a secret, edits or deletes audit rows | Ciphertext swap/edit is detected (AAD binding + AEAD tag). Mutable metadata carries an HMAC under a key derived from the DEK, checked on every read: a re-enabled version, extended expiry, cleared `not_before`, edited tags or forged deletion state is refused with `crypto` and audited. The audit log is a keyed hash chain with a keyed head record: edits, gaps and reordering break the chain; rows removed from the end are detected and recorded at the next unlock, and the vault then refuses every unlock and operation until its owner has reviewed the surviving history and acknowledged the truncation. Rows written before unlock (failed attempts) are chained with a public key: forgeable, but not silently removable. Vault-wide settings (schema, name, recovery level, retention) carry their own HMAC, so retention cannot be shortened to force a purge. A schema marker rolled back to the legacy format is refused: the vault key is wrapped under an AAD that names the format, and migration is only ever an explicit command. Removing the whole audit history together with its head is recorded, not accepted as a fresh log. Putting one vault's file in place of another's (renamed, copied or swapped) is refused: a vault opened by name must carry that name in its authenticated settings, so a reader asking for `prod` is never handed a file that unlocks as `dev` (`vault_mismatch`, recorded in that file's log). |
| **Careless operator / agent reading output** | Sees stdout/stderr of CLI commands, logs, JSON | Metadata commands never show values; `--reveal` is explicit; prompts never echo; `-v` never prints values; the `ui` browser cannot read a value at all; SDK values print as `[REDACTED]` and no SDK error, message or hint contains one. |
| **Compromised dependency inside an application** | Runs inside a process that uses an SDK | Reads every secret the application can read: the same process, the same unlock. Cannot write through the SDK: no binding has a set, update, delete, recover, purge, protector or audit operation ([ADR 0005](adr/0005-read-only-sdks.md)), so it cannot plant a value or disable a version through the library. Read-only is a smaller surface, not a boundary: the write-capable `so_vault_*` functions are in the same C ABI library for tooling, and code that can load them or run the CLI is the same-user process below. Every read it makes is audited. |
| **Supply-chain attacker** | Alters a dependency, the build, or a package between the repository and you | Locked dependencies, `cargo audit` in CI, one workflow that builds every package from one commit, trusted publishing for npm, PyPI, crates.io and NuGet, with provenance on npm and PyPI, signed artefacts on Maven Central, `SHA256SUMS` on every release. The archives on the GitHub release are not signed; see [Supply chain](supply-chain.md). |
| **Same-user malicious process or agent** | Runs code as you, reads your memory, calls the CLI, reads the OS credential store under your login | **Not defended.** Can call `secret get --reveal` with the same available unlock credentials. This is the boundary of the local vault and the reason the broker is planned. |
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
| Audit log integrity | Keyed hash chain over `audit_events` plus a keyed head record that names the newest keyed row and counts the keyed rows. Every unlock walks the chain from the newest acknowledgement to the end: a row that does not follow its predecessor, or whose hash does not verify (one removed, replaced or edited inside the log), refuses the unlock, is recorded as `audit_verify` / `failure` and blocks the vault like a truncation. Before every operation the head is checked: rows removed from the end, a missing or invalid head, or a keyed row removed or demoted from the middle fail it. `sourceorrery audit --verify` reports breaks, truncations and unkeyed rows (`storage::integrity`, `storage::sqlite::audit`; [security review](security-review.md), finding 1) |
| Truncation blocks the vault until acknowledged | A recorded truncation that no later keyed `audit_verify` / `success` acknowledgement covers refuses every unlock and operation with `crypto`, naming the event; only `sourceorrery audit` and the audit view of `sourceorrery ui` unlock such a vault: both for reading the log, `audit` also for verifying the chain and for `audit --acknowledge`, which prints the truncation events, asks for confirmation and appends the acknowledgement under the vault key. Refusals and the acknowledgement are themselves on the chain; removing the acknowledgement is another truncation that un-acknowledges what it covered (`storage::sqlite::audit`, [vault-format.md](vault-format.md#audit-chain)) |
| Every rejected operation is audited | Invalid names, rejected time windows and tags, empty updates and refused protector changes go through the same failure path as any other error: the operation body is rolled back and one `failure` row is committed (an invalid name is not recorded, since it is arbitrary input) |
| Exclusive vault creation | The vault file is created with `O_EXCL` / `CREATE_NEW`; concurrent creators get `vault_exists` and never remove the winner's file |
| Accepted credentials can unlock | At most 8 passphrase protectors can be installed, matching what unlock will try |
| KDF residue | Argon2's working memory and output buffer are caller-owned and zeroised when the derivation ends |
| Secure deletion on purge | SQLite `secure_delete = ON` |
| File permissions | `0700` dir / `0600` file on Unix; profile ACLs on Windows |
| Memory hygiene | `zeroize` on `SecretBytes`, `SymmetricKey`, decrypted buffers |
| Authenticated vault settings | HMAC over schema, name, recovery level and retention, verified on every unlock |
| A vault is only served under its own name | Opening by name compares the requested name with the authenticated name in the file, once the settings verify (before any migration for a legacy file); a mismatch is refused with `vault_mismatch` and recorded as `vault_open` / `failure` in that file's log (`storage::registry`, `storage::sqlite`) |
| Format bound into key wrapping | The wrapped vault key's AAD names the schema; a rolled-back marker cannot unwrap as legacy |
| Explicit, one-way legacy migration | `vault migrate` only; plain `open` refuses older schemas |
| Audit history must exist | An existing vault with no rows and no head is a detected truncation, never a fresh start |
| Resource ceilings before authentication | Argon2 parameters from the file are capped (1 GiB, 64 passes, 16 lanes); at most 8 passphrase protectors are tried |
| Keyring entries deleted only when provably this vault's | Account must match the vault's own identity and no sibling vault may reference it; `--keep-os-key` opts out |
| No secret echoes in diagnostics | Manifest parse errors report a category and position, never the offending text |
| Terminal output sanitised | Text read from the vault file can be planted by a tamperer: protector labels and keyring accounts are not authenticated at all, and the vault name is not until unlock. Audit rows written before unlock can be forged too. So table output, status lines, notes, errors and prompts show control characters (C0 including ESC, TAB, CR and LF; DEL; C1), bidi formatting characters and the invisible formatting characters (zero-width space, word joiner, byte-order mark, tag characters) as `\u{..}` escapes; text a provider's server supplies is bounded and cleaned the same way before it enters any error message, since the SDKs print messages as they are (`sourceorrery_core::text`). Planted text cannot move the cursor to hide audit rows, write the clipboard (OSC 52) or reorder what is shown. Multi-line messages keep their own line breaks. JSON is left to serde, and revealed values stay byte-exact (`cli::output::sanitize`) |
| Idle lock in the browser | `ui` drops the open vault after `--lock-after` minutes without a key (default 10) and on `L`, so the vault key, zeroised as it is dropped, does not stay in memory for a long-lived session; unlocking again goes through the ordinary unlock order (`sourceorrery-cli::ui`) |
| Value-free interactive browser | `ui` reads the vault only through `MetadataSource`, which has no operation returning a value, so no value is drawn, held in its screen buffers or copied anywhere. Its changes go through a separate `MetadataEditor` (metadata, delete, recover, new versions; no purge, protector or acknowledgement), each checked and confirmed first; a new value is read at the ordinary hidden prompt with the screen suspended and passed straight to the vault; `--read-only` refuses every change; stored text goes through the same `output::sanitize` as the rest of the CLI (`sourceorrery-cli::ui`) |
| Child environment hygiene | `run` and the rotation hooks remove `SOURCEORRERY_PASSPHRASE`, `SOURCEORRERY_PASSPHRASE_FILE`, `SOURCEORRERY_BACKUP_PASSPHRASE` and `SOURCEORRERY_TOTP` from the child; manifests cannot deliver under `SOURCEORRERY_*` names, nor under a variable that changes how programs load or run (`PATH`, `LD_*`, `DYLD_*`, `NODE_OPTIONS`, `JAVA_TOOL_OPTIONS` and the like), since a manifest is repository content |
| Importing `.env` files without showing them | `import` reads the file into zeroised memory and stores each value straight into the vault; its table, JSON and errors carry key names and line numbers only, so a person or a coding agent can migrate a project without values reaching a terminal, a log or a model's context (`sourceorrery-cli::commands::import`, `dotenv`) |
| Agent skills that never handle values | The skills `init --integration` installs tell an agent to learn key names from `import --dry-run`, to ask the user to type new values at the hidden prompt, and never to open `.env` files, reveal values or print the environment. They are instructions, not a boundary: see guarantee 3 ([AI coding agents](ai-agents.md)) |
| Read-only SDKs | Every binding exposes only the read-only `so_reader_*` / `so_project_*` surface or the Rust client: open, get, properties, resolve, load a project. No write, protector or audit operation exists in any SDK ([ADR 0005](adr/0005-read-only-sdks.md)) |
| One unlock order, no prompt in a library | The Rust client owns the unlock order (OS credential store, an explicit passphrase, `SOURCEORRERY_PASSPHRASE`, `SOURCEORRERY_PASSPHRASE_FILE`); SDKs never prompt and never migrate a vault (`crates/sourceorrery`) |
| Values guarded in every language | A value stays in native memory until the application closes it and is zeroised then (`so_bytes_free`, `SecretBytes`); the wrapper prints as `[REDACTED]` and refuses serialisation where the language allows; bytes leave only through an explicit call (`docs/sdks`) |
| Same behaviour in every SDK | One scenario list, judged by one harness, runs against every SDK in CI on Ubuntu, Windows and macOS (`tests/conformance/sdk`) |
| A second check before a person sees a value | The reveal guard (`vault guard`) makes `secret get --reveal`, `backup` and every change to how the vault unlocks ask for the vault passphrase again, a TOTP code from an authenticator app, or both, even when the OS keyring unlocked the vault. The guard and the TOTP secret (sealed with the vault key, with the last accepted step so a code is never accepted twice) live in the authenticated settings record, so a file edit cannot switch the guard off. `run`, `check`, `ui` and the SDKs are untouched: the guard is for the moments a person or an agent at the CLI asks to see a value, not a boundary (`storage::sqlite::guard`, `cli::commands::guard`) |
| A vault is not lost with its passphrase | `vault recovery codes` installs up to 7 random 125-bit codes as passphrase protectors, shown once; one unlocks the vault in place of the passphrase, and `vault passphrase set` then replaces it. A passphrase hint is stored in clear and shown at the prompt; it is refused when it would itself unlock the vault, and it is never trusted (see gap 12) |
| Typed passphrases rated before they are accepted | A passphrase typed at the prompt must rate "good" on a rule-based estimate (common passwords, dictionary-style words, repeats, sequences, years, short lengths; no wordlist shipped) unless `--allow-weak`; `vault passphrase generate` offers one from the OS random source (`cli::strength`). The `setup` wizard applies the same rule to the passphrase and to the first secret as they are typed, draws hidden fields as dots from their length, wipes its buffers, and shows only a generated passphrase and the recovery codes, once (`cli::ui::setup`) |
| Manifest discovery bounded | Without an explicit path, `sourceorrery.toml` is looked for in the working directory and its parents only up to the repository (`.git`), the home directory, and, on Unix, no further than directories and files owned by the home directory's owner. A manifest decides which vault a name means and where a provider credential is sent, so one planted in `/tmp` or a shared parent is never picked up (`core::manifest::Manifest::discover`) |
| Clear text only to the local machine | A remote provider's `address` or `endpoint_url` must be `https://`, or `http://` to `localhost`, `127.0.0.0/8` or `::1`; the Vault client follows no redirect and uses no proxy for a loopback address, so a token never travels to another host (`core::remote`, `sourceorrery-provider-vault::http`) |
| Release integrity | Locked builds, `cargo audit`, one release workflow from one commit, trusted publishing on every registry that offers it (npm, PyPI, crates.io, NuGet) with provenance on npm and PyPI, signatures on Maven Central, checksums on the release ([Supply chain](supply-chain.md)) |

## Known gaps

1. **Agent isolation.** See guarantee 3.
2. **Process environment exposure.** `run` delivers secrets as environment
   variables of the child process, visible to anything that can read that
   process's environment (`/proc/<pid>/environ`, Process Explorer). This is
   the pragmatic bridge from `.env`. Reading through an SDK avoids it: the
   value stays inside the process that asked for it.
3. **Side channels.** Argon2id, HMAC and the AEAD implementations are
   RustCrypto's; no additional constant-time guarantees are claimed beyond
   theirs.
4. **Release signing is partial.** npm and PyPI files carry provenance,
   Maven Central artefacts are signed with the release key and nuget.org
   signs every package it serves, but the archives on the GitHub release
   have checksums and no signature, and the binaries are neither notarised
   (macOS) nor Authenticode-signed (Windows). See
   [Supply chain](supply-chain.md#not-done-yet).
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
   quiet about it, and refuse to go on without its owner: the chain no
   longer verifies (rows removed from the end leave the head naming a row
   that is gone; a row removed from the middle leaves the next one not
   following its predecessor, which the unlock's walk finds), so the next
   unlock is refused with `crypto`, the
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
   check; use `--keep-os-key` when a vault file has been copied. The
   identity the check reads (the vault id and the protector id in the file)
   is not authenticated before unlock, so a decoy file copying a real
   vault's identity passes it; what that costs is one credential-store
   entry, never a value.
9. **Copies an application makes.** An SDK zeroises the value it holds,
   but not the copies an application takes out of it: a Python `str`, a
   Java `String` or a JavaScript string cannot be wiped. Keep such copies
   short-lived.
10. **The OS-keyring path is checked headlessly, and by hand in a desktop
    session.** The conformance suite uses passphrase protectors only. CI
    runs `scripts/dev/keyring-smoke.sh` (and `.ps1` on Windows) against a
    real store on every push: a temporary keychain on macOS, GNOME Keyring
    under a private session bus on Linux, Credential Manager on Windows. A
    desktop session differs (the login keychain, a keyring or KWallet
    unlocked at login, prompts), so the same script is run by hand there;
    the macOS and Linux desktop runs are not yet recorded
    ([roadmap](roadmap.md)).
11. **A backup is as sensitive as the vault, and only a passphrase protects
    it.** `sourceorrery backup` writes every value, sealed under Argon2id
    and XChaCha20-Poly1305 ([format](backup-format.md)); no OS credential
    store is involved, so the file can be opened wherever its passphrase
    is. Choose it as you would a vault passphrase, keep the file where the
    vault's threat model allows, and remember that restoring it writes
    every version into the target, audited but not reversible except by
    deleting the secrets again.
12. **The reveal guard and the hint are for people, not against a
    process.** The guard is satisfied by `SOURCEORRERY_PASSPHRASE` and
    `SOURCEORRERY_TOTP` (or `--code`), so anything that runs as you and
    holds both passes it as a script would; and a code read from the
    phone is good for thirty seconds either side of its step, once. The
    passphrase hint is a `vault_meta` row outside every tag, readable and
    writable before unlock: a tamperer can plant one (it is sanitised
    before it is shown, so it cannot drive the terminal), and it must
    never be the passphrase in disguise. Recovery codes are passphrase
    protectors: as strong as the Argon2 parameters they are wrapped under,
    and as safe as the paper they are written on; one satisfies the guard's
    passphrase factor, since it is a way in by design. The guard belongs to
    the local vault file: a reveal from a remote vault is governed by the
    provider's policy alone.
13. **Between an unlock and the operations that follow, the head is the
    check.** The unlock walks the whole chain; each operation after it
    re-checks the head and its count of keyed rows, which catches rows
    removed from the end or the middle but not a keyed row replaced by a
    forgery of the same count while the handle is open. That needs write
    access to the file between two operations of one process, and the
    forgery is found at the next unlock. Walking the chain on every
    operation would make each one cost the size of the log.
14. **A remote vault's policy is the provider's metadata.** On HashiCorp
    Vault the `enabled` flag, the time window, the deletion marker and the
    rotation state live in `custom_metadata`; on AWS Secrets Manager in
    tags. Whoever may write that metadata (`update` on
    `<mount>/metadata/<name>`; `secretsmanager:TagResource`) administers
    the policy, and nothing in the client can tell a planted flag from a
    set one: the local vault's tags and checkpoints have no counterpart
    there. Grant metadata write capability as policy administration
    ([enterprise](enterprise.md), [security review](security-review.md),
    finding 6).
15. **An explicit manifest is trusted as given.** The discovery bounds
    above apply to the manifest found upwards from the working directory;
    `--manifest FILE` and `OpenOptions::manifest` use the file they name.

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

Until then, SourceOrrery encrypts the values it stores, supports manifests
containing references instead of values, and audits vault operations. These
controls reduce accidental exposure; they do not control what an application
or a process with the same credentials does with a value after reading it.
