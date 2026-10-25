# ADR 0010: Authenticated key wraps, schema 5, and private key files

**Status:** accepted · **Date:** 2026-10-25 · **Changes:** ADR 0009 (what
replacing a recovery key guarantees; the schema it settled), and, for one
crate, the workspace rule that only `sourceorrery-ffi` uses `unsafe`

## Context

The security review of 2026-10-25 (`SECURITY-REVIEW-2026-10-25.md`) found
two problems this record settles before any code changes.

**SR01.** A vault's key is wrapped once per key that opens it: this
machine's key and one recovery key (ADR 0009). Replacing the recovery key
deletes the old recovery wrap and wraps the *same* data-encryption key
(DEK) under the new key. The `key_wraps` table is not part of the
authenticated settings record, and the event that replaces the key does
not bind the new set of wraps. Putting the old wrap row back into the
current file, with the old recovery key, opens the vault and returns
values written after the replacement, and the audit chain still verifies.
`docs/cli.md` and the threat model promise that the old key "stops
working".

**SR04.** `vault create --recovery-key-out FILE` asks for mode `0600` on
Unix but creates the file with inherited permissions on Windows, while
saying it is "readable by you only". Under a shared parent directory the
plaintext recovery key, which opens the whole vault and passes its view
check, is readable by other accounts.

## Decision

### 1. The key wraps are part of the settings record

Every `key_wraps` row is appended to the authenticated settings record
(`integrity::SettingsFields`), in id order, under the label `key_wraps`
with their count: the wrap's id, its `kind_json`, the wrapped key's nonce
and bytes, and its `created_on`, each length-prefixed by the same
canonical encoder as the rest of the record. Unlike the connections and
projects, the section is always present: every vault has exactly one
recovery wrap.

Because the settings record is checkpointed on the audit chain (its tag
is carried by the event that wrote it, and a record whose tag is not the
newest checkpoint is refused), the set of wraps is too. Every change to
`key_wraps` rewrites the record in the same transaction, and the change's
audit event carries the new tag:

| Change | Event that checkpoints the new set |
|---|---|
| a vault is created (its recovery wrap, and this machine's when the store is available) | `vault_create` |
| the recovery key is replaced (setup screens through `change_settings`, or `replace_recovery_key`) | `protector_add` ("recovery key replaced") |
| this machine's key is added | `protector_add` ("this machine's key added") |
| a copy is exported (the copy loses its this-machine wraps) | the copy's own `vault_export` |
| a copy is imported (another machine's wraps removed, this machine's added) | `vault_import` |

Opening a vault already verifies the settings record against the newest
checkpoint after a candidate DEK unwraps and before anything is read. A
substituted, added or removed wrap row now changes the record and is
refused with `crypto`, and putting back the old record as well is refused
because the chain's newest checkpoint is the new one. `keyring_accounts`
still reads the wraps of an unopened file (to find credential-store
entries for `vault destroy`); it is documented as unauthenticated and its
callers keep their existing checks.

### 2. What replacing a recovery key guarantees

Replacing the recovery key makes **the current file** refuse the old key,
including when an old wrap row (or the old settings record with it) is
put back. It does **not** change the DEK. Whoever held the old recovery
key and a copy of the file, or of its old wrap row, from before the
replacement can derive the DEK and decrypt any copy of the vault, the
current file included, with their own tools; no change to the file can
revoke a key someone already knows. The documentation states exactly this
and no more.

In-place DEK rotation (re-encrypting every value and re-authenticating
every row under a new DEK) is a separate feature, not part of 0.3.0.

### 3. Compromise response: a new vault and new values

When a recovery key, an exported copy or a machine may be compromised,
the secrets themselves must be assumed known, so re-storing them anywhere
does not help. The procedure (`docs/threat-model.md`, `docs/cli.md`):

1. Rotate every affected credential at its issuer (the database, the API
   provider, the cloud account), so the exposed values stop working.
2. Create a new vault (`sourceorrery setup`): a fresh DEK and recovery key.
3. Store the new values in it (`secret set`, or `import` from a new
   `.env`), and point each project at it (`init`).
4. Destroy the old vault (`vault destroy`) and the exported copies you
   control. Copies and backups elsewhere stay readable to whoever holds
   the old key; they can no longer be made unreadable.

`vault export` and `vault import` preserve the DEK and the recovery key by
design (a copy for another machine); they are never compromise recovery.

### 4. Schema 5

Authenticating the wraps changes what a valid file is, and files with the
schema-4 settings record exist (development builds of `main`). Rather than
redefine an existing format, the format becomes **schema 5**. Schemas 1 to
4 are refused with `migration_required`, without opening or changing the
file. The record's encoding domains do not change: the schema number is
itself in the record. ADR 0007 is unaffected beyond this: schema 4 was
never released, the C ABI and the contract do not change, and no error
code is added.

### 5. Private files: `sourceorrery-os`, the second crate with `unsafe`

Setting a file's Windows permissions at creation needs Win32 calls
(`CreateFileW` with a security descriptor), which need `unsafe`. Setting
them after the file exists leaves a window in which another account can
open a handle and keep it; checking a dependency's `unsafe` is no better
than reviewing our own. So a new crate, `crates/sourceorrery-os`, is the
second crate allowed `unsafe` (after `sourceorrery-ffi`), over Microsoft's
maintained `windows-sys`. Its whole public surface is one safe function:

```rust
pub fn create_private_new(path: &Path) -> std::io::Result<std::fs::File>;
```

It takes no key material and returns an empty file only once these hold:

* **At creation.** `CreateFileW` with `CREATE_NEW` and an explicit
  security descriptor: owner the current user (the process token's user
  SID), a *protected* DACL granting full access to that user and to
  `SYSTEM` only, so nothing is inherited from the parent; the handle is
  not inheritable. An existing file is never opened or changed.
* **Verified before returning.** The owner and the DACL are read back
  through the created handle and must be exactly that. A volume that does
  not keep ACLs (`FILE_PERSISTENT_ACLS` unset, as on FAT) is refused. On
  any failure the empty file is removed and an error returned; there is
  no fallback to ordinary creation.
* **Unix.** `O_CREAT | O_EXCL` with mode `0600` through the standard
  library, then the mode is checked; no `unsafe` there.
* **Small and checked.** Ordinary files only. Native handles, the token
  and buffers the system allocates are owned by RAII types that close or
  free them. Every `unsafe` block states the pointer, lifetime and
  ownership facts it relies on; the crate denies `unsafe_op_in_unsafe_fn`
  and clippy's `undocumented_unsafe_blocks`, as `sourceorrery-ffi` does.
  The workspace-wide prohibition stays for every other crate, and
  CLAUDE.md names both exceptions.

The CLI says what is enforced: on Windows the key file is "restricted to
your account and Windows SYSTEM", on Unix it is "readable by you only".
What happens around the file (writing, flushing, the order against
creating the vault) is the CLI's concern, not this crate's.

## Consequences

* A vault made by a development build of `main` (schema 4) must be
  recreated, as earlier vaults must.
* Every new operation that changes `key_wraps` must rewrite the settings
  record and checkpoint it in its event; the storage tests put old wrap
  rows back, with and without the old record, to keep that true.
* Users get an accurate replacement guarantee and a compromise procedure
  that does not pretend export, import or replacement can revoke a key.
* One more crate is reviewed as `unsafe` code. It does one thing, and its
  tests check the resulting ACL rather than only that the call succeeded.

## Alternatives considered

* **A per-row MAC on `key_wraps`.** Detects edits to a row but not an old
  authentic row put back; the settings checkpoint already solves replay
  for connections and projects.
* **Rotating the DEK whenever the recovery key is replaced.** It would
  make the old key useless against values written afterwards, but needs a
  re-encryption of every value and row with crash recovery; deferred as
  its own feature. It still could not protect values the old key's holder
  already read.
* **Keeping schema 4.** Cheaper, but a schema-4 file from `main` would
  then fail with an integrity error instead of `migration_required`.
* **`windows-permissions` or `windows-acl`.** Safe APIs, but unmaintained
  since 2021 and built on `winapi` 0.3; they move the `unsafe` out of
  sight without reducing it.
* **`icacls` after creation.** A window in which another account can open
  a handle, and a dependency on parsing tool output.
