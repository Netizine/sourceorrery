# Vault file format (schema version 3)

A vault is a single SQLite database, `<home>/vaults/<name>.sorvault`, created
with `PRAGMA foreign_keys = ON`, `PRAGMA secure_delete = ON` and a 5 s busy
timeout. Every write runs in a `BEGIN IMMEDIATE` transaction.

Default home: `%LOCALAPPDATA%\sourceorrery` (Windows),
`~/Library/Application Support/sourceorrery` (macOS),
`$XDG_DATA_HOME/sourceorrery` or `~/.local/share/sourceorrery` (Linux);
override with `SOURCEORRERY_HOME` or `--home`.

## Tables

### `vault_meta (key, value)`

| key | value |
|-----|-------|
| `schema_version` | `3` |
| `name` | vault name |
| `id` | 32 hex chars, random; bound into every AAD and every integrity tag |
| `created_on` | Unix nanoseconds |
| `recovery_level` | `"recoverable"` or `"purgeable"` (JSON string) |
| `retention_days` | 7–90 |
| `audit_head` | `<id>:<hex HMAC>` — the newest keyed audit row; see *Audit chain* |
| `settings_tag` | hex HMAC-SHA256 over the settings record (`schema_version`, `name`, `id`, `created_on`, `recovery_level`, `retention_days`); verified on every unlock |

### `key_protectors`

| column | meaning |
|--------|---------|
| `id` | 16 hex chars, random |
| `label` | unique human label (`os-keyring`, `passphrase`, `ci`, …) |
| `kind_json` | `{"kind":"os-keyring","service":"sourceorrery","account":"vault/<vault id>/<id>"}` or `{"kind":"passphrase","salt":"<hex 16 bytes>","params":{"memory_kib":65536,"iterations":3,"parallelism":1}}` |
| `wrapped_nonce` | 24-byte XChaCha20 nonce |
| `wrapped_dek` | DEK encrypted under the protector's KEK; AAD `sourceorrery/v<schema>/protector/<vault id>/<protector id>`, so the wrapped key is bound to the on-disk format it was written for (`v3` now; an older `v<n>` only on protectors not yet re-wrapped since a migration) |
| `created_on` | Unix nanoseconds |

### `secrets`

| column | meaning |
|--------|---------|
| `name` | primary key, Azure Key Vault naming rules |
| `created_on` | first version's time |
| `deleted_on` | NULL while live |
| `scheduled_purge_on` | `deleted_on + retention` |
| `recovery_id` | `sourceorrery://<vault>/deletedsecrets/<name>` |
| `tag` | HMAC-SHA256 over the row (see *Metadata tags*) |

### `secret_versions`

| column | meaning |
|--------|---------|
| `name`, `version` | primary key; `version` is 32 hex chars, random |
| `seq` | vault-wide monotonic counter; newest = highest |
| `nonce` | 24-byte XChaCha20 nonce |
| `ciphertext` | value ‖ 16-byte Poly1305 tag; AAD `sourceorrery/v1/value/<vault id>/<name>/<version>` |
| `content_type` | optional |
| `tags_json` | JSON object |
| `enabled` | 0/1 |
| `not_before`, `expires_on` | optional Unix nanoseconds |
| `created_on`, `updated_on` | Unix nanoseconds |
| `tag` | HMAC-SHA256 over the row (see *Metadata tags*) |

### `audit_events`

| column | meaning |
|--------|---------|
| `id` | autoincrement |
| `occurred_on` | Unix nanoseconds |
| `actor` | `user:<name>`, `system:sourceorrery`, … |
| `operation` | `vault_create`, `vault_open`, `vault_migrate`, `protector_add`, `protector_remove`, `secret_set`, `secret_get`, `secret_list`, `secret_update`, `secret_delete`, `secret_recover`, `secret_purge`, `audit_verify` |
| `secret_name`, `version` | optional |
| `outcome` | `success`, `denied`, `failure` |
| `detail` | error code or short note; **never a value** |
| `prev_hash` | `hash` of the previous row (32 zero bytes for the first) |
| `hash` | `HMAC-SHA256(k, canonical(prev_hash, row))` (see *Audit chain*) |
| `keyed` | 1 when `k` is the metadata key, 0 when it is the all-zero key |
| `state_tag` | checkpoint of the `secrets` row named by `secret_name` after this event: the row's new `tag`, or the empty blob when the row was removed; NULL when the event did not change it (see *Checkpoints*) |
| `version_tag` | checkpoint of the `secret_versions` row named by `secret_name` + `version`, likewise |

Index `audit_checkpoints` on `(secret_name, id)` covers the rows where
either checkpoint column is set, so finding a secret's checkpoints does not
scan its reads.

## Key hierarchy

```
DEK (32 random bytes) ── XChaCha20-Poly1305 ──► each value
  │
  └─ HKDF-SHA256(ikm = DEK, salt = none, info = "sourceorrery/v2/metadata")
         └──► metadata key ── HMAC-SHA256 ──► metadata tags, audit chain, audit head
  ▲ wrapped by
KEK per protector:
  os-keyring  : 32 random bytes stored in the OS credential store
                service "sourceorrery", account "vault/<vault id>/<protector id>"
  passphrase  : Argon2id(passphrase, salt, params) → 32 bytes
```

The metadata key is never stored; it is re-derived from the DEK on every
unlock. Nothing that can be read from the file allows computing it.

Unlock order: every `os-keyring` protector is tried first (no interaction);
then the passphrase provider is asked up to three times and each passphrase is
tried against every passphrase protector. Every failed attempt is an audit row
(`vault_open` / `denied`); giving up writes `vault_open` / `failure`.

## What is encrypted

Only `secret_versions.ciphertext` and `key_protectors.wrapped_dek`.
Names, tags, timestamps, flags and audit rows are plaintext. Since schema 2
the mutable plaintext is **authenticated**, so it can be read without the
key but not changed without detection, and since schema 3 each row is also
**bound to the audit chain**, so an older authentic copy of it cannot be
put back (see [threat-model.md](threat-model.md)).

## Metadata tags

Every `secrets` and `secret_versions` row carries `tag =
HMAC-SHA256(metadata key, canonical(row))`. The tag is written with every
insert and update and verified on every read; a row whose tag does not
verify is refused with error code `crypto` ("metadata integrity check failed
for `<name>`") and a `failure` audit row. Nothing is ever repaired or
purged on the strength of unverified metadata: a forged `deleted_on` is not
honoured, and a forged purge date does not purge.

The version tag does not cover `nonce` or `ciphertext`; the AEAD protects
those (see *What is encrypted*). Reads verify a secret's version rows from
the metadata columns alone and fetch the nonce and ciphertext of the one
version they return, so a damaged value is detected when that version is
read, not when the secret is listed or another version is read.

## Checkpoints

A tag proves that the vault wrote a row at some point, not that the row is
current: an earlier copy of the same row, tag included, verifies just as
well. So every audit event that changes a row also records the state the
row has afterwards, as a *checkpoint* in the event itself:

| event | `state_tag` | `version_tag` |
|-------|-------------|---------------|
| `secret_set` | new `secrets` row's tag (only when the secret is created) | new version row's tag |
| `secret_update` | | updated version row's tag |
| `secret_delete` (soft) | deleted-state tag | |
| `secret_recover` | live-state tag | |
| `secret_delete` (purgeable vault), `secret_purge`, retention purge | empty blob: the row is gone | |
| `vault_migrate` (one per row, detail `checkpoint`) | the row's tag as found | the row's tag as found |

Both columns are part of the row's chain hash, so a checkpoint cannot be
edited, inserted or removed without breaking the chain, and only keyed
rows whose hash verifies count (an unkeyed row is forgeable by design).

Before a row is honoured, its stored `tag` must equal the **newest**
checkpoint for it in the chain, and the tag must verify over the row's
fields. The rule has no accept-if-none case: a row with no checkpoint, a row
whose checkpoint is the empty blob, and a *missing* row whose checkpoint
says it exists are all refused with `crypto` and a `failure` audit row. For
versions, every version checkpointed since the secret was last recorded
absent must be present, so removing the newest version does not make an
older value current. Listings visit every name the chain records, not only
the rows left in the table.

Because the newest checkpoint is what matters, every operation first checks
that the chain head still names the newest keyed row; a shortened chain is
not consulted (see *Audit chain*).

### Canonical encoding

A record is encoded as a sequence of fields in a fixed order. Strings and
byte strings are prefixed with their length as a big-endian `u64`; integers
are 8-byte big-endian two's complement; booleans are one byte (`0`/`1`);
optional fields are a presence byte followed by the value when present.
The first two fields are always a domain string and the vault id, so a tag
from one kind of row, or another vault, never verifies for a different one.

| record | domain | fields, in order |
|--------|--------|------------------|
| version | `sourceorrery/v2/version` | vault id, name, version, seq, enabled, content_type?, tags_json, not_before?, expires_on?, created_on, updated_on |
| secret | `sourceorrery/v2/secret` | vault id, name, created_on, deleted_on?, scheduled_purge_on?, recovery_id? |
| audit row | `sourceorrery/v3/audit` | vault id, prev_hash, id, occurred_on, actor, operation, secret_name?, version?, outcome, detail?, keyed, state_tag?, version_tag? |
| audit head | `sourceorrery/v2/audit-head` | vault id, id, hash |
| settings | `sourceorrery/v2/settings` | vault id, schema_version, name, created_on, recovery_level, retention_days |

`?` marks an optional field (`state_tag?` and `version_tag?` are optional
byte strings); timestamps are their stored Unix-nanosecond integers. The
audit-row domain changed to `v3` when the checkpoint fields were added;
the migration re-chains every existing row under it.

## Audit chain

Each audit row's `hash` is `HMAC-SHA256(k, canonical(prev_hash, row))`,
where `prev_hash` is the previous row's `hash` (32 zero bytes for the first
row). Editing a row, deleting one from the middle, inserting one or
reordering them breaks the chain at the first affected row.

`k` is normally the metadata key (`keyed = 1`). Rows written **before the
vault is unlocked** — failed `vault_open` attempts — cannot use it: they are
chained with the all-zero key and flagged `keyed = 0`. Such rows are
forgeable by anyone who can write the file, but they still take part in
the chain, so removing or inserting one ahead of a keyed row is detected.
`audit --verify` reports them as *unkeyed*, not broken.

Removing rows from the **end** of the log leaves a valid chain, so the
newest keyed row is also pinned by `vault_meta.audit_head =
"<id>:<hex HMAC-SHA256(metadata key, canonical(audit-head, vault id, id, hash))>"`,
rewritten on every keyed append. Before every keyed append the vault checks
that the head still names the newest keyed row; if it does not — rows were
removed after it, or the head record is missing or invalid — it first
appends an `audit_verify` / `failure` row saying so (for example
`rows removed after event 41 (head was event 44)`), and only then the
requested row. The evidence is itself part of the chain; removing it is
another truncation and is detected the same way at the next keyed write.

Since schema 3 the chain is also the record of current row state, so a
shortened chain must not be consulted. Every unlock and every operation
therefore checks the head *first*: when it is stale, the unlock or
operation is **refused** with `crypto` ("audit log integrity: rows removed
after event 41 …"), and that refusal is what writes the `audit_verify` /
`failure` row and re-anchors the head. The next unlock proceeds on the
surviving history, with the truncation permanently on record; see the
threat model for what that does and does not prove.

`SqliteVault::verify_audit_chain()` (`sourceorrery audit --verify`) walks
the whole log and reports: rows, keyed and unkeyed counts, `first_broken`
(the first row whose link or hash fails), `truncations` (keyed
`audit_verify` / `failure` rows) and `head_valid`. The log is intact when
`first_broken` is null, `truncations` is 0 and `head_valid` is true. The
check is read-only.

## Compatibility

`schema_version` is checked on open. A **newer** schema is refused with a
clear error. An **older** schema is refused too (`migration_required`):
migrating is an explicit, one-way command, `sourceorrery vault migrate`,
because the legacy format carries no integrity data and its contents can
only be taken on trust.

The migration is guarded by the key wrapping. Since schema 2 the vault key
is wrapped under an AAD that names the format, so a file whose marker was
edited back to an older number cannot be unwrapped as that older format:
the protector that unlocks it reports the format it was bound to, every
OS-keyring protector is checked the same way, and a key bound to a newer
schema than the marker aborts the migration with `crypto`. Only a key
genuinely wrapped under the marker's AAD enters the migration.

The migration brings schema 1 and schema 2 files to schema 3 in one
transaction: a schema 1 file first gains the integrity columns and a tag on
every row; both then gain the checkpoint columns, every audit row is
re-chained under the current encoding (keyed), one `vault_migrate`
checkpoint event is recorded per `secrets` row and per `secret_versions`
row with the tag the row has (a row with no tag gets no checkpoint and
stays refused), `settings_tag` is written, every key the migration holds is
re-wrapped under the new AAD and `schema_version` is bumped; a final
`vault_migrate` row records `schema <n> -> 3`. A schema 2 file whose audit
head is stale is refused, as an unlock would be, rather than re-chained. A
passphrase protector that was not used for the migration is re-wrapped the
next time it unlocks the vault.

Argon2 parameters stored on a protector are capped before they are run
(1 GiB, 64 passes, 16 lanes; a protector beyond the ceiling is skipped) and
at most eight passphrase protectors are tried per attempt; `vault protector
add` refuses a ninth, so every installed passphrase can unlock.

## Creating a vault

The vault file is created exclusively (`O_EXCL` / `CREATE_NEW`) before
anything is written to it, so of several processes creating the same name
at once exactly one owns the file; the others fail with `vault_exists` and
never touch it. Only the owner removes the file again if the rest of
creation (for example installing an OS-keyring protector) fails.

## Deleting a vault

`sourceorrery vault destroy <name>` reads the protector table (no unlock
needed) and removes the file. An OS-keyring entry listed there is deleted
only when its account is exactly `vault/<this vault id>/<protector id>` and
no other vault file in the same home references it; otherwise it is kept and
reported, because protector metadata is unauthenticated until the vault is
unlocked and must not be allowed to point deletion at another vault's key.
`--keep-os-key` skips credential-store deletion altogether.
