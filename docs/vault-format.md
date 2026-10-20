# Vault file format (schema version 2)

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
| `schema_version` | `2` |
| `name` | vault name |
| `id` | 32 hex chars, random; bound into every AAD and every integrity tag |
| `created_on` | Unix nanoseconds |
| `recovery_level` | `"recoverable"` or `"purgeable"` (JSON string) |
| `retention_days` | 7–90 |
| `audit_head` | `<id>:<hex HMAC>` — the newest keyed audit row; see *Audit chain* |

### `key_protectors`

| column | meaning |
|--------|---------|
| `id` | 16 hex chars, random |
| `label` | unique human label (`os-keyring`, `passphrase`, `ci`, …) |
| `kind_json` | `{"kind":"os-keyring","service":"sourceorrery","account":"vault/<vault id>/<id>"}` or `{"kind":"passphrase","salt":"<hex 16 bytes>","params":{"memory_kib":65536,"iterations":3,"parallelism":1}}` |
| `wrapped_nonce` | 24-byte XChaCha20 nonce |
| `wrapped_dek` | DEK encrypted under the protector's KEK; AAD `sourceorrery/v1/protector/<vault id>/<protector id>` |
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
key but not changed without detection (see [threat-model.md](threat-model.md)).

## Metadata tags

Every `secrets` and `secret_versions` row carries `tag =
HMAC-SHA256(metadata key, canonical(row))`. The tag is written with every
insert and update and verified on every read; a row whose tag does not
verify is refused with error code `crypto` ("metadata integrity check failed
for `<name>`") and a `failure` audit row. Nothing is ever repaired or
purged on the strength of unverified metadata: a forged `deleted_on` is not
honoured, and a forged purge date does not purge.

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
| audit row | `sourceorrery/v2/audit` | vault id, prev_hash, id, occurred_on, actor, operation, secret_name?, version?, outcome, detail?, keyed |
| audit head | `sourceorrery/v2/audit-head` | vault id, id, hash |

`?` marks an optional field; timestamps are their stored Unix-nanosecond
integers.

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
Note that `vault_open` is a keyed write, so the check runs on every unlock.

`SqliteVault::verify_audit_chain()` (`sourceorrery audit --verify`) walks
the whole log and reports: rows, keyed and unkeyed counts, `first_broken`
(the first row whose link or hash fails), `truncations` (keyed
`audit_verify` / `failure` rows) and `head_valid`. The log is intact when
`first_broken` is null, `truncations` is 0 and `head_valid` is true. The
check is read-only.

## Compatibility

`schema_version` is checked on open. A **newer** schema is refused with a
clear `storage` error. An **older** supported schema (currently 1) is
migrated forward in one transaction the first time it is unlocked: the
columns above are added, every `secrets` and `secret_versions` row is
tagged, every existing audit row — including pre-migration failed unlocks —
is chained under the metadata key, the head is written, `schema_version`
becomes `2` and a `vault_migrate` / `success` row (`schema 1 -> 2`) is
appended. A migrated vault can no longer be opened by a schema 1 build.

Argon2 parameters are stored per protector, so defaults can be raised
without breaking existing vaults. Migrations are forward-only.

## Deleting a vault

`sourceorrery vault destroy <name>` reads the protector table (no unlock
needed), deletes any OS-keyring entries it references, then removes the file.
