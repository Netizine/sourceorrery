# Vault file format (schema version 1)

A vault is a single SQLite database, `<home>/vaults/<name>.sorvault`, created
with `PRAGMA foreign_keys = ON` and `PRAGMA secure_delete = ON`.

Default home: `%LOCALAPPDATA%\sourceorrery` (Windows),
`~/Library/Application Support/sourceorrery` (macOS),
`$XDG_DATA_HOME/sourceorrery` or `~/.local/share/sourceorrery` (Linux);
override with `SOURCEORRERY_HOME` or `--home`.

## Tables

### `vault_meta (key, value)`

| key | value |
|-----|-------|
| `schema_version` | `1` |
| `name` | vault name |
| `id` | 32 hex chars, random; bound into every AAD |
| `created_on` | Unix nanoseconds |
| `recovery_level` | `"recoverable"` or `"purgeable"` (JSON string) |
| `retention_days` | 7–90 |

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

### `audit_events`

| column | meaning |
|--------|---------|
| `id` | autoincrement |
| `occurred_on` | Unix nanoseconds |
| `actor` | `user:<name>`, `system:sourceorrery`, … |
| `operation` | `vault_create`, `vault_open`, `protector_add`, `protector_remove`, `secret_set`, `secret_get`, `secret_list`, `secret_update`, `secret_delete`, `secret_recover`, `secret_purge` |
| `secret_name`, `version` | optional |
| `outcome` | `success`, `denied`, `failure` |
| `detail` | error code or short note; **never a value** |

## Key hierarchy

```
DEK (32 random bytes) ── XChaCha20-Poly1305 ──► each value
  ▲ wrapped by
KEK per protector:
  os-keyring  : 32 random bytes stored in the OS credential store
                service "sourceorrery", account "vault/<vault id>/<protector id>"
  passphrase  : Argon2id(passphrase, salt, params) → 32 bytes
```

Unlock order: every `os-keyring` protector is tried first (no interaction);
then the passphrase provider is asked up to three times and each passphrase is
tried against every passphrase protector. Every failed attempt is an audit row
(`vault_open` / `denied`); giving up writes `vault_open` / `failure`.

## What is encrypted

Only `secret_versions.ciphertext` and `key_protectors.wrapped_dek`.
Names, tags, timestamps, flags and audit rows are plaintext and are **not**
integrity-protected in schema version 1 (see [threat-model.md](threat-model.md)).

## Compatibility

`schema_version` is checked on open; a newer schema is refused with a clear
error. Argon2 parameters are stored per protector, so defaults can be raised
without breaking existing vaults. Migrations will bump `schema_version` and be
forward-only.

## Deleting a vault

`sourceorrery vault destroy <name>` reads the protector table (no unlock
needed), deletes any OS-keyring entries it references, then removes the file.
