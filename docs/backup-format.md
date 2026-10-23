# Backup file format

`sourceorrery backup` writes one file holding the secrets of a vault, every
version with its value, sealed under a passphrase; `sourceorrery restore`
reads it into a vault ([CLI reference](cli.md#backup-and-restore)). The
file is as sensitive as the vault: its passphrase is the only thing that
protects it. This page is the format, for the record and for anyone who
needs to know what a `.sobackup` file contains.

## Layout

```text
"SOBACKUP"            8 bytes, the magic
header length         u32, little-endian
header                JSON, clear text
nonce                 24 bytes
payload               XChaCha20-Poly1305 ciphertext (tag included)
```

### Header

Clear text, so a backup can be identified without its passphrase
(`sourceorrery restore` prints the source vault and the time before asking
for it). It never names a secret.

| Field | Meaning |
|-------|---------|
| `format` | `1`. A reader refuses a larger number with `backup_format` rather than guessing. |
| `vault`, `vault_id` | The vault the backup was taken from, for the record; a backup can be restored into any vault. |
| `created_on` | RFC 3339, when the export was taken. |
| `kdf` | `argon2id` with `memory_kib`, `iterations` and `parallelism`, the parameters of the protector KDF (64 MiB, 3 passes, 1 lane by default). A reader caps them like a protector's (1 GiB, 64 passes, 16 lanes) before running them. |
| `salt` | 16 random bytes, hex. |
| `verifier` | The magic sealed under the derived key with its own additional data (`sourceorrery/backup/v1/verifier`), `nonce` and `bytes` in hex. |

### Key and payload

The key is Argon2id of the passphrase with the header's parameters and
salt, 32 bytes. The verifier is opened first: if it does not open, the
passphrase is wrong (`backup_passphrase`) and nothing else is read. Then
the payload is opened with the magic and the header bytes, exactly as
stored, as additional authenticated data. Changing the `format`, `vault`,
`vault_id` or `created_on` fields, the nonce or any byte of the payload
makes that fail (`crypto`), so a typo and a tampered file do not read the
same. An edit to the `kdf` parameters, the `salt` or the `verifier`
itself changes the derived key, so a correct passphrase fails the verifier
and the file reads as `backup_passphrase`: those three fields are
authenticated only once the passphrase is right, which is also when a
tampered one can do no harm.

Inside the payload:

```text
metadata length       u32, little-endian
metadata              JSON
values                every value's bytes, back to back, in metadata order
```

The metadata lists each secret (`name`, `created_on`, optional `deleted`
with `deleted_on` and `scheduled_purge_on`) and each of its versions,
oldest first, with `version`, `enabled`, `content_type`, `tags`,
`not_before`, `expires_on`, `created_on`, `updated_on` and `len`, the
length of its value in the bytes that follow. Values are never inside the
JSON: they are copied from the vault's in-memory `SecretBytes` into one
zeroising buffer that is encrypted whole, and sliced back into
`SecretBytes` when the file is opened. A declared length that runs past the
bytes, or bytes left over, is `crypto`. A secret name that is not a valid
secret name is refused before anything is written to a vault.

The audit log is not part of a backup: it is the vault file's history, and
restoring rows into another vault's chain would make that chain lie.

## What restore does

Every version in the backup becomes a **new** version of the target
secret, written through the same checkpointed path as `secret set`, oldest
first so the newest stays newest. The version keeps its metadata (enabled,
content type, tags, time window) and gains two tags:
`sourceorrery.restored-from` with the original version id and
`sourceorrery.restored-created-on` with the original creation time. Each
written version is one keyed `secret_restore` audit event. A name that
already exists in the target is skipped unless `--overwrite` adds the
versions on top; a name the target holds soft-deleted is always skipped. A
secret the backup holds as deleted comes back live, or is soft-deleted
again right after with `--keep-deleted`. Restoring is safe to repeat.

The export that produces a backup reads every version's value, disabled
and expired ones included, which `secret get` would refuse: it is the one
privileged read in the contract, recorded as one `vault_backup` audit event
per secret with the version count as detail
([architecture](architecture.md#the-secretclient-contract)).
