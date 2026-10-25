# Vault file format (schema version 5)

A vault is a single SQLite database, `<home>/vaults/<name>.sorvault`, created
with `PRAGMA foreign_keys = ON`, `PRAGMA secure_delete = ON` and a 5 s busy
timeout. Every write runs in a `BEGIN IMMEDIATE` transaction.

Default home: `%LOCALAPPDATA%\sourceorrery` (Windows),
`~/Library/Application Support/sourceorrery` (macOS),
`$XDG_DATA_HOME/sourceorrery` or `~/.local/share/sourceorrery` (Linux);
override with `SOURCEORRERY_HOME` or `--home`.

> [!WARNING]
> This is a format reference, not a guide to editing a vault with SQL.
> Values, policy metadata and audit checkpoints are authenticated; changing
> rows outside the CLI or storage API can make the vault refuse access.
> Keep exported copies (`vault export`) and use the supported commands for
> changes.

## Tables

### `vault_meta (key, value)`

| key | value |
|-----|-------|
| `schema_version` | `5` |
| `name` | vault name; covered by `settings_tag`. Opening a vault by name refuses a file whose name here is not the one asked for (`vault_mismatch`), so `<name>.sorvault` always holds the vault `<name>` |
| `id` | 32 hex chars, random; bound into every AAD and every integrity tag |
| `created_on` | Unix nanoseconds |
| `recovery_level` | `"recoverable"` or `"purgeable"` (JSON string) |
| `retention_days` | 7–90 |
| `audit_head` | `<id>:<keyed>:<hex HMAC>` — the newest keyed audit row and the number of keyed rows; see *Audit chain* |
| `settings_tag` | hex HMAC-SHA256 over the settings record (below); verified on every open, and checkpointed on the audit chain (see *Checkpoints*) |
| `password` | present when the view check asks for a password: `{"nonce", "ciphertext"}`, the JSON `{"salt", "params", "hash"}` of its salted Argon2id hash sealed with the vault key under the AAD `sourceorrery/v4/password/<id>`. Covered by `settings_tag` |
| `password_hint` | present when the password has a hint: the hint sealed the same way under `sourceorrery/v4/password-hint/<id>`. At most 120 characters, no control characters, and never the password. Covered by `settings_tag` |
| `second_factor` | present once an authenticator is enrolled: `{"nonce", "ciphertext", "enrolled_on", "verified", "last_counter"}`; the TOTP secret sealed under `sourceorrery/v4/second-factor/<id>`, whether a code has been accepted since enrolment, and the last accepted step (a code for it or an earlier step is refused). Covered by `settings_tag` |
| `check_failures` | present after a wrong answer to the view check: `{"count", "last_on"}`, the wrong answers in a row and when the last was given. Covered by `settings_tag` |

### `key_wraps`

The vault key wrapped once for this machine and once under the recovery
key. Every row is listed in the settings record, so the set of wraps is
authenticated and checkpointed with it ([ADR 0010](adr/0010-authenticated-key-wraps-and-private-files.md)):
an old wrap row put back, or one added, removed or edited, is refused at
open.

| column | meaning |
|--------|---------|
| `id` | 16 hex chars, random |
| `kind_json` | `{"kind":"this-machine","service":"sourceorrery","account":"vault/<vault id>/<id>"}` (the key-encryption key is in that credential-store entry) or `{"kind":"recovery","salt":"<hex 16 bytes>"}` (one per vault) |
| `wrapped_nonce` | 24-byte XChaCha20 nonce |
| `wrapped_key` | the vault key encrypted under the wrap's key-encryption key; AAD `sourceorrery/v4/wrap/<vault id>/<wrap id>`, so a wrapped key is bound to this format, this vault and this wrap |
| `created_on` | Unix nanoseconds; the recovery wrap's is when the recovery key was issued |

### `connections`

A vault's connections to providers: where a secret it does not keep in
the file is kept.

| column | meaning |
|--------|---------|
| `id` | 16 hex chars, random |
| `kind` | the provider: `hashicorp-vault`, `aws-secrets-manager` or `azure-key-vault` (one connection per provider) |
| `settings_json` | the provider's settings (address and mount, region and prefix, vault URL), as `ConnectionSettings`; a URL is `https://`, or `http://` to this machine |
| `credential_source` | `ambient` (the provider's own sign-in on the machine) or `stored` |
| `sealed_credentials` | when stored: `{"nonce", "ciphertext"}`, the credentials (a Vault token, an AWS access key, an Azure client secret, each length-prefixed after its kind) sealed under `sourceorrery/v4/connection/<vault id>/<id>` |
| `created_on` | Unix nanoseconds |
| `last_test_on`, `last_test_outcome` | the last connection test: when, and `ok` or the error code; cleared when the settings or credentials change |
| `tag` | HMAC-SHA256 over the row (see *Metadata tags*) |

### `projects`

The project folders whose manifest `init` wrote from this vault.

| column | meaning |
|--------|---------|
| `id` | 16 hex chars, random |
| `path_mac` | HMAC-SHA256 under the metadata key over the folder's path (domain `sourceorrery/v4/project-path`): one record per folder, without the path in clear |
| `sealed` | `{"nonce", "ciphertext"}`: the folder's path and the project's name, length-prefixed, sealed under `sourceorrery/v4/project/<vault id>/<id>` |
| `linked_on` | Unix nanoseconds: when the folder was first recorded |
| `tag` | HMAC-SHA256 over the row (see *Metadata tags*) |

### `secrets`

| column | meaning |
|--------|---------|
| `name` | primary key, the secret naming rules (letters, digits, hyphens; at most 127) |
| `created_on` | first version's time |
| `deleted_on` | NULL while live |
| `scheduled_purge_on` | `deleted_on + retention` |
| `recovery_id` | `sourceorrery://<vault>/deletedsecrets/<name>` |
| `storage` | the id of the connection that keeps the secret's value, or NULL for the vault file. A secret kept at a connection is a catalog entry: it has no versions here, and the vault's own operations refuse it (`unsupported`); its versions and value are the provider's |
| `description` | what the secret is for, one line of at most 200 characters, or NULL |
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
| `operation` | `vault_create`, `vault_open`, `protector_add`, `secret_set`, `secret_get`, `secret_list`, `secret_inspect`, `secret_update`, `secret_delete`, `secret_recover`, `secret_purge`, `audit_verify`, `guard`, `vault_change`, `vault_export`, `vault_import`, `connection_test`, `project_link`, `project_unlink` (a call to a provider is recorded by the vault under the operation it was); `protector_remove`, `vault_migrate`, `vault_backup` and `secret_restore` are names an earlier release wrote |
| `secret_name`, `version` | optional |
| `outcome` | `success`, `denied`, `failure`; `pending` for a change at a connection recorded before it is sent, and `unknown` for one the provider may have made ([ADR 0011](adr/0011-provider-writes-fail-closed.md)) |
| `detail` | error code or short note; **never a value** |
| `prev_hash` | `hash` of the previous row (32 zero bytes for the first) |
| `hash` | `HMAC-SHA256(k, canonical(prev_hash, row))` (see *Audit chain*) |
| `keyed` | 1 when `k` is the metadata key, 0 when it is the all-zero key |
| `state_tag` | checkpoint of the `secrets` row named by `secret_name` after this event: the row's new `tag`, or the empty blob when the row was removed; NULL when the event did not change it (see *Checkpoints*) |
| `version_tag` | checkpoint of the `secret_versions` row named by `secret_name` + `version`, likewise |
| `settings_tag` | checkpoint of the settings record after this event: the 32 bytes of `vault_meta.settings_tag` as the event left it; NULL when the event did not rewrite the record (see *Checkpoints*) |

Index `audit_checkpoints` on `(secret_name, id)` covers the rows where
either row checkpoint column is set, so finding a secret's checkpoints does
not scan its reads. Index `audit_verifications` on `id` covers the
`audit_verify` rows (truncations and acknowledgements), which every unlock
and operation consults. Index `audit_settings` on `id` covers the rows that
carry a settings checkpoint, so the newest is found without a scan.

## Key hierarchy

```
DEK (32 random bytes) ── XChaCha20-Poly1305 ──► each value, the view check's
  │                                              records, stored credentials,
  │                                              project paths and names
  └─ HKDF-SHA256(ikm = DEK, salt = none, info = "sourceorrery/v2/metadata")
         └──► metadata key ── HMAC-SHA256 ──► metadata tags, project path MACs,
                                               audit chain, audit head, settings
  ▲ wrapped by
KEK per wrap:
  this-machine : 32 random bytes in the OS credential store,
                 service "sourceorrery", account "vault/<vault id>/<wrap id>"
  recovery     : HKDF-SHA256(the recovery key's 125 bits, salt,
                 info "sourceorrery/v4/recovery-key/<vault id>") → 32 bytes
```

The metadata key is never stored; it is re-derived from the DEK on every
open. Nothing that can be read from the file allows computing it.

The recovery key is 25 characters in five groups from an alphabet without
look-alikes (125 random bits); case, spaces, hyphens and the look-alike
letters do not matter when it is typed. Being random and long, it needs no
password hashing.

Opening order: every `this-machine` wrap whose credential-store entry is
present is tried first (no interaction); then the recovery-key provider is
asked up to three times. Every failed attempt is an audit row
(`vault_open` / `denied`); giving up writes `vault_open` / `failure`.

The view check is not part of the key hierarchy: the vault opens without
it, and it guards nothing cryptographically. Its password hash is salted
Argon2id with the parameters stored beside it, capped before they are run
(1 GiB, 64 passes, 16 lanes).

## What is encrypted

`secret_versions.ciphertext`, `key_wraps.wrapped_key`, the view check's
`password`, `password_hint` and `second_factor` records, a connection's
`sealed_credentials` and a project's `sealed` path and name. Names, tags,
descriptions, timestamps, flags, connection settings and audit rows are
plaintext. The mutable plaintext is **authenticated**, so it can be read
without the key but not changed without detection, and each `secrets` and
`secret_versions` row, like the settings record, is also **bound to the
audit chain**, so an older authentic copy of it cannot be put back (see
[threat-model.md](threat-model.md)).

## Metadata tags

Every `secrets`, `secret_versions`, `connections` and `projects` row
carries `tag = HMAC-SHA256(metadata key, canonical(row))`. The tag is written with every
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

A listing reads every keyed checkpoint row once per page (authenticated
once, folded per name) and then each window of names in three statements
whatever it holds: the names in `secrets` after the cursor, and the
`secrets` and `secret_versions` rows of those names. A page walks windows
until it has `max_results` items, skipping the names the other listing
owns (deleted names in a live listing and the reverse), so its token is
the name of its last item. The token is present while candidate names
remain; whether any of them is an item is not decided ahead (that would
verify rows beyond the page), so the page after the last item can be empty.
Pages cut the set of *names*; a secret's versions are always judged
together, since which one is newest can only be decided against the
complete set.

Because the newest checkpoint is what matters, every operation first checks
that the chain head still names the newest keyed row; a shortened chain is
not consulted (see *Audit chain*).

### The settings record

The settings record (below) is checkpointed in the same way, in the
`settings_tag` column: every event that rewrites the record carries the
tag the record has afterwards.

| event | why it rewrites the record |
|-------|----------------------------|
| `vault_create` | the first record |
| `guard` | the password, its hint or the authenticator set, changed, verified or removed; every answer to the view check that is weighed, right or wrong (`check_failures` counts the wrong ones, an accepted code advances `last_counter`; a refused answer is `denied` and carries the checkpoint all the same) |
| `vault_change` | a connection added, changed or removed (one event each, also on the setup screens) |
| `protector_add` | the recovery key replaced (setup screens or `replace_recovery_key`), or this machine's key added: the new set of key wraps |
| `connection_test` | the last test kept in the connection's row, failed or not |
| `project_link`, `project_unlink` | a project row added, renamed or removed |
| `vault_export` | in the copy: the view check and this machine's key wrap left out |
| `vault_import` | always: another machine's key wraps removed and this machine's added, and the new name when the copy takes one |
| `audit_verify` / `success` (an acknowledgement) | it does not: it records the record as it stands (see below) |

The vault opens only when `vault_meta.settings_tag` equals the `settings_tag`
of the newest keyed event that carries one, and that event's hash verifies;
otherwise the open is refused with `crypto` and recorded as `vault_open` /
`failure` (`settings integrity check failed: …`). Every change to the record,
every answer to the view check and every read of the connections and
projects judges the record the same way before using it, so a record put
back while a vault is open is never built on. As for rows there is no
accept-if-none case.

While a detected truncation waits to be acknowledged the record is judged by
its tag alone: the missing events may have held its newest checkpoint. A
blocked vault refuses every change then, except what weighing the view check
writes (its answers are still weighed, so that the owner can acknowledge).
The acknowledgement records the record as it stands, so the vault opens
again with the settings the owner accepted along with the surviving history.

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
| secret | `sourceorrery/v2/secret` | vault id, name, created_on, deleted_on?, scheduled_purge_on?, recovery_id?, storage?, description? |
| connection | `sourceorrery/v4/connection` | vault id, id, kind, settings_json, credential_source, sealed_credentials?, created_on, last_test_on?, last_test_outcome? |
| project | `sourceorrery/v4/project` | vault id, id, path_mac, sealed, linked_on |
| project path | `sourceorrery/v4/project-path` | vault id, path (the key is the metadata key; the MAC is the row's `path_mac`) |
| audit row | `sourceorrery/v4/audit` | vault id, prev_hash, id, occurred_on, actor, operation, secret_name?, version?, outcome, detail?, keyed, state_tag?, version_tag?, settings_tag? |
| audit head | `sourceorrery/v2/audit-head` | vault id, id, hash |
| settings | `sourceorrery/v2/settings` | vault id, schema_version, name, created_on, recovery_level, retention_days, then each of `"password"`, `"password_hint"`, `"second_factor"` and `"check_failures"` followed by its stored JSON when present, then `"connections"`, their count and each connection's id and tag in id order when there are any, then `"projects"` the same way, then always `"key_wraps"`, their count and each wrap's id and key-wrap encoding in id order |
| key wrap | `sourceorrery/v5/key-wrap` | vault id, id, kind_json, wrapped_nonce, wrapped_key, created_on (the whole row; listed inside the settings record, not tagged on its own) |

`?` marks an optional field (`state_tag?`, `version_tag?` and
`settings_tag?` are optional byte strings); timestamps are their stored
Unix-nanosecond integers.

The connections and projects are listed in the settings record by id and
tag, and the key wraps by id and their whole content, so a row added,
removed, or replaced by an older authentic copy of itself breaks the
settings tag and the vault refuses to open. An older authentic copy of the
*whole* record (its `vault_meta` keys and its connections, projects and key
wraps together) verifies by its tag, but it is not the record the chain
checkpointed last, so it is refused as well (see *The settings record*).
This is what makes a replaced recovery key stop working in the file; it
does not change the vault key, which an old key's holder can still use on
an old copy (ADR 0010). Only an older copy of the whole file, log included, goes
undetected ([threat model](threat-model.md), *Snapshot rollback*).

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
"<id>:<keyed>:<hex HMAC-SHA256(metadata key, canonical(audit-head, vault id, id, hash, "keyed", keyed))>"`,
where `keyed` is the number of rows flagged `keyed = 1`, rewritten on every
keyed append. Removing a row from the **middle** leaves the head naming
the newest row, so two more checks exist: every unlock walks the chain
from the newest acknowledgement to the end and refuses on the first row
that does not follow its predecessor or whose hash does not verify, and
the keyed count under the head's MAC lets every operation notice a keyed
row removed or demoted since the head was written without walking the
log. Before every keyed append the vault checks that the head still names
the newest keyed row and counts what the log holds; if it does not — rows
were removed after it, a keyed row is missing, or the head record is
missing or invalid — it first appends an `audit_verify` / `failure` row
saying so (for example
`rows removed after event 41 (head was event 44)`), and only then the
requested row. The evidence is itself part of the chain; removing it is
another truncation and is detected the same way at the next keyed write.

Since schema 3 the chain is also the record of current row state, so a
shortened chain must not be consulted. Every unlock and every operation
therefore checks the head *first*: when it is stale, the unlock or
operation is **refused** with `crypto` ("audit log integrity: rows removed
after event 41 …"), and that refusal is what writes the `audit_verify` /
`failure` row and re-anchors the head.

### Acknowledging a truncation

A recorded truncation then **blocks the vault**. A keyed `audit_verify` /
`failure` row whose hash verifies, with no later keyed, verifying
`audit_verify` / `success` row whose detail begins `truncation
acknowledged`, is an *unacknowledged* truncation; while one exists every
unlock and every operation is refused with `crypto`, naming the event
("the truncation detected at event 42 (rows removed after event 41 (head
was event 44)) is unacknowledged …"), and each refusal is itself recorded
(`vault_open` / `failure` with detail `truncation unacknowledged`, or the
operation's own `failure` row). Rows flagged keyed that do not verify count
for neither side; `audit --verify` reports them as broken.

Only an unlock *for inspection* (`SqliteVault::open_with` with
`allow_quarantined`, `VaultRegistry::open_for_inspection`; the CLI's
`sourceorrery audit` command) gets a handle to such a vault. It writes
`vault_open` / `success` with detail `inspection (truncation
unacknowledged)`, skips the retention purge an open normally performs,
and the handle still refuses every secret operation; it can read the log,
verify the chain and acknowledge. A chain head found stale at an inspection unlock is recorded
rather than refused, so a truncation can be reviewed and acknowledged in
one session. On a vault with nothing to acknowledge an inspection unlock
is an ordinary unlock.

`SqliteVault::acknowledge_truncations(event_ids)` (`sourceorrery audit
--acknowledge`) appends one keyed `audit_verify` / `success` row with
detail `truncation acknowledged (events 42, 57)`: the owner's record that
the surviving history was reviewed and is accepted as authoritative. It
runs in one write transaction, re-checks the head (a stale head is
recorded and refused, so nothing is acknowledged unseen) and requires
`event_ids` to be exactly the unacknowledged events at that moment, so a
truncation another process detected in between is refused with
`invalid_argument` rather than swept in. The acknowledgement covers every
truncation before it; the truncation rows stay on the chain and keep
counting in `truncations`. Removing the acknowledgement is another
truncation and un-acknowledges what it covered.

`SqliteVault::verify_audit_chain()` (`sourceorrery audit --verify`) walks
the whole log and reports: rows, keyed and unkeyed counts, `first_broken`
(the first row whose link or hash fails), `truncations` (keyed
`audit_verify` / `failure` rows), `unacknowledged` (those after the newest
acknowledgement) and `head_valid`. The log is intact when `first_broken`
is null, `truncations` is 0 and `head_valid` is true; an acknowledged
truncation is still a truncation. The check is read-only.

## Compatibility

`schema_version` is checked on open. A **newer** schema is refused with a
clear error. An **older** one (schemas 1–4: earlier releases, and development
builds before the key wraps were authenticated) is refused with
`migration_required`, without the file being changed: those files are not
read, nothing is written to them or beside them, and `vault export`,
`vault destroy` and `vault create` refuse them too. The file is kept for
the release that wrote it, and the vault is recreated and its secrets set
again from it: [Upgrading](upgrading.md) is the tested procedure. The
wrapping AAD names the format, so a file whose marker was edited to
another number cannot be opened as that format either.

## Creating a vault

The vault file is created exclusively (`O_EXCL` / `CREATE_NEW`) before
anything is written to it, so of several processes creating the same name
at once exactly one owns the file; the others fail with `vault_exists` and
never touch it. Only the owner removes the file again if the rest of
creation (for example keeping this machine's key in the credential store,
or the settings the setup screens chose) fails.

## Exporting and importing

`vault export` writes a consistent copy of the file with SQLite's online
backup and then removes from the copy what belongs to this machine and
this vault's owner: every `this-machine` wrap and the view check's
records. The copy opens only with the recovery key, and its own log
records the export. `vault import` opens such a copy with its recovery
key, verifies its name, settings and chain, adds a `this-machine` wrap
for the new machine and registers it; it comes with no view check.

## Deleting a vault

`sourceorrery vault destroy <name>` reads the `key_wraps` table (no
opening needed) and removes the file. A credential-store entry listed there
is deleted only when its account is exactly `vault/<this vault id>/<wrap
id>` and no other vault file in the same home references it; otherwise it
is kept and reported, because wrap metadata is unauthenticated until the
vault is open and must not be allowed to point deletion at another vault's
key.
`--keep-os-key` skips credential-store deletion altogether.
