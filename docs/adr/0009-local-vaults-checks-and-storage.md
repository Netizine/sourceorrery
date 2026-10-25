# ADR 0009: Local vaults, an optional view check, and storage per secret

**Status:** accepted · **Date:** 2026-10-24 · **Changes:** ADR 0002 (protectors
as the setup model), ADR 0008 (remote vaults declared in the manifest), and,
once, ADR 0007's deprecation and migration rules

> **0.3.0 implementation:** The original proposal below used schema 4; ADR 0010 advances the implemented format to schema 5 with authenticated key wraps. Earlier files are refused and left unchanged, not deleted. The [current format reference](../vault-format.md) defines the implemented tables and fields.

## Context

A walkthrough of `sourceorrery setup` on 2026-10-24 found that the vault's
user-facing model is the wrong shape. [ui_flow_changes.md](../../ui_flow_changes.md)
records the flow screen by screen and the thirteen problems found. In short:

* **Setup does more than set up a vault.** It also creates a secret and
  writes a manifest into whatever folder it runs in.
* **Two access policies.** Opening a vault and showing a value (the reveal
  guard) follow different rules, and the wizard can set a guard that asks
  for a passphrase the vault does not have.
* **Providers are invisible to the vault.** A remote provider is chosen by
  a `[vaults.<name>]` table in the project's manifest, so a vault name is
  either all local or all remote, and setup never mentions providers.
* **`init` ignores the vault.** It writes a template entry instead of the
  vault's secrets.

The model separates vault setup, interactive viewing and application access:

* **A vault is set up, not secrets.** It has an auto-generated key, which
  the machine holds.
* **An optional view check.** A password, optionally with an
  authenticator code on top, decides whether a person may view the vault
  and reveal a value, and nothing else. It is chosen when the vault is
  created.
* **Commands that don't view just run.** `run`, `init`, `check` and the
  SDKs never ask.
* **Storage chosen per secret.** The vault may keep secrets itself or in
  HashiCorp Vault, AWS Secrets Manager or Azure Key Vault, with the
  connections set up in the same flow.
* **Projects come from the vault.** They are built from secrets picked out
  of it (all of them, or some), with any new ones the project needs added
  to the vault on the way.
* **Exports leave the check behind.** The recovery key opens an export,
  and the check is set again after import.
* **No backwards compatibility.** Earlier formats are refused and left unchanged; no automatic deletion or conversion occurs.

The implementation retains these constraints:

* values only in `SecretBytes`;
* a value-free `ui`;
* read-only SDKs;
* append-only error codes;
* new semantics in core, with a conformance test.

## Decision

### 1. A vault is a local file and the catalog of its secrets

Every vault is one SQLite file in the home directory. It lists every secret
it holds, whether the value is in the file or at a provider. A vault name is
letters, digits, `-` and `_`, 1–64 characters, unique ignoring case (Windows
and macOS file names are case-insensitive). Names are not renamed in this
change.

### 2. The vault key

The vault key is 256 random bits from the OS generator, created with the
vault and never shown. As today, values are sealed under it and the metadata
key is derived from it. It is wrapped twice:

| Wrap | KEK | When it exists | Opens the vault |
|------|-----|----------------|-----------------|
| **This machine** | 32 random bytes in the OS credential store (Credential Manager, Keychain, Secret Service) | Created with the vault and at import, wherever a store is available | On the machine and user account it was made for, without asking |
| **Recovery key** | HKDF-SHA256(recovery key, random salt, vault id) | Always; exactly one | Anywhere: another machine, an exported copy, a machine with no credential store |

* **The recovery key** uses the existing recovery-code format (125 bits,
  25 characters; case and hyphens ignored). It is shown once and replaced
  only on request; the old one then stops working.
* **Why HKDF.** The key is 125 random bits, so a slow hash adds nothing
  against guessing; HKDF keeps opening with it instant for CI and
  containers. Argon2id stays where a person chooses the secret: the
  password.
* **Switching the store off.** `SOURCEORRERY_KEYRING=off` treats the
  credential store as absent. Tests always set it, since they must never
  touch the real store; a container or a shared machine can use it too.
* **No credential store.** On a machine without one (WSL, containers, CI,
  servers without Secret Service), the vault opens with the recovery key.
  It comes from `SOURCEORRERY_RECOVERY_KEY`, `--recovery-key-file` /
  `SOURCEORRERY_RECOVERY_KEY_FILE`, or the prompt. These replace
  `SOURCEORRERY_PASSPHRASE*` as what CI and containers supply.
* **At rest:** a copied file opens only with the recovery key. The
  credential-store entry stays on its machine, protected by the platform
  (DPAPI, Keychain, the login keyring) as today.

### 3. The view check

Optional, chosen when the vault is created, changeable later by someone who
passes it or holds the recovery key:

| Part | Verified by | Stored |
|------|-------------|--------|
| **Password** | Argon2id(password, salt) compared in constant time with the stored hash | The salted hash, sealed under the vault key; the password itself never |
| **Hint** (optional, with a password) | — | Sealed under the vault key; shown at the password prompt; a hint that matches the password is refused |
| **Authenticator code** (optional, only with a password) | RFC 6238 against the seed, ±1 time step, each step accepted once | The seed and the last accepted step, sealed under the vault key, as today |

**What asks for it.** Viewing the vault, and nothing else:

* `ui`: when it opens, and again after its idle lock.
* `secret list`, `secret get` (with or without `--reveal`) and
  `secret versions`.
* `audit`.
* `vault create` on an existing vault: its settings are on view there, and
  without the check anyone could switch the check off.

**What never asks.** `run`, `check`, `init`, `import`,
`secret set|update|delete|recover|purge|rotate`, `vault export`,
`vault import`, `vault list`, `vault destroy` and every SDK open just run.

**Answers** come from `SOURCEORRERY_PASSWORD` / `--password-file` and
`--code` / `SOURCEORRERY_TOTP` for scripts, else the terminal prompt. `run`
and the rotation hooks remove these, and the recovery-key variables, from
the child's environment. The recovery key also passes the check, since it is
the way back in; the audit row says it was used.

**Failures.** A wrong or missing answer is `permission_denied`, as the
reveal guard's is today. It is audited with a detail naming the check, never
the answer. After five consecutive wrong answers each further attempt waits
30 seconds, doubling to 15 minutes. The counter is in the authenticated
settings and is reset by a right answer; the recovery key always works.

**The limit.** The check stops a person using SourceOrrery to look: a
technician or a colleague at an unlocked machine opening the vault browser,
listing secrets or revealing a value. It is not encryption, and it does not
protect the values:

* `run` delivers values without asking, by design, so whoever can run
  commands as the owner can write a manifest naming the secrets and run a
  program that prints its environment.
* A program can read the credential store and the file directly.

The vault key protects values at rest. A separate view check keeps
interactive viewing distinct from unattended application access (see
Alternatives).

### 4. Storage and connections

**Storage.** A vault's storage is the SourceOrrery vault (always) plus any
of HashiCorp Vault, AWS Secrets Manager and Azure Key Vault, each through a
**connection** stored in the vault.

**Connections.**

* **Settings:** the non-secret settings the manifest's `[vaults.*]` tables
  hold today (address, mount, namespace; region, prefix, endpoint URL;
  vault URL), authenticated like other metadata.
* **Credentials:** a source, either **ambient** or **stored**.
  * *Ambient* is the provider's own chain, as today: environment, CLI
    login, workload or managed identity.
  * *Stored* means credentials sealed under the vault key: a Vault token,
    an AWS access key pair, an Azure client secret. They are never shown
    again and never cross `MetadataSource`.
* **One per kind:** one connection per provider kind to start; rows are
  keyed by id so several can follow.
* **Tests:** the wizard's test makes one metadata call. Its outcome and
  time are kept and shown, audited as `connection_test`.

The rules that guard where credentials go are unchanged: `https://`, or
`http://` to loopback only; no redirects for the Vault client.

### 5. Secrets and routing

**A secret** has a name (the existing rule), a value, a storage, and an
optional description, tags and time window.

**Values.**

* *In the SourceOrrery vault:* the value and every version are in the file,
  as today.
* *At a provider:* the file holds a catalog row (name, storage,
  description, created). Versions, the enabled flag, the time window and
  deletion state are the provider's, mapped as ADR 0008 and
  `docs/providers/` describe. The value reaches the provider in clear to
  it, so other consumers and the provider's own rotation keep working.

**`Routed`** is a `SecretClient` over the local vault that sends each call
to the secret's storage. It lives in `sourceorrery-provider`, which holds
dispatch only, like the adapters there.

* **The contract does not change:** choosing the storage of a *new*
  secret is `Routed`'s own method, and every existing operation is routed
  by the catalog.
* **The catalog row** is written in the same operation as the provider
  call. A failure on either side is reported, never half-applied silently.
* **Missing secrets:** a secret deleted at the provider out of band is
  reported as missing there, not hidden.
* **Connections in use:** a connection that a secret still uses cannot be
  removed (`invalid_argument`). An unreachable provider is
  `provider_unavailable` and refused credentials are `unauthenticated`, as
  today.
* **Capabilities** are per storage.
* **The local audit log** records every read and change of a
  provider-stored secret too, with the storage in its detail. This is new:
  today a remote vault has no local log, and the provider's log (CloudTrail,
  Vault audit devices, Azure diagnostics) remains the authority for what
  the provider served.

### 6. Projects and the manifest

* **The manifest** keeps `[project]` (`name`, `vault`), `[secrets.<name>]`
  (`required`, `purpose`, `env`, `version`) and `[rotation.<name>]`. The
  `[vaults.<name>]` tables and the per-secret `vault` key go. The manifest
  can no longer say where a credential is sent.
* **`init [VAULT]`** needs an existing vault and no check. It has its own
  screens, built like the setup wizard (`ui/init/`):
  1. Which vault, when there are several.
  2. The vault's secrets by name, storage and description (never a
     value), with an **All** toggle.
  3. A loop asking whether to add a new secret: a name under the secret
     name rules and not already in the vault, a hidden value typed twice,
     a storage when the vault has more than one, and an optional
     description. Each is stored in the vault as soon as it is confirmed,
     so its value leaves memory at once.
  4. A review that writes the manifest (`purpose` comes from the
     description) and records the folder.

  Leaving before the review writes no manifest; secrets already stored
  stay in the vault. Without a terminal, `--all` or `--secret NAME …`
  pick secrets and nothing new is added, since a value is never a
  command-line argument.

  **With an existing manifest,** `init` is how a project adds secrets. It
  loads the vault the manifest names, skips the vault and project
  screens, and opens the list with the manifest's secrets ticked.
  * A manifest entry the vault lacks is marked, and can be given a value
    through the same form.
  * New secrets come from the vault's list or the add-new loop.
  * The file is edited in place (`toml_edit`), so comments, `env`
    overrides, `version` pins and `[rotation.*]` tables survive.
* **The vault records each project** as a path and a project name, sealed
  under the vault key (a folder name can say more than a secret name),
  with a keyed MAC of the path for uniqueness. The manifest at that path
  is the source of its secret list, so a hand edit never drifts from the
  vault.
* **The `ui` Projects view** checks each path on disk when it opens: ✓
  when `sourceorrery.toml` is there, ✗ when not. A ✗ link can be removed
  (`project_unlink`).

### 7. Commands

* **The vault wizard:** `setup` and `vault create [NAME]` are one wizard.
  A NAME that exists opens that vault for changes after the view check:
  the check, the recovery key, storage, connections.
  * It writes nothing until its review screen confirms, then commits in
    one transaction.
  * The authenticator seed is generated and verified in memory first.
  * Non-interactive creation (CI, the SDK fixture vault) uses
    `vault create NAME --recovery-key-out FILE [--password-file FILE]
    [--storage …]`, with one flag set per provider. The authenticator is
    set up only in the wizard.
* **Moving vaults:** `vault export` and `vault import` replace `backup` and
  `restore` (section 8).
* **Kept:** `vault list`, `vault destroy`, `secret …` (for scripts, CI and
  agents; `set` gains `--storage`), `import` (`--storage`), `check`,
  `run`, `audit`, `ui`, `init`, `completions`.
* **Removed:**
  * the `vault protector`, `vault passphrase`, `vault 2fa`, `vault guard`,
    `vault recovery`, `vault info` and `vault migrate` subcommands;
  * `backup` and `restore`;
  * the word "passphrase": "password" is the check, and "recovery key" is
    what opens a vault away from its machine.

### 8. Export and import

**`vault export`** (no check: an export opens only with the recovery key)
writes a consistent copy of the file with SQLite's online backup.

* **Left out:** this machine's wrap, the password hash, the hint and the
  authenticator. The copy's own log records `vault_export` and what was
  left out.
* **Kept:** the settings, the connections (credentials still sealed), the
  catalog, the local values, the projects and the audit log.

**`vault import`**, in this order:

1. Opens the copy with the recovery key.
2. Verifies the copy's name, settings and audit chain.
3. Adds this machine's wrap.
4. Copies the file into the home directory under its name, or `--name`.
   An existing name, ignoring case, is refused, so an import never
   replaces a vault.
5. Records `vault_import`.
6. Offers to set a view check: on a terminal through the wizard's check
   screen, otherwise with `--password-file`.

## Schema 4 (outline)

> **Superseded in part by [ADR 0010](0010-authenticated-key-wraps-and-private-files.md):**
> the key wraps join the authenticated settings record and the format
> becomes schema 5; replacing the recovery key makes the file refuse the
> old key but does not change the vault key.

`docs/vault-format.md` is rewritten with the code. New records use
`sourceorrery/v4/…` domains and AADs; record encodings that do not change
keep theirs. Schema 4 is not released until the whole change is, so the
tables for storage, connections and projects arrive with the code that
uses them, with no migration in between. Changes from schema 3:

| Where | Change |
|-------|--------|
| `vault_meta` | `schema_version` `4`. New keys: `view_check` (`{"password": bool, "authenticator": bool}`), `password` (the sealed salted hash and its Argon2 parameters), `password_hint` (sealed), `check_failures` (`{"count", "since"}`), `recovery_issued_on`. `second_factor` stays (sealed seed, `verified`, `last_counter`). `reveal_guard` and the clear-text `passphrase_hint` go. `settings_tag` covers every key above. |
| `key_protectors` → `key_wraps` | `id`, `kind` (`this-machine`, `recovery`), `kind_json` (store service and account, or the HKDF salt), `wrapped_nonce`, `wrapped_key` under the AAD `sourceorrery/v4/wrap/<vault id>/<wrap id>`, `created_on`. Exactly one `recovery` row. |
| `connections` (new) | `id`, `kind`, `settings_json`, `credential_source` (`ambient` / `stored`), `sealed_credentials` (nullable; AAD `sourceorrery/v4/connection/<vault id>/<id>`), `last_test_on`, `last_test_outcome`, `tag`. |
| `secrets` | New `storage` (a connection id, or NULL for the SourceOrrery vault) and `description`, both in the row's tag and checkpoints. |
| `secret_versions` | Unchanged; rows exist only for secrets stored in the file. |
| `projects` (new) | `id`, `path_mac` (unique; HMAC of the path under the metadata key), `sealed` (path and name; AAD `sourceorrery/v4/project/<vault id>/<id>`), `linked_on`, `tag`. |
| `audit_events` | New operations, appended: `vault_change`, `connection_test`, `project_link`, `project_unlink`, `vault_export`, `vault_import`. New `settings_tag`: the settings record's tag after each event that rewrites it, part of the chain hash (domain `sourceorrery/v4/audit`). |

## Threat model changes

`docs/threat-model.md` changes with the code. What changes:

* **Offline disk reader.** A copied file opens only with the recovery key.
  The password hash, the hint and the authenticator seed are sealed, so
  the copy says nothing about them.
* **A person at an unlocked machine using SourceOrrery** (a technician, a
  colleague, an agent at the CLI). Stopped by the view check from the
  browser, listings, `--reveal` and the audit log. Not stopped from
  `run` and the other commands that never ask: that is section 3's limit,
  stated in the guarantees table.
* **Same-user process.** Still not defended, as guarantee 3 says. The
  check is for people using SourceOrrery's views, not against code.
* **The manifest.** It no longer names a provider or an endpoint, so a
  planted manifest cannot send credentials anywhere. Discovery bounds
  still matter: the manifest chooses the vault name and the variables
  `run` delivers.
* **Stored credentials.** They are as safe as the vault key: sealed,
  never shown, exported with the vault. Ambient credentials stay the
  default for workloads.
* **Provider-stored secrets.** Policy stays the provider's metadata (gap
  14). The local catalog and log add a record of access, not a control:
  the provider decides what it serves.
* **The recovery key.** It opens every copy and passes the check, so it
  is as sensitive as the vault. CI holds it as a repository secret. It is
  shown once, audited when used, and replaceable.
* **Rows that change:** the reveal-guard control becomes the view check.
  Gap 12 shrinks (the hint is sealed now). Gap 7 (migration) goes.
  Gap 6 (snapshot rollback) applies to an imported copy as to any copy.
* **Found in the implementation, and closed:** the settings record (the
  `vault_meta` keys and the connections and projects it lists) was
  authenticated but not checkpointed on the audit chain, so an older
  authentic copy of the whole record verified, and someone who could write
  the file could switch the view check back off that way. Now every event
  that rewrites the record carries its new tag (`audit_events.settings_tag`),
  and the vault opens, and changes the record, only when its tag is the
  newest the chain records; anything else is refused with `crypto`, as a
  replayed row is. The acknowledgement of a truncation records the record
  as it stands, since the missing events may have held its newest
  checkpoint. What remains is gap 6 itself: a rollback of the whole file,
  and a replay hidden by a truncation its owner acknowledges.

## Measurements

Taken on the implementation (this repository at the commit that completes
it, a 4-core Intel i7-8650U laptop on Windows 11, Rust 1.99.1, a
`--release` CLI with its default features, vaults made with
`SOURCEORRERY_KEYRING=off`, medians of seven to nine runs):

| What | Cost |
|------|------|
| Crates added to the dependency graph | none: `toml_edit`, which `init` edits a manifest with, was already in it through `toml`; `qrcode` moved behind the `ui` feature |
| The release CLI (`ui`, `remote`, `os-keyring`, `otlp`) | 20.9 MB |
| `vault create` without and with a view-check password | 218 ms against 384 ms: one Argon2id hash at 64 MiB and 3 passes, about 170 ms, is the price of a password check each time it is asked |
| `secret list` on a vault with 20 secrets, opened with its recovery key | 52 ms without a view check, 67 ms with one (a recovery key passes the check, so no hash is computed) |
| `check` over a manifest of those 20 secrets | 335 ms; it never asks the view check, so a password costs `run` and `check` nothing |
| The vault file with 20 secrets, a password and its recovery key | 120 KiB |

## Alternatives considered

* **A password that also locks the vault key** (the key needs the
  credential store and the password).
  * It would stop a same-user attacker without the password.
  * But `run`, `init` and the SDKs would need the password on every
    machine.
  * This design uses a view check. A password-bound vault key could be
    considered separately as a future per-vault option.
* **A 6-digit PIN.** Rejected. As key material it could be
  guessed in hours; as a check it adds nothing a password does not.
* **An authenticator code on its own.** It is "password plus": a second
  part of the password check, never the only one.
* **Keep the reveal guard beside an unlock policy.** Rejected: two policies
  are what produced the "passphrase the vault does not have" defect.
* **Several passphrase protectors (today's model).** Rejected: this
  machine's wrap and one recovery key cover desktops, WSL, containers and
  CI.
* **A key file where there is no credential store.** Rejected: at rest it
  would be as readable as the vault file beside it. The recovery key from
  the environment keeps a copied file closed.
* **A separate export passphrase.** Rejected: the recovery key already is
  the portable way in.
* **Mirroring provider metadata in the local file.** Rejected: two sources
  of truth for the enabled flag and the time window. The provider's is the
  one other consumers see.
* **Sealing values under the vault key before they reach a provider.**
  Rejected for now: other consumers and the provider's rotation could not
  read them. It could return as a per-connection option.
* **Provider configuration kept in the manifest.** Rejected: storage is a
  property of the secret, and a repository file should not decide where
  credentials go.

## Consequences

* **ADR 0007, once.** This is a breaking change on every surface: CLI,
  Rust API, C ABI (the options struct's passphrase fields become
  recovery-key fields, so `SO_ABI_VERSION` is bumped and the `abi-compat`
  job skips), contract (unlock sources and hints change, so
  `CONTRACT_VERSION` becomes `"2"`), SDK APIs, vault file and manifest.
  ADR 0007's "deprecation before removal" and "a new schema only after an
  explicit migration" were superseded by the current pre-1.0 version
  policy in ADR 0007.
  * Schemas 1–3 are refused with a message that the vault must be
    recreated.
  * `vault migrate` and its code go.
  * The release is the next minor (0.x) release.
* **ADR 0002's design stays:** one SQLite file with values sealed
  individually under a vault key wrapped by an OS-store key or an Argon2id
  key. The interactive policy becomes a view check;
  key wraps open the vault independently.
* **ADR 0008's adapters and providers stay.** What changes is that a
  provider is reached through a connection in the vault, never through a
  manifest table, and the provider crates take their credentials from that
  connection.
* **Errors and audit:**
  * No new error codes. A failed view check is `permission_denied`; a
    vault with no way to open it here is `locked`.
  * `backup_passphrase` and `backup_format` are no longer produced; they
    stay reserved, since the list is append-only. `migration_required`
    now means the vault must be recreated.
  * Six new audit operations, appended. `vault_backup` stays reserved
    likewise.
* **SDKs:** `OpenOptions` replaces `passphrase` / `passphrase_file` with
  `recovery_key` / `recovery_key_file`. An SDK never asks the view check,
  and bindings carry no logic beyond passing the options and mapping codes.
* **No unlock session is needed**, since nothing that runs a program asks
  for anything.
* **A security review** of the new storage follows the implementation, as
  for schemas 2 and 3 (`docs/security-review.md`).
