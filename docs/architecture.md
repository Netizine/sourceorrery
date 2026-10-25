# SourceOrrery architecture

*Architecture and technical research — October 2026*

An open-source, Rust-native secrets platform for AI-assisted software
development. The most secure `.env` file in the age of AI coding agents is the
one that doesn't exist.

SourceOrrery addresses an increasingly important engineering problem: we give
AI coding agents access to repositories, development environments, terminals
and build pipelines while continuing to distribute credentials through
plaintext configuration files.

The opportunity is not simply to replace `.env` files with encrypted storage.
It is to create language-independent secrets infrastructure that separates
secret storage, access permissions and runtime retrieval from application
source code.

## 1. Design

* **Rust-native core.** One implementation of storage, cryptography,
  identity, policy and secret lifecycle management.
* **Cross-platform CLI.** A polished terminal interface on macOS, Windows and
  Linux.
* **Cloud-secrets-manager-style API.** Familiar `SecretClient`, `set_secret`,
  `get_secret`, versioning and lifecycle operations, independent of any one
  vendor.
* **Multi-language SDKs.** Read-only clients for Python,
  JavaScript/TypeScript, Rust, Java, .NET, Go, C, C++ and PHP over one Rust
  implementation (shipped); a standard local protocol with the broker
  (milestone 3).
* **Enterprise capabilities.** Identity-aware authorisation, least privilege,
  rotation, auditability, recoverability and integration with external vaults.
* **Local-first.** No mandatory cloud account, SaaS subscription or remote
  server to get started.

> [!NOTE]
> Retrieval goes through an encrypted local vault, which keeps each secret
> in its own file or at a provider it connects to (HashiCorp Vault, AWS
> Secrets Manager, Azure Key Vault). A provider's secrets use its identity
> and policy controls; the vault file's use the key that opens it. The authenticated local broker and same-user agent isolation
> remain planned work, not guarantees of the local SDKs.

One important qualification: removing `.env` files eliminates a major
accidental-exposure route, but it does not protect against an AI agent or
malicious process operating with the same permissions as the application.
SourceOrrery addresses that boundary explicitly (see [threat-model.md](threat-model.md))
rather than promising that local secrets are inaccessible to agents.

## 2. Workspace

```
sourceorrery/
├── crates/
│   ├── sourceorrery-core       contracts: SecretClient, properties, errors,
│   │                           policy, identity, audit, manifest
│   ├── sourceorrery-crypto     XChaCha20-Poly1305, Argon2id, envelope wrapping
│   ├── sourceorrery-storage    encrypted SQLite vault, its key wraps
│   │                           (this machine, the recovery key), the view
│   │                           check, connections, catalog, projects,
│   │                           export and import, vault registry
│   ├── sourceorrery-cli        the `sourceorrery` binary
│   ├── sourceorrery            the read-only client: the CLI's opening
│   │                           order, manifest loading, error hints (the
│   │                           Rust SDK)
│   ├── sourceorrery-ffi        stable C ABI (cbindgen header): read-only
│   │                           so_reader_* for SDKs, so_vault_* for tooling
│   ├── sourceorrery-provider   Blocking / AsyncLocal adapters between the
│   │                           sync and async shapes of the contract;
│   │                           open_connection picks a provider for a
│   │                           vault's connection; Routed, the vault over
│   │                           every storage
│   ├── sourceorrery-provider-vault  HashiCorp Vault KV v2 behind the contract
│   ├── sourceorrery-provider-aws    AWS Secrets Manager behind the contract
│   └── sourceorrery-provider-azure  Azure Key Vault behind the contract
├── bindings/                   the other nine SDKs (see §7)
├── tests/conformance           lifecycle + security suite for every backend/SDK
├── scripts/ci, scripts/release fixture vault for SDK tests; version stamping
├── docs/                       this folder
└── .github/workflows           CI on Ubuntu/Windows/macOS, manual release
```

The critical principle: **applications consume secrets through a defined
API; they do not know where those secrets are stored.** All semantics live in
`sourceorrery-core`. Backends and bindings implement the contract and pass the
conformance suite; none carries business logic of its own.

### Dependency direction

```
cli ──► storage ──► crypto
 │         │
 └────► core ◄──────┘ (crypto has no core dependency; storage maps its errors)

cli ──► provider (Routed, the connections)
sourceorrery (client) ──► provider, storage, core
sourceorrery-ffi ──────► sourceorrery (client), storage, core
sourceorrery-provider ─► core, tokio; provider-vault, provider-aws, provider-azure (features)
sourceorrery-provider-vault ─► core, reqwest (rustls)
sourceorrery-provider-aws ───► core, aws-sdk-secretsmanager, aws-config
sourceorrery-provider-azure ─► core, azure_security_keyvault_secrets, azure_identity
tests/conformance ─────► storage, core; provider in its tests
bindings/python, bindings/node ──► sourceorrery (client)      native extensions
bindings/{java,dotnet,go,cpp,php} ──► sourceorrery-ffi (C ABI) foreign-function calls
```

## 3. Domain model (`sourceorrery-core`)

| Type | Role |
|------|------|
| `SecretBytes` | The only carrier of a plaintext value. Zeroised on drop, `Debug` redacted, **no `Serialize`**. |
| `SecretProperties` | Metadata of one version: name, version id, enabled, content type, tags, `not_before`, `expires_on`, timestamps, recovery level. |
| `Secret` | `SecretProperties` + `SecretBytes`. |
| `SetSecretOptions` / `UpdateSecretProperties` | Inputs. Updates use `Option<Option<T>>` to distinguish *unchanged* / *clear* / *set*. |
| `DeletedSecret` | A soft-deleted secret with `deleted_on`, `scheduled_purge_on`, `recovery_id`. |
| `SecretReference` | `sourceorrery://vault/name[/version]` — contains no secret material. |
| `SecretError` | Typed errors with stable, append-only string codes for SDKs. |
| `Principal` | Who is asking (`user`, `workload`, `agent`, `system`). Today it labels the OS user; it is not verified identity. |
| `AuditEvent` | Metadata-only record: actor, operation, secret, version, outcome, detail (error code). |
| `Manifest` | `sourceorrery.toml`: project name, the vault, the secrets it uses (and how each is delivered), rotation hooks. Rejects unknown fields, so it cannot hold a value, a credential or where a secret is kept. |
| `ConnectionSettings` / `Credentials` | How a vault reaches a provider (`core::connection`): the provider and its addressing keys, and optionally its credentials as `SecretBytes`. The vault stores both; a credential is sealed and never serialised. |

### The `SecretClient` contract

```rust
pub trait SecretClient {
    fn vault_name(&self) -> &str;
    fn set_secret(&self, name: &str, value: SecretBytes, options: SetSecretOptions) -> Result<SecretProperties>;
    fn get_secret(&self, name: &str, version: Option<&str>) -> Result<Secret>;
    fn get_secret_properties(&self, name: &str, version: Option<&str>) -> Result<SecretProperties>;
    fn list_properties_of_secrets(&self) -> Result<Vec<SecretProperties>>;
    fn list_properties_of_secrets_page(&self, options: ListOptions) -> Result<Page<SecretProperties>>; // provided
    fn list_properties_of_secret_versions(&self, name: &str) -> Result<Vec<SecretProperties>>;
    fn update_secret_properties(&self, name: &str, version: Option<&str>, update: UpdateSecretProperties) -> Result<SecretProperties>;
    fn delete_secret(&self, name: &str) -> Result<DeletedSecret>;
    fn get_deleted_secret(&self, name: &str) -> Result<DeletedSecret>;
    fn list_deleted_secrets(&self) -> Result<Vec<DeletedSecret>>;
    fn list_deleted_secrets_page(&self, options: ListOptions) -> Result<Page<DeletedSecret>>; // provided
    fn recover_deleted_secret(&self, name: &str) -> Result<SecretProperties>;
    fn purge_deleted_secret(&self, name: &str) -> Result<()>;
    fn audit_events(&self, query: AuditQuery) -> Result<Vec<AuditEvent>>;
    fn resolve(&self, reference: &SecretReference) -> Result<Secret>; // provided
}
```

The contract has a second shape, `AsyncSecretClient`: the same methods as
`async fn`, the same semantics, for backends that wait on the network (the
remote providers of milestone 4, [ADR 0008](adr/0008-remote-providers.md)).
It is object safe (`Box<dyn AsyncSecretClient>`, through `async-trait`) so a
provider can be chosen at run time. `sourceorrery-provider` turns either
shape into the other: `Blocking<A>` drives an async client on a Tokio
runtime it owns or borrows, so the CLI, the C ABI and every SDK run
unchanged against a remote provider; `AsyncLocal<C>` runs a synchronous
client on Tokio's blocking pool, so async applications reach the local
vault. Both pass every operation and every error through untouched.

Semantics every implementation must honour:

| Operation | Semantics |
|-----------|-----------|
| `set_secret` | Creates a new **immutable** version; never mutates an old one. Fails with `deleted_conflict` if a soft-deleted secret of that name exists. |
| `get_secret(name, None)` | Returns the **newest accessible** version: enabled and inside its time window. If none is accessible, the error explains why the newest was rejected. |
| `get_secret(name, Some(v))` | Exactly that version, or a policy error (`disabled`, `not_yet_valid`, `expired`). |
| `get_secret_properties` | Metadata only, policy not applied — disabled/expired versions can be inspected. |
| `list_*` | Metadata only, in name order. |
| `list_*_page` | A window of the same order: up to `max_results` items whose names sort after the continuation token, and a token of their own, the name of the last item, while names remain after it (`None` on the last page). A token is a name, so a secret created or removed between pages shows up or not by where it sorts, and nothing is returned twice. The names after a token may all belong to the other listing (deleted versus live), so the final page can hold fewer items than `max_results`, even none: page until the token is `None`. `max_results: Some(0)` or a token that is not a secret name is `invalid_argument`. The defaults cut the page out of the full listing; the SQLite backend reads only the window. |
| `update_secret_properties` | Metadata only, never the value, never a new version. |
| `delete_secret` | Soft-deletes **all versions** in a recoverable vault; immediate in a purgeable vault. |
| `recover_deleted_secret` | Restores all versions. |
| `purge_deleted_secret` | Permanent. Only valid on a deleted secret. |
| `audit_events` | Every operation above is recorded, successes and failures, never with a value; metadata reads appear as `secret_inspect`. Reading the log and verifying the chain are not recorded; acknowledging a detected truncation of it is (`audit_verify` / `success`). |

The lifecycle conformance suite checks these as functions over
`&dyn SecretClient` (`sourceorrery_conformance::lifecycle`), run against the
SQLite vault directly and through the adapter pair, and by each remote
provider's CI job through its `Blocking` adapter. A remote backend may
differ only where its service cannot express the contract
(`SecretClient::capabilities`, per secret through `capabilities_of`), and
documents each difference; `audit_events` returning `unsupported` (the
service keeps its own log) is the one common to all.

A vault keeps each secret in one storage: its own file, or a provider
through one of its connections. `Routed` (`sourceorrery-provider`) is the
vault over every storage: a `SecretClient` over the vault file that sends
each call to where the secret is kept and records the provider's call in
the vault's own audit log. The CLI, the SDKs and the browser all read
through it; a secret's storage is the vault's record (`secrets.storage`),
never the manifest's.

A deliberate difference from the managed cloud secrets services: `not_before` and `expires_on`
are **enforced** on retrieval, not advisory.

Rotation is not an operation of the contract but a workflow over it
(`core::rotation`, [rotation.md](rotation.md)): a new value is written as a
disabled candidate, validated, enabled while the version it replaces is
disabled, and the previous credential retired at the issuer after a grace
period. Every step is an ordinary `set` or `update`, recorded in the
versions' tags; the issuer's side is a command the CLI runs, because a new
value is not a rotated credential until the issuer knows about it. It needs
per-version properties (`SecretClient::capabilities`), which the local vault,
HashiCorp Vault and Azure Key Vault have and AWS Secrets Manager has not.

Moving a vault is not an operation of the contract either: `vault
export` copies the file (SQLite's online backup) without this machine's
key or the view check, so the copy opens with the recovery key only, and
`vault import` brings such a copy in and gives it this machine's key
(`storage::sqlite::export`).

## 4. Cryptography (`sourceorrery-crypto`)

No algorithms are implemented in this repository.

| Purpose | Primitive | Crate |
|---------|-----------|-------|
| Value and key encryption | XChaCha20-Poly1305, random 24-byte nonce | `chacha20poly1305` |
| View-check password hash | Argon2id v1.3, 64 MiB / 3 passes / 1 lane by default | `argon2` |
| Recovery key → key, integrity keys | HKDF-SHA256 (the recovery key is 125 random bits; sub-keys of the vault key) | `hkdf` |
| Authenticator codes | TOTP, RFC 6238 over HMAC-SHA1 | `hmac`, `sha1` |
| Metadata, settings and audit-chain tags | HMAC-SHA256 | `hmac`, `sha2` |
| Randomness | OS CSPRNG | `getrandom` |

Every ciphertext carries **additional authenticated data** naming where it
lives, so a ciphertext copied between records fails to decrypt instead of
returning the wrong secret:

* values: `sourceorrery/v1/value/<vault id>/<name>/<version>`
* wrapped keys: `sourceorrery/v4/wrap/<vault id>/<wrap id>`, so a wrapped
  key is bound to the on-disk format it was written for
* the view check's records, a connection's credentials, a project's path
  and name: `sourceorrery/v4/<kind>/<vault id>[/<id>]`

Mutable rows, vault settings and the audit chain are authenticated with
HMAC-SHA256 under keys derived from the vault key; the domains and what
each tag covers are in [vault-format.md](vault-format.md).

## 5. Storage (`sourceorrery-storage`)

The one backend today is the **encrypted vault**: one SQLite file per vault
with versioned records, soft-delete state and the audit log. The OS credential
store is used to protect the vault *key*, not to hold secret values, because
Credential Manager, Keychain and Secret Service do not natively provide
version history, retention, policy or audit. See [vault-format.md](vault-format.md).

### Key hierarchy

```
key wrap                               two per vault
  this-machine : random KEK in the OS credential store
  recovery     : KEK = HKDF(recovery key, salt)
        │ wraps
        ▼
vault DEK  ────────────────────────►  encrypts every value and every sealed record
```

This machine opens the vault without asking; the recovery key, shown once
when the vault is made, opens it on any other machine, in WSL, a
container, CI or an exported copy. Replacing the recovery key removes the
old wrap in the same transaction. The view check (an optional password and
authenticator code before a person views the vault) is a check the vault
enforces, not part of this hierarchy: the key does not depend on it.

### Backend classes

| Backend | Status |
|---------|--------|
| Encrypted SQLite vault, its key in the OS store and under its recovery key | Shipped (milestone 1) |
| Providers a vault connects to (HashiCorp Vault, AWS Secrets Manager, Azure Key Vault), each implementing the same contract, chosen per secret ([providers](providers/index.md); identity, policy and revocation: [enterprise](enterprise.md)) | Shipped |

Headless Linux servers often have no Secret Service daemon. There the vault
opens with its recovery key, provisioned from a file or the environment —
never a silent fallback to plaintext or an unprotected vault.

### How costs grow

Every read records an audit row, so a vault's history grows with its use.
Measured with `crates/sourceorrery-provider/examples/scale.rs` on one
machine (Intel Core i7-8650U, 4 cores, NVMe SSD, Windows 11, release
build), median milliseconds of 15 runs (5 for the whole-log operations),
10 secrets unless stated:

| Operation | 1,000 events | 10,000 | 100,000 | What it grows with |
|---|---|---|---|---|
| Open (unlock) | 21 | 68 | 553 | every event since the newest acknowledgement: the walk at unlock verifies each one (about 5 µs) |
| Read: `get`, `properties`, through `Routed` | 13 | 15 | 20–22 | the audit row it commits (about 12 ms of it), and the count of keyed rows the chain-head check takes (about 2 ms per 100,000 events) |
| List every secret | 15 | 15 | 18 | the secrets, not the history: 33 ms for 1,000 secrets, 180 ms for 10,000 |
| Newest 100 audit events | 0.25 | 0.24 | 0.25 | nothing |
| `audit export --follow`, one poll | 0.2 | 0.8 | 27 | every event: each poll looks for newer ones by time |
| Every event; `audit --verify` | 2; 7 | 14; 50 | 173; 520 | every event, by design |
| `vault export` | 58 | 105 | 558 | the file's size |
| A read with four handles reading at once | 14 | 15 | 21 | as a read: writers take turns, and none waited out the 5 s busy timeout |

On that machine the vault is tested to 100,000 events and 10,000 secrets;
a read stays within 25 ms there, an unlock within a second, and a listing
of 10,000 secrets within 250 ms. Other machines differ, mostly in what a
durable commit costs. Before the `audit_keyed` index, every operation
counted the keyed rows with a scan of the whole log, three times: a read
took 91 ms at 100,000 events and a listing 128 ms. That index, and each
check naming the index it reads ([vault format](vault-format.md)), removed
the scans.
What still grows with the history is deliberate or measured: the walk at
unlock is the check that finds a row replaced inside the log, and starting
it later would skip authenticating those rows.

## 6. CLI (`sourceorrery-cli`)

`clap` for the command surface, `rpassword` for hidden input, `owo-colors`
for output, `tracing` for diagnostics. Design rules:

* `set` reads the value interactively, from stdin or a file. There is no
  `--value` flag: arguments leak via shell history and process listings.
* `list`, `versions`, `get`, `audit` show metadata. `get --reveal` is the one
  deliberate disclosure; `run` is the other (into a child's environment).
  The viewing commands and `ui` ask the vault's view check
  (`Ctx::check_view`); `run`, `check`, `init` and the SDKs never do.
* `setup` and `vault create [NAME]` are the setup screens (`ui::setup`): a
  state machine over a backend, drawn by a view, committed in one
  transaction at its review (`SqliteVault::change_settings`). `init` has
  screens of its own (`ui::init`) that read the vault's catalog and write
  the manifest. Without a terminal both take flags.
* Prompts go to stderr so stdout stays clean for data and `--output json`.
* Every error carries its stable code in JSON mode.
* `ui` is an interactive browser built on Ratatui (the `ui` cargo feature,
  on by default). It sees a vault only through `ui::source::MetadataSource`,
  which has no operation that returns a value, and it reads each thing
  once, when first shown, because every metadata read is audited. It opens
  vaults for inspection, as `audit` does, so a blocked vault still shows
  its audit log, and through `Routed`, so a secret a provider keeps is
  listed and changed there. Changes go through a separate
  `ui::editor::MetadataEditor` that only `ui::app` holds, once checked
  (against the storage's capabilities too) and confirmed (`ui::edit`); a
  new value comes from the CLI's hidden prompt with the screen suspended;
  the vault's settings change on the setup screens.
  Its `dark` and `light` themes are the documentation site's palettes
  (`site/src/styles/paper.css`); keep the two in step.

* `import` moves a `.env` file into a vault (`cli::dotenv` parses it; values
  go straight into `SecretBytes`) and declares its keys in the manifest;
  it prints key names only.
* `init --integration <agent>` writes the agent skills compiled into the
  binary from `crates/sourceorrery-cli/skills/` (`cli::integrations`), to
  each agent's skills directory; `integrations/` and the Claude Code plugin
  in `plugins/sourceorrery/` are generated from the same files and checked
  by a test ([ai-agents.md](ai-agents.md)).

Reference: [cli.md](cli.md).

## 7. Integration surface for other languages

Three ways to reach the Rust core:

1. **Native extensions** (shipped) — the Python (PyO3 and maturin) and
   Node.js (napi-rs) SDKs compile the Rust client into the extension
   module itself.
2. **The C ABI** (shipped) — `sourceorrery-ffi`, which the Java (Foreign
   Function and Memory API), .NET (`LibraryImport`), Go (cgo), C, C++ and
   PHP (FFI) SDKs call, and which any other language can call to build its
   own binding.
3. **Local broker protocol** (milestone 3) — an authenticated local socket
   / named pipe to a SourceOrrery process. The only path that can offer a
   security boundary the application does not control.

The compatibility contract is the SourceOrrery API and `CONTRACT_VERSION`,
not any binding generator. See [`bindings/README.md`](../bindings/README.md).

### The bindings layer

Ten SDKs, all **read-only** ([ADR 0005](adr/0005-read-only-sdks.md)): open
a vault with the CLI's opening order, get the newest accessible or an
explicit version, read properties, resolve a `sourceorrery://` reference,
load a `sourceorrery.toml`, close. No write, key or audit surface
exists in any of them; a library that cannot write cannot be tricked into
writing. User guides: [sdks/](sdks/index.md).

```
                     ┌────────────────────────────────────────────┐
  Rust (crate)  ───► │ sourceorrery                               │
  Python (PyO3) ───► │   SecretReader · Project · Error{code,hint}│ ──► storage ──► crypto
  Node (napi-rs) ──► │   opening order, manifest semantics, hints │
                     └──────────────────────┬─────────────────────┘
                                            │
                     ┌──────────────────────▼─────────────────────┐
  Java (FFM)     ──► │ sourceorrery-ffi                           │
  .NET (P/Invoke)──► │   so_reader_* / so_project_* (read-only)   │
  Go (cgo)       ──► │   so_vault_* / so_secret_* (tooling only)  │
  C, C++, PHP    ──► │   so_last_error_{code,message,hint}        │
                     └────────────────────────────────────────────┘
```

Three rules keep the layer thin ([ADR 0006](adr/0006-binding-technologies.md)):

* **All logic in Rust.** The `sourceorrery` crate owns the opening order
  (this machine's key in the OS credential store, then the recovery key: an
  explicit one, `SOURCEORRERY_RECOVERY_KEY`, `SOURCEORRERY_RECOVERY_KEY_FILE`;
  never a prompt, never the view check), the manifest semantics
  (mirroring `sourceorrery run`) and the *hint* attached to every error:
  the sentence that tells the person what to do. A binding maps the stable
  code to a typed error and passes code, message and hint through.
* **Values are guarded in every language.** Held in native memory until
  closed (zeroised by `so_bytes_free` or `SecretBytes`), printed as
  `[REDACTED]`, not serialisable by accident, copied out only through an
  explicit call.
* **Every SDK is proven in CI** on Ubuntu, Windows and macOS against a
  vault the CLI creates in the job (`scripts/ci/fixture-vault.sh`), with
  its tests, its example and the cross-language conformance harness
  (`tests/conformance/sdk/`: one scenario list, one runner per SDK, one
  judge); a binding whose tests do not pass does not ship. Releases are
  cut by the manual workflow described in [release.md](release.md).

## 8. Platform matrix

| OS | Arch | Tier | Today |
|----|------|------|-------|
| macOS | arm64, x86-64 | 1 | release builds; CI on arm64 |
| Windows | x86-64, arm64 | 1 | release builds; CI on x86-64 |
| Linux glibc | x86-64, arm64 | 1 | release builds; CI on x86-64 |
| Linux musl | x86-64, arm64 | 2 | planned (milestone 5) |
| Linux | armv7 | 2 | planned (milestone 5) |
| FreeBSD / OpenBSD | x86-64 | community | planned (milestone 5) |

Every release builds the CLI, the C ABI and the SDK packages for the six
Tier 1 targets on native runners (Windows arm64 is cross-compiled); CI
runs every test on Ubuntu, Windows and macOS. A working binary does not
guarantee a working credential backend; CI tests the recovery-key path
everywhere and runs the OS-keyring smoke test against a real store on
each platform (`scripts/dev/keyring-smoke.sh` and `.ps1`).

## 9. Differentiators

* **Agent-aware access profiles** (milestone 3): a coding-agent session starts
  with no production-secret privileges.
* **Secret references instead of values**: shipped.
* **Reference-based project manifests**: inline `value` fields are rejected;
  comments and metadata still require care.
* **Policy-aware runtime resolution**: time windows and enabled state shipped;
  identity-based policy with the broker.
* **Provider-agnostic contract**: start local, move to enterprise storage
  without rewriting application secret access.

## 10. Three decisions made before the first line

1. The Rust core owns all secret-management semantics.
2. The contract follows the conceptual model of the managed cloud secrets
   services but is independent of any vendor.
3. The threat model is explicit: eliminating `.env` files is valuable;
   protecting secrets from arbitrary code executed by an AI agent requires a
   separate authentication and isolation strategy.

Decision records: [adr/](adr/).
