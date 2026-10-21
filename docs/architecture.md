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
* **Azure Key Vault–inspired API.** Familiar `SecretClient`, `set_secret`,
  `get_secret`, versioning and lifecycle operations, independent of Azure.
* **Multi-language SDKs.** C#, Python, JavaScript/TypeScript, Java and more via
  native bindings or a standard local protocol.
* **Enterprise capabilities.** Identity-aware authorisation, least privilege,
  rotation, auditability, recoverability and integration with external vaults.
* **Local-first.** No mandatory cloud account, SaaS subscription or remote
  server to get started.

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
│   ├── sourceorrery-storage    encrypted SQLite vault, key protectors,
│   │                           OS keyring, vault registry
│   ├── sourceorrery-cli        the `sourceorrery` binary
│   ├── sourceorrery            the read-only client: CLI unlock order,
│   │                           manifest loading, error hints (the Rust SDK)
│   └── sourceorrery-ffi        stable C ABI (cbindgen header): read-only
│                               so_reader_* for SDKs, so_vault_* for tooling
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

sourceorrery (client) ──► storage, core
sourceorrery-ffi ──────► sourceorrery (client), storage, core
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
| `Principal` | Who is asking (`user`, `workload`, `agent`, `system`). Milestone 1 labels the OS user; it is not verified identity. |
| `AuditEvent` | Metadata-only record: actor, operation, secret, version, outcome, detail (error code). |
| `Manifest` | `sourceorrery.toml`: project name, default vault, required secrets. Rejects unknown fields, so it cannot hold a value. |

### The `SecretClient` contract

```rust
pub trait SecretClient {
    fn vault_name(&self) -> &str;
    fn set_secret(&self, name: &str, value: SecretBytes, options: SetSecretOptions) -> Result<SecretProperties>;
    fn get_secret(&self, name: &str, version: Option<&str>) -> Result<Secret>;
    fn get_secret_properties(&self, name: &str, version: Option<&str>) -> Result<SecretProperties>;
    fn list_properties_of_secrets(&self) -> Result<Vec<SecretProperties>>;
    fn list_properties_of_secret_versions(&self, name: &str) -> Result<Vec<SecretProperties>>;
    fn update_secret_properties(&self, name: &str, version: Option<&str>, update: UpdateSecretProperties) -> Result<SecretProperties>;
    fn delete_secret(&self, name: &str) -> Result<DeletedSecret>;
    fn get_deleted_secret(&self, name: &str) -> Result<DeletedSecret>;
    fn list_deleted_secrets(&self) -> Result<Vec<DeletedSecret>>;
    fn recover_deleted_secret(&self, name: &str) -> Result<SecretProperties>;
    fn purge_deleted_secret(&self, name: &str) -> Result<()>;
    fn audit_events(&self, query: AuditQuery) -> Result<Vec<AuditEvent>>;
    fn resolve(&self, reference: &SecretReference) -> Result<Secret>; // provided
}
```

Semantics every implementation must honour:

| Operation | Semantics |
|-----------|-----------|
| `set_secret` | Creates a new **immutable** version; never mutates an old one. Fails with `deleted_conflict` if a soft-deleted secret of that name exists. |
| `get_secret(name, None)` | Returns the **newest accessible** version: enabled and inside its time window. If none is accessible, the error explains why the newest was rejected. |
| `get_secret(name, Some(v))` | Exactly that version, or a policy error (`disabled`, `not_yet_valid`, `expired`). |
| `get_secret_properties` | Metadata only, policy not applied — disabled/expired versions can be inspected. |
| `list_*` | Metadata only. |
| `update_secret_properties` | Metadata only, never the value, never a new version. |
| `delete_secret` | Soft-deletes **all versions** in a recoverable vault; immediate in a purgeable vault. |
| `recover_deleted_secret` | Restores all versions. |
| `purge_deleted_secret` | Permanent. Only valid on a deleted secret. |
| `audit_events` | Every operation above is recorded, successes and failures, never with a value; metadata reads appear as `secret_inspect`. Reading the log and verifying the chain are not recorded; acknowledging a detected truncation of it is (`audit_verify` / `success`). |

A deliberate difference from Azure Key Vault: `not_before` and `expires_on`
are **enforced** on retrieval, not advisory.

Rotation is intentionally not an operation yet. A new value is not a rotated
credential; real rotation needs the external issuer (milestone 4).

## 4. Cryptography (`sourceorrery-crypto`)

No algorithms are implemented in this repository.

| Purpose | Primitive | Crate |
|---------|-----------|-------|
| Value and key encryption | XChaCha20-Poly1305, random 24-byte nonce | `chacha20poly1305` |
| Passphrase → key | Argon2id v1.3, 64 MiB / 3 passes / 1 lane by default | `argon2` |
| Randomness | OS CSPRNG | `getrandom` |

Every ciphertext carries **additional authenticated data** naming where it
lives, so a ciphertext copied between records fails to decrypt instead of
returning the wrong secret:

* values: `sourceorrery/v1/value/<vault id>/<name>/<version>`
* wrapped keys: `sourceorrery/v1/protector/<vault id>/<protector id>`

## 5. Storage (`sourceorrery-storage`)

The milestone 1 backend is the **encrypted vault**: one SQLite file per vault
with versioned records, soft-delete state and the audit log. The OS credential
store is used to protect the vault *key*, not to hold secret values, because
Credential Manager, Keychain and Secret Service do not natively provide
version history, retention, policy or audit. See [vault-format.md](vault-format.md).

### Key hierarchy

```
key protector                          one or more per vault
  os-keyring  : random KEK in the OS credential store
  passphrase  : KEK = Argon2id(passphrase, salt, params)
        │ wraps
        ▼
vault DEK  ────────────────────────►  encrypts every value
```

Adding a protector wraps the same DEK again. A vault created on Windows with
Credential Manager can therefore also carry a passphrase protector for WSL,
Docker or CI. Removing the last protector is refused.

### Backend classes (planned)

| Backend | Status |
|---------|--------|
| Encrypted SQLite vault, key in OS store or passphrase | Milestone 1 |
| Remote provider (Azure Key Vault, AWS Secrets Manager, HashiCorp Vault, SourceOrrery server) implementing the same contract | Milestone 4 |

Headless Linux servers often have no Secret Service daemon. The fallback is a
passphrase protector with an independently provisioned secret — never silent
fallback to plaintext or an unprotected vault.

## 6. CLI (`sourceorrery-cli`)

`clap` for the command surface, `rpassword` for hidden input, `owo-colors`
for output, `tracing` for diagnostics. Design rules:

* `set` reads the value interactively, from stdin or a file. There is no
  `--value` flag: arguments leak via shell history and process listings.
* `list`, `versions`, `get`, `audit` show metadata. `get --reveal` is the one
  deliberate disclosure; `run` is the other (into a child's environment).
* Prompts go to stderr so stdout stays clean for data and `--output json`.
* Every error carries its stable code in JSON mode.
* `ui` is an interactive browser built on Ratatui (the `ui` cargo feature,
  on by default). It sees a vault only through `ui::source::MetadataSource`,
  which has no operation that returns a value, and it reads the vault only
  when it starts and when asked to, because every metadata read is audited.
  Its `dark` and `light` themes are the documentation site's palettes
  (`site/src/styles/paper.css`); keep the two in step.

Reference: [cli.md](cli.md).

## 7. Integration surface for other languages

Three ways to reach the Rust core, in order of preference for a given host:

1. **Native bindings** — the application loads the Rust library (napi-rs,
   PyO3/Maturin, Interoptopus, JNI/FFM, UniFFI).
2. **Local broker protocol** — an authenticated local socket / named pipe to a
   SourceOrrery process. The universal fallback and the only path that can
   offer a security boundary the application does not control.
3. **Stable C ABI** — for long-tail languages to build their own bindings.

The compatibility contract is the SourceOrrery API and `CONTRACT_VERSION`,
not any binding generator. See [`bindings/README.md`](../bindings/README.md).

### The bindings layer (milestone 2, shipped)

Ten SDKs, all **read-only** ([ADR 0005](adr/0005-read-only-sdks.md)): open
a vault with the CLI's unlock order, get the newest accessible or an
explicit version, read properties, resolve a `sourceorrery://` reference,
load a `sourceorrery.toml`, close. No write, protector or audit surface
exists in any of them; a library that cannot write cannot be tricked into
writing. User guides: [sdks/](sdks/index.md).

```
                     ┌────────────────────────────────────────────┐
  Rust (crate)  ───► │ sourceorrery                               │
  Python (PyO3) ───► │   SecretReader · Project · Error{code,hint}│ ──► storage ──► crypto
  Node (napi-rs) ──► │   unlock order, manifest semantics, hints  │
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

* **All logic in Rust.** The `sourceorrery` crate owns the unlock order
  (OS credential store, explicit passphrase, `SOURCEORRERY_PASSPHRASE`,
  `SOURCEORRERY_PASSPHRASE_FILE`, never a prompt), the manifest semantics
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

| OS | Arch | Tier |
|----|------|------|
| macOS | arm64, x86-64 | 1 |
| Windows | x86-64, arm64 | 1 |
| Linux glibc | x86-64, arm64 | 1 |
| Linux musl | x86-64, arm64 | 2 |
| Linux | armv7 | 2 |
| FreeBSD / OpenBSD | x86-64 | community |

A working binary does not guarantee a working credential backend; CI tests
the passphrase path everywhere and the OS-keyring path is validated manually
per platform until a keyring-capable CI matrix exists.

## 9. Differentiators

* **Agent-aware access profiles** (milestone 3): a coding-agent session starts
  with no production-secret privileges.
* **Secret references instead of values**: shipped.
* **No-secret project manifests**: shipped.
* **Policy-aware runtime resolution**: time windows and enabled state shipped;
  identity-based policy with the broker.
* **Provider-agnostic contract**: start local, move to enterprise storage
  without rewriting application secret access.

## 10. Three decisions made before the first line

1. The Rust core owns all secret-management semantics.
2. The contract is compatible with Azure Key Vault's conceptual model but
   independent of Azure.
3. The threat model is explicit: eliminating `.env` files is valuable;
   protecting secrets from arbitrary code executed by an AI agent requires a
   separate authentication and isolation strategy.

Decision records: [adr/](adr/).
