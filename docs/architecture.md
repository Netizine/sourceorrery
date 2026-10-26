# SourceOrrery 0.3.1 architecture

SourceOrrery is a local-first secrets platform. A local vault owns the
catalog, keys, provider connections, project records and audit history.
Each secret's values are kept either in that vault's encrypted SQLite
file or at one of its configured providers. Applications read through the
same Rust client regardless of that storage choice.

The CLI administers vaults and secrets. The terminal browser displays
metadata only. Application SDKs expose read-only operations. There is no
SourceOrrery daemon, local IPC service or same-user agent isolation in
0.3.1; those are [future work](roadmap.md#milestone-3--local-broker-and-agent-isolation).

## Components and dependency direction

| Component | Responsibility |
|-----------|----------------|
| `sourceorrery-core` | `SecretClient` and `AsyncSecretClient`, lifecycle semantics, properties, errors, references, manifest validation, policy and rotation state. |
| `sourceorrery-crypto` | Wrappers around established cryptographic libraries; zeroising/redacted key types, recovery-key generation and TOTP. |
| `sourceorrery-storage` | SQLite vault, authenticated records and audit checkpoints, key wraps, view check, connections, projects, registry and export/import. |
| `sourceorrery-os` | Exclusive creation of private recovery-key files, including a verified owner/SYSTEM-only Windows DACL. |
| `sourceorrery-provider` | `Routed` dispatch by the vault's per-secret catalog, provider connection opening, and synchronous/asynchronous adapters. |
| `sourceorrery-provider-vault` | HashiCorp Vault KV v2 mapping. |
| `sourceorrery-provider-aws` | AWS Secrets Manager mapping over the AWS SDK. |
| `sourceorrery-provider-azure` | Azure Key Vault mapping over the Azure SDK and its credential chain. |
| `sourceorrery` | Read-only application client: unlock sources, reference resolution, project loading and actionable errors. |
| `sourceorrery-ffi` | C ABI: read-only `so_reader_*` / `so_project_*` for applications, separate write-capable tooling functions. |
| `sourceorrery-cli` | Management commands, hidden prompts, setup/init wizards, metadata browser and child-process delivery. |
| `bindings/` | Thin native extensions or C ABI wrappers; error mapping and language-appropriate value ownership. |
| `tests/conformance` | Shared lifecycle and read-only SDK scenarios. |

```text
CLI ───────────────────────────► core / storage / Routed
Rust SDK ──► sourceorrery ──────► core / storage / Routed
Python, Node native extensions ─► sourceorrery
Java, .NET, Go, C, C++, PHP ─────► C ABI ──► sourceorrery

Routed ──► local SQLite values
       └─► provider adapters ──► HashiCorp Vault / AWS / Azure
storage ──► crypto; private key-file creation ──► sourceorrery-os
```

The local vault is still required when all values are remote. Its catalog
decides where a secret is kept, its connection supplies provider settings
and optionally credentials, and its audit records the routed operation.
The project manifest does not select a provider or carry credentials.

## Opening a vault

The vault data-encryption key is wrapped for this machine's OS credential
store and under one recovery key. A process first tries the machine's
credential-store entry. If that does not open the vault, it tries the
recovery-key sources supplied by its caller or environment. CLI commands
may prompt; SDKs never prompt. Headless deployments can disable the OS
store and provision a restricted recovery-key file.

The **view check** is separate: an optional password and authenticator
check before a person browses or reveals values. It does not derive the
encryption key and is not application authorisation. `run`, `check`,
`init` and the SDKs do not ask it; recovery-key access satisfies it.

Anyone who can obtain the vault key or use the same OS credential store
can access the local vault. Provider IAM adds its own checks for remote
values. Neither is an isolation boundary between two processes already
running with the same user's privileges. [Threat model](threat-model.md)

## Secret lifecycle and provider differences

A secret has a name and immutable value versions. Each version has enabled
state, content type, tags, activation/expiry times and timestamps.
`get_secret(name, None)` chooses the newest accessible version; an explicit
version is returned only if that version passes policy. Metadata reads
can inspect disabled or expired versions without returning their values.

A recoverable vault soft-deletes all versions and permits recovery within
retention. A purgeable vault deletes permanently. Lists and paged lists
return metadata, with deterministic name ordering. Stable error codes and
capabilities make provider limitations explicit:

| Storage | Per-version properties | Clear time window | Important limit |
|---------|------------------------|-------------------|-----------------|
| Local vault | Yes | Yes | Integrity checks can quarantine a damaged audit history. |
| HashiCorp Vault KV v2 | Yes | Yes | KV retention, token policy and server behaviour still apply. |
| AWS Secrets Manager | No | Yes | Properties apply to the secret; changes cannot express independent properties for old versions. |
| Azure Key Vault | Yes | No | A time window can be replaced, but not removed. |

The [provider guides](providers/index.md) define each mapping. The CLI
checks capabilities before submitting a change. Rotation requires
per-version properties, so it is supported locally, with HashiCorp Vault
and with Azure Key Vault, but not with AWS Secrets Manager. Issuer changes
run through explicit manifest hooks; see [rotation](rotation.md).

## Storage, cryptography and audit

The supported local format is **schema 5**. SQLite stores the catalog,
local ciphertext, sealed credentials and project paths, settings and the
audit log. Metadata such as secret names, tags and timestamps is not secret
material and must not contain values. See the [format](vault-format.md)
for table definitions and authentication domains.

| Purpose | Primitive |
|---------|-----------|
| Values and sealed records | XChaCha20-Poly1305, random 24-byte nonces and record-specific AAD. |
| Recovery-key wrapping | HKDF-SHA256 from the generated 125-bit recovery key and a per-wrap salt. |
| View-check password | Salted Argon2id; the hash and parameters are sealed under the vault key. |
| Settings, metadata and audit | HMAC-SHA256 under derived keys; wrap inventory and state checkpoints are authenticated. |
| Authenticator | TOTP over HMAC-SHA1. |
| Randomness | OS CSPRNG. |

Reads and writes append audit events without values. Routed mutations
record an attempt before contacting the provider. A lost answer can leave
an outcome unknown; the implementation does not retry a mutation to make
that uncertainty disappear. Audit-log reading and chain verification are
read-only. [Provider write handling](adr/0011-provider-writes-fail-closed.md)

Integrity checks detect edited records, broken chains and partial rollback.
They cannot detect a complete, internally consistent older copy without a
checkpoint kept outside the file. Replacing the recovery key changes its
wrap, not the vault data-encryption key; old copies remain usable with
their old recovery key.

`vault export` makes a consistent encrypted copy that omits this machine's
wrap and the view check. `vault import` verifies a supported copy and adds
a key for the destination machine when a credential store is available.
Remote values stay at the provider and need provider-native backups.
[Export and import](upgrading.md)

## CLI, terminal screens and runtime delivery

The CLI manages creation, versioning, metadata, deletion/recovery,
connections and auditing. Values enter through hidden prompts, stdin or
files, never secret-value command-line arguments. Metadata is the default
output; explicit `secret get --reveal` discloses a value.

The browser reads through `MetadataSource`, which has no value-returning
operation. Navigation, filtering, sorting, menus, theme preview and cached
inspection use retained metadata. Opening uncached details and explicit
refresh perform audited reads. Confirmed changes go through a separate
editor with validation and capability checks. New values are collected
through the suspended terminal's hidden prompt. The setup/init wizards
retain their own typed secret buffers and review/commit flows.

Refresh is synchronous. A visible operation message precedes the call,
followed by freshness/failure feedback; it does not promise working
cancellation or idle locking while a provider call blocks. Idle ticks do
not refresh metadata or extend the session lifetime. [CLI reference](cli.md)

`sourceorrery.toml` declares a project's vault and required/optional secret
references. `check` resolves metadata; `run` delivers resolved values to
the child through environment variables.
This delivery channel and copies made by the child are outside vault
at-rest encryption. The child can disclose anything it receives.

Agent skills are compiled into the CLI from
`crates/sourceorrery-cli/skills/`; the integration/plugin copies are
generated and drift-tested. They instruct agents to migrate references
and code without reading values. Instructions do not constrain a hostile
same-user process. [Agent integrations](ai-agents.md)

## Application SDKs

The public SDK surface opens vaults, gets values and properties, resolves
references and loads projects. There are no public SDK mutation, key,
connection or audit-management operations. Reads still append audit rows,
so the vault directory needs write access. Read-only describes the API;
it does not sandbox code that can invoke other libraries or the CLI.

Python and Node embed the Rust client in native extensions. Other
languages use the C ABI, whose application entry points are read-only;
write-capable C tooling entry points are separate. ABI **2** and contract
**2** are the 0.3.1 baseline, and bindings reject incompatible libraries.
Values are held in zeroising/redacted native buffers. Copies exposed as a
language string, byte array, file or process environment are the caller's
responsibility. [SDK guides](sdks/index.md)

## Builds and platform support

The release matrix targets macOS arm64/x86-64, Windows x86-64/arm64 and
Linux glibc x86-64/arm64. Windows arm64 is cross-compiled; the other release
builds use native runners. Runtime requirements differ by package:
Linux CLI/C ABI/Node packages target glibc 2.34, Python wheels
`manylinux_2_28`; macOS targets 11.0 on Apple silicon and 10.12 on Intel;
Windows targets Windows 10 / Server 2016 or later. A usable credential
backend is an additional platform requirement; recovery-key operation is
available without one.

Builds use Rust 1.91.1 or newer. `remote`, `provider-*`, `ui`, `otlp` and
`os-keyring` features select optional integrations. Release gates cover
formatting, Clippy, workspace tests, the minimum toolchain, SDK/ABI and
provider checks, dependency audits and the exact commit's hosted CI.
[Building](building.md) · [Releasing](release.md) · [Security review](security-review.md)

The source tree being ready to push does not mean a release has passed
its hosted or manual acceptance. Package publication is a separate,
explicit release operation.
