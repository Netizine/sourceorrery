<p align="center">
  <img src="logo.png" alt="SourceOrrery" width="360">
</p>

# SourceOrrery

**Secrets belong to the runtime, not the repository.**

Documentation: **[sourceorrery.ai](https://sourceorrery.ai)**

SourceOrrery is an open-source, Rust-native secrets platform for software
development in the age of AI coding agents. It replaces the plaintext `.env`
file with an encrypted local vault, an Azure Key Vault–style lifecycle API
(versions, soft delete, recovery, time windows, audit) and a manifest that
declares *which* secrets a project needs without ever holding their values.

> **Status: milestone 2 — core, encrypted vault, CLI and read-only SDKs.**
> Local-first and usable today on Windows, macOS and Linux, from Python,
> JavaScript/TypeScript, Rust, Java, .NET, Go, C, C++ and PHP
> ([docs/sdks](docs/sdks/index.md)). The authenticated local broker and
> remote providers are on the [roadmap](docs/roadmap.md). Not yet audited;
> do not treat it as a production secret store.

## Why

We give coding agents access to repositories, terminals and build pipelines
while still distributing credentials through plaintext files that sit in the
working tree, get indexed, get pasted into prompts and get committed.

SourceOrrery takes a different line:

* **No plaintext at rest, in anything SourceOrrery writes.** Every value is
  encrypted (XChaCha20-Poly1305) in a single SQLite file whose policy metadata
  and audit log are authenticated too. The vault key is protected by your OS
  credential store (Windows Credential Manager, macOS Keychain, Secret
  Service) and/or an Argon2id passphrase. Files you pass in, child processes,
  logs and other software are outside that boundary.
* **References, not values.** `sourceorrery://development/database-password`
  is safe to commit, log and paste. Today it resolves inside any process that
  can unlock the vault; per-runtime identity arrives with the broker
  (milestone 3).
* **A manifest for references, not values.** `sourceorrery.toml` declares
  *which* secrets a project needs. It accepts references and rejects inline
  `value` fields (without echoing them), but it cannot stop someone typing a
  secret into a comment or a `purpose`; keep sensitive material out of names
  and metadata.
* **Metadata by default.** `list`, `versions`, `get` and `audit` never print a
  value. Disclosure is a deliberate `get --reveal`.
* **Versioned and recoverable.** Every `set` creates an immutable version.
  Deletes are soft, recoverable and audited. Expiry and activation times are
  enforced, not advisory.

## Quick start

```bash
# 1. Create a vault (key protected by the OS credential store when available)
sourceorrery vault create development

# 2. Store a secret — interactively, from stdin or a file; never as an argument
sourceorrery secret set database-password --vault development

# 3. Inspect without revealing
sourceorrery secret list --vault development
sourceorrery secret get database-password --vault development

# 4. Declare what your project needs and run it with secrets injected
sourceorrery init
sourceorrery check
sourceorrery run -- npm start      # DATABASE_PASSWORD is set in the child only
```

Working headless (WSL, Docker, CI)? Add a passphrase protector to the same
vault and unlock with `--passphrase-file` or `SOURCEORRERY_PASSPHRASE`:

```bash
sourceorrery vault protector add --kind passphrase --vault development
```

See [docs/cli.md](docs/cli.md) for every command.

From code, an application only ever *reads* ([why](docs/adr/0005-read-only-sdks.md)):

```python
from sourceorrery import SecretReader            # pip install sourceorrery

with SecretReader("development") as reader, reader.get("database-password") as secret:
    connect(password=secret.value.expose_text())  # zeroised when the block ends
```

The same five calls exist for JavaScript/TypeScript, Rust, Java, .NET, Go,
C, C++ and PHP, each with typed errors whose hint says what to do
(`sourceorrery secret set ...`, which passphrase sources were tried, ...).
See [docs/sdks](docs/sdks/index.md).

## What SourceOrrery does and does not protect

Three different guarantees, kept separate on purpose
([threat model](docs/threat-model.md)):

| Guarantee | Milestone 1 |
|-----------|-------------|
| **At-rest protection** — no plaintext secrets on disk, in the repo or in agent context | Yes |
| **Access control** — which identities may retrieve which secret | Local only: whoever can unlock the vault |
| **Agent isolation** — an untrusted agent running as *your* user cannot impersonate your application | **No.** Requires the authenticated broker and OS isolation (milestone 3) |

Removing `.env` closes the accidental-exposure routes. It does not stop code
running with your privileges from calling the same API you can. SourceOrrery
says so rather than promising otherwise.

Every operation that reads or changes a secret, including metadata reads and
rejected attempts, is recorded in a keyed audit chain; reading the log and
verifying it are not. Each change also records the new state of the rows it
touched in that chain, so putting an older copy of a row back (a re-enabled
version, an undeleted secret) is refused. Tampering with the file is
detected, not prevented: restoring a complete older copy of a vault cannot be
noticed without a checkpoint kept outside the file, so keep the last
`audit --verify` output or back the file up.

## Architecture

```
crates/
  sourceorrery-core      contracts: SecretClient, properties, policy, audit, manifest
  sourceorrery-crypto    XChaCha20-Poly1305, Argon2id, envelope key wrapping
  sourceorrery-storage   encrypted SQLite vault, OS-keyring + passphrase protectors
  sourceorrery-cli       the `sourceorrery` binary
  sourceorrery           the read-only client (Rust SDK): unlock order, manifest, hints
  sourceorrery-ffi       stable C ABI (cbindgen header): so_reader_* for SDKs
bindings/                Python, Node, Java, .NET, Go, C++, PHP SDKs
tests/conformance        the semantics every backend and SDK must pass
docs/                    architecture, threat model, vault format, SDK guides, roadmap
```

The Rust core owns every semantic. Storage backends and (future) language
bindings never carry their own business logic; they pass the conformance
suite or they are not SourceOrrery. Read more in
[docs/architecture.md](docs/architecture.md).

## Build from source

Requires Rust 1.88+ and a C compiler (for the bundled SQLite).

```bash
cargo build --release
cargo test --workspace
./target/release/sourceorrery --help
```

Headless servers without a credential store can build with
`--no-default-features` on `sourceorrery-storage` and use passphrase
protectors only.

## Roadmap

1. **Core and local CLI** — shipped.
2. **Read-only SDKs** for Python, JavaScript/TypeScript, Rust, Java, .NET,
   Go, C, C++ and PHP, and a release pipeline — this release.
3. Authenticated local broker, capability tokens, agent-aware profiles.
4. Enterprise: remote providers, workload identity, rotation, RBAC.
5. Community SDKs via the published C ABI and conformance harness.

Details in [docs/roadmap.md](docs/roadmap.md).

## Licence

Dual-licensed under [MIT](LICENSE-MIT) or [Apache 2.0](LICENSE-APACHE), at
your option.

Security reports: see [SECURITY.md](SECURITY.md).
