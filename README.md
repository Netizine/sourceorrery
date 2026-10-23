<p align="center">
  <img src="logo.png" alt="SourceOrrery" width="128">
</p>

# SourceOrrery

**Secrets belong to the runtime, not the repository.**

Documentation: **[sourceorrery.ai](https://sourceorrery.ai)** [![AI Code Assurance](https://sonarcloud.io/api/project_badges/ai_code_assurance?project=Netizine_sourceorrery)](https://sonarcloud.io/summary/new_code?id=Netizine_sourceorrery)

[![Quality gate status](https://sonarcloud.io/api/project_badges/measure?project=Netizine_sourceorrery&metric=alert_status)](https://sonarcloud.io/summary/new_code?id=Netizine_sourceorrery) [![Reliability Rating](https://sonarcloud.io/api/project_badges/measure?project=Netizine_sourceorrery&metric=reliability_rating)](https://sonarcloud.io/summary/new_code?id=Netizine_sourceorrery) [![Security issues](https://sonarcloud.io/api/project_badges/measure?project=Netizine_sourceorrery&metric=software_quality_security_issues)](https://sonarcloud.io/summary/new_code?id=Netizine_sourceorrery) [![Coverage](https://sonarcloud.io/api/project_badges/measure?project=Netizine_sourceorrery&metric=coverage)](https://sonarcloud.io/summary/new_code?id=Netizine_sourceorrery)

SourceOrrery is an open-source, Rust-native secrets platform for software
development in the age of AI coding agents. It replaces the plaintext `.env`
file with an encrypted local vault, a cloud-secrets-manager-style lifecycle API
(versions, soft delete, recovery, time windows, audit) and a manifest that
declares *which* secrets a project needs without ever holding their values.

> [!WARNING]
> **Version 0.1.4 — core, encrypted vault, CLI with an interactive vault
> manager, and read-only SDKs (milestones 1 and 2).**
> Local-first and usable today on Windows, macOS and Linux, from Python,
> JavaScript/TypeScript, Rust, Java, .NET, Go, C, C++ and PHP
> ([docs/sdks](docs/sdks/index.md)). The authenticated local broker and
> remote providers are on the [roadmap](docs/roadmap.md). Not yet audited;
> do not treat it as a production secret store.

> [!NOTE]
> This documentation targets **0.1.4**, including `.env` import, agent skills
> installed by `init --integration`, and the `vault_mismatch` check. See the
> [release roadmap](docs/roadmap.md#release-014).

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

Install the [CLI](https://sourceorrery.ai/getting-started/) first, then,
from your application's directory:

```bash
sourceorrery setup
```

Six screens take you from a vault to a running program: a vault with a
strong passphrase (typed against a strength meter, or generated), a first
database password (typed or generated, never shown), recovery codes and a
hint, an authenticator app as a second factor, the reveal guard (whether
`secret get --reveal` must ask for the passphrase and a code again), and
the manifest. The same steps as commands, which the wizard prints when
there is no terminal ([First run](docs/getting-started.md)); replace
`npm start` with the command you normally use to start your application:

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

# 5. Optional: recovery codes, an authenticator app, and the guard on --reveal
sourceorrery vault recovery codes --vault development
sourceorrery vault 2fa enable --vault development
sourceorrery vault guard --reveal passphrase,second-factor --vault development
```

Working headless (WSL, Docker, CI)? Add a passphrase protector to the same
vault and unlock with `--passphrase-file` or `SOURCEORRERY_PASSPHRASE`:

```bash
sourceorrery vault protector add --kind passphrase --vault development
```

`sourceorrery import .env` imports supported
entries into the vault and declares them in `sourceorrery.toml`, printing
key names only. It leaves the original file in place; existing secrets and
empty values are skipped by default. See [docs/cli.md](docs/cli.md) for every
command.

## AI coding agents

`sourceorrery init --integration <agent>` installs two skills that let an
AI coding agent set SourceOrrery up and migrate a project off `.env` files,
code included, with instructions to keep values out of its context. They are compiled
into the CLI (it makes no network requests) and written where each agent
looks:

```bash
sourceorrery init --integration claude    # gemini, copilot, antigravity, cline, codex,
                                          # cursor, hermes, kilocode, kimi, kiro, opencode, all
```

The repository is also a Claude Code plugin marketplace
(`/plugin marketplace add Netizine/sourceorrery`), and
[integrations/](integrations/README.md) holds the skills per agent for
copying by hand. Guide: [docs/ai-agents.md](docs/ai-agents.md).

## Reading secrets from code

The CLI manages vaults; applications read them through the SDKs, which
only ever *read* ([why](docs/adr/0005-read-only-sdks.md)):

```python
from sourceorrery import SecretReader            # pip install sourceorrery

with SecretReader("development") as reader, reader.get("database-password") as secret:
    connect(password=secret.value.expose_text())
# The SDK's native buffer is zeroised; Python strings copied from it are not.
```

The same calls exist in every language, each with typed errors whose hint
says what to do (`sourceorrery secret set ...`, which passphrase sources
were tried, ...). No SDK installs the CLI: create the vault and store its
secrets with the CLI first. An SDK opens the vault file itself, so the CLI
need not be installed where the application runs.

| Language | Package | Guide |
|----------|---------|-------|
| Python | [`sourceorrery`](https://pypi.org/project/sourceorrery/) on PyPI | [Python](https://sourceorrery.ai/sdks/python/) |
| JavaScript / TypeScript | [`@sourceorreryai/sdk`](https://www.npmjs.com/package/@sourceorreryai/sdk) on npm | [JavaScript](https://sourceorrery.ai/sdks/javascript/) |
| Rust | [`sourceorrery`](https://crates.io/crates/sourceorrery) on crates.io | [Rust](https://sourceorrery.ai/sdks/rust/) |
| Java | [`ai.sourceorrery:sourceorrery`](https://central.sonatype.com/artifact/ai.sourceorrery/sourceorrery) on Maven Central | [Java](https://sourceorrery.ai/sdks/java/) |
| .NET | [`SourceOrrery`](https://www.nuget.org/packages/SourceOrrery) on NuGet | [.NET](https://sourceorrery.ai/sdks/dotnet/) |
| Go | [`github.com/netizine/sourceorrery/bindings/go`](https://pkg.go.dev/github.com/netizine/sourceorrery/bindings/go) | [Go](https://sourceorrery.ai/sdks/go/) |
| PHP | [`sourceorrery/sourceorrery`](https://packagist.org/packages/sourceorrery/sourceorrery) on Packagist | [PHP](https://sourceorrery.ai/sdks/php/) |
| C, C++ | `sourceorrery-ffi` archive on the [GitHub release](https://github.com/Netizine/sourceorrery/releases/latest) | [C](https://sourceorrery.ai/sdks/c/), [C++](https://sourceorrery.ai/sdks/cpp/) |

Python, JavaScript, Rust, Java and .NET packages include the native code
they need. Go, PHP, C and C++ load the C ABI library from the
`sourceorrery-ffi-<version>-<target>` archive on the GitHub release; each
guide shows where to put it. The PHP package on Packagist is this
repository at the release tag, with the SDK in
[`bindings/php`](bindings/php/README.md).

## What SourceOrrery does and does not protect

Three different guarantees, kept separate on purpose
([threat model](docs/threat-model.md)):

| Guarantee | Today |
|-----------|-------|
| **At-rest protection** — values stored by SourceOrrery are encrypted; metadata output omits them | Yes; input files, application output and copies are outside this boundary |
| **Access control** — which identities may retrieve which secret | Local only: whoever can unlock the vault |
| **Agent isolation** — an untrusted agent running as *your* user cannot impersonate your application | **No.** Requires the authenticated broker and OS isolation (milestone 3) |

Removing `.env` closes the accidental-exposure routes. It does not stop code
running with your privileges from calling the same API you can. SourceOrrery
says so rather than promising otherwise.

Every operation that reads or changes a secret, including metadata reads and
rejected attempts, is recorded in a keyed audit chain; reading the log and
verifying it are not. Each change also records the new state of the rows it
touched in that chain, so putting an older copy of a row back (a re-enabled
version, an undeleted secret) is refused, and a log found shortened blocks
the vault until its owner has reviewed what survives and acknowledged the
loss (`audit --acknowledge`). Tampering with the file is detected, not
prevented: restoring a complete older copy of a vault cannot be noticed
without a checkpoint kept outside the file, so keep the last
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

The Rust core owns every semantic. Storage backends and language bindings
never carry their own business logic; they pass the conformance suite or
they are not SourceOrrery. Read more in
[docs/architecture.md](docs/architecture.md).

## Install

SourceOrrery 0.1.4 can be installed three ways (step by step in
[Getting started](https://sourceorrery.ai/getting-started/)):

- **From the package registries.** The CLI: `brew install Netizine/sourceorrery/sourceorrery` (macOS, Linux), `winget install Netizine.SourceOrrery`, `scoop install sourceorrery` (bucket `Netizine/scoop-sourceorrery`) or `cargo install --locked sourceorrery-cli --version 0.1.4`.
  The SDKs: `pip install sourceorrery`, `npm install @sourceorreryai/sdk`,
  `cargo add sourceorrery`, `ai.sourceorrery:sourceorrery` on Maven Central,
  `dotnet add package SourceOrrery`,
  `go get github.com/netizine/sourceorrery/bindings/go@v0.1.4` and
  `composer require sourceorrery/sourceorrery`.
- **From the GitHub release.** The
  [v0.1.4 release](https://github.com/Netizine/sourceorrery/releases/tag/v0.1.4)
  has the CLI for Windows, macOS and Linux (x64 and arm64), the C ABI
  library with its headers, and every SDK package, with `SHA256SUMS`.
- **From source**, below.

How each package is published (trusted publishing and provenance where
the registry supports it) and how to check what you installed:
[docs/supply-chain.md](docs/supply-chain.md).

## Build from source

Requires Git, Python 3 for version stamping, Rust 1.91.1+ installed with rustup,
a C compiler for the
bundled SQLite (the Visual Studio Build Tools on Windows, the Xcode
Command Line Tools on macOS, gcc or clang on Linux) and, on Linux,
`pkg-config` and `libdbus-1-dev` for the Secret Service.

```bash
git clone https://github.com/Netizine/sourceorrery
cd sourceorrery
git checkout v0.1.4
python scripts/release/set-version.py 0.1.4                      # Python 3; stamps this local build
cargo build --release -p sourceorrery-cli -p sourceorrery-ffi   # the CLI and the C ABI, in target/release
cargo test --workspace
cargo install --locked --path crates/sourceorrery-cli           # the CLI into ~/.cargo/bin
```

Headless servers without a credential store can build the CLI with
`--no-default-features` and use passphrase protectors only. Every SDK, the
SDK test vault and the conformance harness:
[docs/building.md](docs/building.md).

## Roadmap

1. **Core and local CLI** — shipped.
2. **Read-only SDKs** for Python, JavaScript/TypeScript, Rust, Java, .NET,
   Go, C, C++ and PHP, and a release pipeline — included in 0.1.4, with
   trusted publishing for PyPI and crates.io. Supply-chain
   hardening continues: signed archives, notarised binaries.
3. Authenticated local broker, capability tokens, agent-aware profiles.
4. Enterprise: remote providers, workload identity, rotation, RBAC.
5. Community SDKs via the published C ABI and conformance harness.

Details in [docs/roadmap.md](docs/roadmap.md).

## Licence

Dual-licensed under [MIT](LICENSE-MIT) or [Apache 2.0](LICENSE-APACHE), at
your option.

Security reports: see [SECURITY.md](SECURITY.md).
