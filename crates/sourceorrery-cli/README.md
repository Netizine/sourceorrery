# SourceOrrery CLI

**Secrets belong to the runtime, not the repository.**

`sourceorrery` replaces the plaintext `.env` file with an encrypted local
vault. It stores each secret as immutable, versioned, encrypted values with
a cloud-secrets-manager-style lifecycle (enable and disable, activation and
expiry times, soft delete, recovery, purge), keeps a tamper-evident audit
log of every access, and starts your application with its secrets in the
environment from a manifest, `sourceorrery.toml`, that names the secrets
a project needs and can never hold a value. `sourceorrery ui` is an
interactive vault manager that never shows a value.

Documentation: **<https://sourceorrery.ai>** ·
[Getting started](https://sourceorrery.ai/getting-started/) ·
[CLI reference](https://sourceorrery.ai/reference/cli/) ·
[Threat model](https://sourceorrery.ai/security/threat-model/)

## Install

Follow the [CLI installation guide](https://sourceorrery.ai/getting-started/#install)
for your platform. It covers ready-to-run packages, verified downloads and
source builds; Rust is not required for a prebuilt installation.

If you are reading this inside a CLI release archive, the `sourceorrery`
binary next to this README is the CLI. The installation guide explains how
to add it to your `PATH`. Check the installed version with
`sourceorrery --version`.

## Quick start

### Option 1: Set up with the CLI

Create or choose a `development` vault on the setup screens, keeping its
recovery key privately. Then store a value at the hidden prompt and select
the project's secrets:

```bash
sourceorrery setup
sourceorrery secret set database-password --vault development
sourceorrery init development --all
sourceorrery check
sourceorrery run -- npm start
sourceorrery ui
```

`sourceorrery import .env` can move existing values without displaying
them; review its report before deleting the original file.

### Option 2: Set up with an AI coding agent

```bash
sourceorrery init --integration all
```

Use your existing coding agent and ask: "Set up SourceOrrery for this
project without showing secret values." Replace `all` with your agent's
name to install only its skills. The agent handles the manifest, code and
launch commands; you create vaults and enter values privately.
The [agent setup guide](https://sourceorrery.ai/guides/ai-agents/)
also covers updating skills from the repository independently of the CLI.

On a server, in a container or in CI, where this machine's key is not
available, the vault opens with its recovery key from
`SOURCEORRERY_RECOVERY_KEY_FILE`
([Headless](https://sourceorrery.ai/guides/headless/)).

## Reading secrets from code

Applications read the vaults this CLI manages through the read-only SDKs.
They open the vault file themselves, so the CLI does not have to be
installed where the application runs.

| Language | Package |
|----------|---------|
| Rust | [`sourceorrery`](https://crates.io/crates/sourceorrery) |
| Python | [`sourceorrery`](https://pypi.org/project/sourceorrery/) on PyPI |
| JavaScript / TypeScript | [`@sourceorreryai/sdk`](https://www.npmjs.com/package/@sourceorreryai/sdk) on npm |
| Java | [`ai.sourceorrery:sourceorrery`](https://central.sonatype.com/artifact/ai.sourceorrery/sourceorrery) on Maven Central |
| .NET | [`SourceOrrery`](https://www.nuget.org/packages/SourceOrrery) on NuGet |
| Go | [`github.com/netizine/sourceorrery/bindings/go`](https://pkg.go.dev/github.com/netizine/sourceorrery/bindings/go) |
| PHP | [`sourceorrery/sourceorrery`](https://packagist.org/packages/sourceorrery/sourceorrery) on Packagist |
| C, C++ | the `sourceorrery-ffi` archive on the GitHub release |

## What it does and does not protect

No plaintext secret on disk, in the repository or in shell history, and
every access on the record. It does **not** isolate secrets from code
running as your own user: anything that runs as you can unlock the same
vault. The [threat model](https://sourceorrery.ai/security/threat-model/)
keeps those guarantees apart. SourceOrrery has not been audited; do not
treat it as a production secret store yet.

## Features

`os-keyring` (default) keeps this machine's key in the OS credential
store; `ui` (default) is the interactive vault manager and the setup and
`init` screens; `remote` (default) the providers a vault's connections
reach; `otlp` (default) the OpenTelemetry export of audit events. Build
with `--no-default-features` for vaults that open with their recovery keys
only, no screens and no providers.

## Licence

MIT or Apache-2.0, at your option. Source:
<https://github.com/Netizine/sourceorrery>.
