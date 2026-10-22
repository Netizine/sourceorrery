# SourceOrrery CLI

**Secrets belong to the runtime, not the repository.**

`sourceorrery` replaces the plaintext `.env` file with an encrypted local
vault. It stores each secret as immutable, versioned, encrypted values with
an Azure Key Vault–style lifecycle (enable and disable, activation and
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

```bash
cargo install --locked sourceorrery-cli
```

This builds the `sourceorrery` binary. It needs Rust 1.88 or newer and a C
compiler for the bundled SQLite, and on Linux `pkg-config` and
`libdbus-1-dev` for the Secret Service. `--locked` builds with the
dependency versions the release was tested with.

Prebuilt binaries for Windows, macOS and Linux (x64 and arm64), with a
`SHA256SUMS` file, are on the
[GitHub releases](https://github.com/Netizine/sourceorrery/releases/latest)
page. If you are reading this inside one of those archives, the
`sourceorrery` binary next to it is the CLI: put it on your `PATH`
([per platform](https://sourceorrery.ai/getting-started/#from-the-github-release)).

## Quick start

```bash
# A vault, its key protected by the OS credential store
sourceorrery vault create development

# A secret, typed at a hidden prompt, piped in or read from a file; never an argument
sourceorrery secret set database-password --vault development

# Metadata only; a value is shown only with an explicit --reveal
sourceorrery secret list --vault development

# Declare what the project needs, check it resolves, run with it
sourceorrery init
sourceorrery check
sourceorrery run -- npm start      # DATABASE_PASSWORD is set in the child only

# Browse vaults, secrets, versions and the audit log
sourceorrery ui

# Already have a .env file? Store every value and declare every key, printing names only
sourceorrery import .env

# Give an AI coding agent the skills to set up SourceOrrery and migrate the project
sourceorrery init --integration claude      # or cursor, codex, copilot, gemini, ... all
```

The agent skills are compiled into the binary, so nothing is downloaded:
[AI coding agents](https://sourceorrery.ai/guides/ai-agents/).

On a server, in a container or in CI there is no credential store: add a
passphrase protector and unlock with `SOURCEORRERY_PASSPHRASE_FILE`
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

`os-keyring` (default) protects vault keys with the OS credential store;
`ui` (default) is the interactive vault manager. Build with
`--no-default-features` for passphrase protectors only and no `ui`.

## Licence

MIT or Apache-2.0, at your option. Source:
<https://github.com/Netizine/sourceorrery>.
