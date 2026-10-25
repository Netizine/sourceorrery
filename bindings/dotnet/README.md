# SourceOrrery (.NET)

**Read secrets from [SourceOrrery](https://sourceorrery.ai) vaults in
.NET.** Secrets belong to the runtime, not the repository.

```csharp
using SourceOrrery;

using var reader = SecretReader.Open("development");
using var secret = reader.Get("database-password");
Connect(password: secret.Value.ExposeText());   // disposing zeroises the value
```

SourceOrrery replaces the plaintext `.env` file with an encrypted local
vault. This package is its read-only .NET SDK: it opens a vault, reads the
newest accessible version of a secret (or an exact version), its
properties and `sourceorrery://` references, and loads every secret a
project's `sourceorrery.toml` declares. It cannot create, change or delete
a secret through its public API; reads still append audit events.

Documentation: [the .NET guide](https://sourceorrery.ai/sdks/dotnet/) ·
[Getting started](https://sourceorrery.ai/getting-started/) ·
[Threat model](https://sourceorrery.ai/security/threat-model/)

## Before you start: the CLI

### Option 1: Set up with the CLI

This SDK is read-only. Use the separately installed `sourceorrery` CLI to
create vaults and set secret values. NuGet does not install the CLI. Follow
the [CLI installation guide](https://sourceorrery.ai/getting-started/#install), then:

```bash
sourceorrery vault create development
sourceorrery secret set database-password --vault development   # typed at a hidden prompt
```

The CLI does not have to be installed where your application runs: this
package opens the vault file itself.

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

## Install

```bash
dotnet add package SourceOrrery
```

Targets .NET 8 and later, with source-generated `LibraryImport` P/Invoke,
so it is trimming- and AOT-compatible. The package carries the native
library for `win-x64`, `win-arm64`, `osx-x64`, `osx-arm64`, `linux-x64` and
`linux-arm64` under `runtimes/`; set `SOURCEORRERY_NATIVE_DIR` to use a
library from elsewhere. It is published by trusted publishing and carries
nuget.org's repository signature
([Supply chain](https://sourceorrery.ai/security/supply-chain/)).

## Unlocking

`SecretReader.Open("development")` finds the vault under
`SOURCEORRERY_HOME` (or the platform data directory) and opens it like
the CLI: this machine's key in the OS credential store first, then
`SOURCEORRERY_RECOVERY_KEY`, then the file named by
`SOURCEORRERY_RECOVERY_KEY_FILE`; never an interactive prompt, and never
the vault's view check. On servers, in containers and in CI, where this
machine's key is not available, pass the vault's recovery key as a file
([Headless](https://sourceorrery.ai/guides/headless/)).

## Secrets at a provider

A secret that one of the vault's connections stores (HashiCorp Vault, AWS
Secrets Manager or Azure Key Vault) is read at that provider by the same
calls, with the credentials the connection stores or the ones the
provider's own tools find in the environment
([providers](https://sourceorrery.ai/providers/)).

## Errors and values

Every failure is a `SourceOrreryException` or a subclass
(`SecretNotFoundException`, `VaultLockedException`,
`SecretExpiredException`, `UnauthenticatedException`,
`ProviderUnavailableException`, …) with a stable `Code` and a `Hint` that
says what to do, such as the `sourceorrery secret set` command that would
store a missing secret. A value is a `SecretValue`: it prints as `[REDACTED]`,
lends its bytes as a span through `Use` or copies them out through
`Expose` and `ExposeText`, and is zeroised when disposed.

## Building from source

From a clone of the repository, with Rust 1.91.1+, a C compiler and the .NET
10 SDK. The tests read a vault that the CLI creates; the fixture script
also points `SOURCEORRERY_NATIVE_DIR` at the library just built. In Bash
(Git Bash on Windows):

```bash
cargo build --release -p sourceorrery-cli -p sourceorrery-ffi
eval "$(bash scripts/ci/fixture-vault.sh)"
dotnet test bindings/dotnet/SourceOrrery.sln
```

Every step, with the prerequisites for each platform:
<https://sourceorrery.ai/sdks/dotnet/#building-from-source>.

## Licence

MIT or Apache-2.0, at your option. Source:
<https://github.com/Netizine/sourceorrery/tree/main/bindings/dotnet>.
