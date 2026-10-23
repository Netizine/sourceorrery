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
a secret: an application that only reads cannot be tricked into writing.

Documentation: [the .NET guide](https://sourceorrery.ai/sdks/dotnet/) ·
[Getting started](https://sourceorrery.ai/getting-started/) ·
[Threat model](https://sourceorrery.ai/security/threat-model/)

## Before you start: the CLI

This package only reads. Vaults are created, and secrets stored, with the
`sourceorrery` command-line tool, which NuGet does not install. Install it
once on the machine where you manage secrets, from the
[GitHub release](https://github.com/Netizine/sourceorrery/releases/latest)
(Windows, macOS and Linux, x64 and arm64) or with
`cargo install --locked sourceorrery-cli --version 0.1.4`
([step by step](https://sourceorrery.ai/getting-started/#install)), then:

```bash
sourceorrery vault create development
sourceorrery secret set database-password --vault development   # typed at a hidden prompt
```

The CLI does not have to be installed where your application runs: this
package opens the vault file itself.

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
`SOURCEORRERY_HOME` (or the platform data directory) and unlocks it like
the CLI: the OS credential store first, then `SOURCEORRERY_PASSPHRASE`,
then the file named by `SOURCEORRERY_PASSPHRASE_FILE`; never an interactive
prompt. On servers, in containers and in CI, give the vault a passphrase
protector and pass the passphrase as a file
([Headless](https://sourceorrery.ai/guides/headless/)).

## Remote vaults

A vault that `sourceorrery.toml` declares in a `[vaults.<name>]` table is
opened at its remote provider by the same `SecretReader.Open` call;
`new OpenOptions { Manifest = path }` names the manifest to resolve through
(default: the nearest `sourceorrery.toml` above the current directory).
Credentials come from the provider's own environment, never from the
manifest: HashiCorp Vault is the first provider, and its credential comes
from `VAULT_TOKEN` or the other sources
[the provider documents](../../docs/providers/hashicorp-vault.md).

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
