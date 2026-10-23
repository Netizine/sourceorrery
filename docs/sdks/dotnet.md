# .NET

## Install

### From NuGet

```bash
dotnet add package SourceOrrery
```

or, in the project file:

```xml
<PackageReference Include="SourceOrrery" Version="0.1.4" />
```

[`SourceOrrery` on NuGet](https://www.nuget.org/packages/SourceOrrery)
carries the native library for `win-x64`, `win-arm64`, `osx-x64`,
`osx-arm64`, `linux-x64` and `linux-arm64` under `runtimes/<rid>/native`,
so one package serves every platform. It is published by trusted
publishing and carries nuget.org's repository signature
([Supply chain](../supply-chain.md#nuget)).

Targets .NET 8 and later. P/Invoke is source-generated with
`LibraryImport`, so the package is trimming- and AOT-compatible. Set
`SOURCEORRERY_NATIVE_DIR` to use a native library from elsewhere.

### From the GitHub release

The same package, `SourceOrrery.0.1.4.nupkg`, is attached to the
[v0.1.4 release](https://github.com/Netizine/sourceorrery/releases/tag/v0.1.4).
Put it in a folder, register that folder as a package source in the
repository's `nuget.config`, and add the package:

<!-- tabs: os -->

#### Windows

```powershell
New-Item -ItemType Directory -Force packages | Out-Null
Invoke-WebRequest https://github.com/Netizine/sourceorrery/releases/download/v0.1.4/SourceOrrery.0.1.4.nupkg -OutFile packages\SourceOrrery.0.1.4.nupkg
dotnet new nugetconfig                        # once per repository, if it has no nuget.config yet
dotnet nuget add source .\packages --name sourceorrery-release --configfile nuget.config
dotnet add package SourceOrrery --version 0.1.4
```

#### macOS

```bash
mkdir -p packages
curl -L -o packages/SourceOrrery.0.1.4.nupkg https://github.com/Netizine/sourceorrery/releases/download/v0.1.4/SourceOrrery.0.1.4.nupkg
dotnet new nugetconfig                        # once per repository, if it has no nuget.config yet
dotnet nuget add source ./packages --name sourceorrery-release --configfile nuget.config
dotnet add package SourceOrrery --version 0.1.4
```

#### Linux

```bash
mkdir -p packages
curl -L -o packages/SourceOrrery.0.1.4.nupkg https://github.com/Netizine/sourceorrery/releases/download/v0.1.4/SourceOrrery.0.1.4.nupkg
dotnet new nugetconfig                        # once per repository, if it has no nuget.config yet
dotnet nuget add source ./packages --name sourceorrery-release --configfile nuget.config
dotnet add package SourceOrrery --version 0.1.4
```

<!-- /tabs -->

### From source

See [Building from source](#building-from-source) below.

## Get a secret

```csharp
using SourceOrrery;

using var reader = SecretReader.Open("development");
using var secret = reader.Get("database-password");
Connect(password: secret.Value.ExposeText());
// disposing zeroises the value and releases the vault
```

`SecretReader.Open(vault)` behaves like the CLI: `SOURCEORRERY_HOME`
locates the vault; the OS credential store, then `SOURCEORRERY_PASSPHRASE`,
then `SOURCEORRERY_PASSPHRASE_FILE` unlock it. `SecretReader.Open(vault,
new OpenOptions { Home = .., Passphrase = .., PassphraseFile = .., Environment = false })`
overrides any of that.

A vault that `sourceorrery.toml` declares in a `[vaults.<name>]` table
([providers](../providers/index.md)) is opened at its remote provider by
the same call; `new OpenOptions { Manifest = path }` names the manifest to
resolve through (default: the nearest `sourceorrery.toml` above the current
directory; `Project.Load` always uses the manifest it loads). Credentials
come from the provider's own environment, never from the manifest, which
holds the address only. HashiCorp Vault is the first provider: its
credential comes from `VAULT_TOKEN` or the other sources
[the provider documents](../providers/hashicorp-vault.md).

| Call | Returns |
|------|---------|
| `reader.Get(name)` | `Secret` for the newest accessible version |
| `reader.Get(name, version)` | `Secret` for exactly that version |
| `reader.GetProperties(name, version?)` | `SecretProperties` record (policy not applied) |
| `reader.Resolve("sourceorrery://development/database-password")` | `Secret` |
| `reader.GetDescriptor()` | `VaultDescriptor` record (no values) |

`Secret.Properties` (`Vault`, `Name`, `Version`, `Enabled`, `ContentType`,
`Tags`, `NotBefore`, `ExpiresOn`, `CreatedOn`, `UpdatedOn` as
`DateTimeOffset`, `RecoveryLevel`, `Reference`) and `Secret.Value`, a
`SecretValue`:

```csharp
value.Use((span, _) => Connect(span));   // ReadOnlySpan<byte>, no copy
value.Expose();                          // byte[] (a copy)
value.ExposeText();                      // string
value.Length;
value.Dispose();                         // zeroise; Expose() throws ObjectDisposedException afterwards
value.ToString();                        // "[REDACTED]"
```

## Errors

Every failure is a `SourceOrreryException` or a subclass, with `Code`,
`Detail`, `Hint` and `Message` (detail plus hint):

```csharp
try
{
    using var reader = SecretReader.Open("development");
    using var secret = reader.Get("database-password");
}
catch (VaultLockedException e) { Console.Error.WriteLine(e.Hint); }
catch (SecretNotFoundException e) { Console.Error.WriteLine(e.Hint); }
catch (SourceOrreryException e) { Console.Error.WriteLine($"{e.Code}: {e.Message}"); }
```

Classes: `VaultNotFoundException`, `VaultLockedException`,
`MigrationRequiredException`, `VaultMismatchException`,
`SecretNotFoundException`, `VersionNotFoundException`,
`SecretDeletedException`, `PolicyException` with
`SecretDisabledException`, `SecretNotYetValidException` (`IsTransient`),
`SecretExpiredException`, `IntegrityException`, `UnsupportedException`,
`InvalidArgumentException`, `InvalidNameException`, `ManifestException`,
`PermissionDeniedException`, `StorageException`,
`UnauthenticatedException` (the remote provider refused the process's
credentials), `ProviderUnavailableException` (the provider could not be
reached; `IsTransient`). See [the SDK overview](index.md#errors).

## Load a project

```csharp
using var project = Project.Load("sourceorrery.toml");   // or Project.Load() to discover it
foreach (var secret in project.Secrets)
{
    Environment.SetEnvironmentVariable(secret.Env, secret.Value.ExposeText());
}
```

`Project.Load` resolves every `[secrets.*]` entry the way `sourceorrery run`
does and throws the first required secret's exception if one cannot be read.

## Threads

A `SecretReader` may be shared between threads.

## Building from source

You need Git, Rust 1.88 or newer installed with rustup, and a C compiler
(on Linux also `pkg-config` and `libdbus-1-dev`);
[Building from source](../building.md#what-you-need) has the commands for
each platform. For this SDK, also the .NET SDK: 8 or newer builds the
library, and the tests and the example need .NET 10, which they target.

Get the code, build the native library, and pack the library into a
NuGet package:

```bash
git clone https://github.com/Netizine/sourceorrery
cd sourceorrery
git checkout v0.1.4              # or stay on main for the newest changes
cargo build --release -p sourceorrery-ffi
dotnet pack bindings/dotnet/SourceOrrery/SourceOrrery.csproj -c Release -o dist/nuget
```

`dist/nuget/SourceOrrery.<version>.nupkg` installs like the release's
package (register `dist/nuget` as a package source, as above). The version
is the one committed in the repository, not the release's;
[Get the code](../building.md#get-the-code) shows how to stamp the release
version first. A package built this way carries no native library (the
release workflow adds one per platform under `runtimes/`), so give your
application the one you built: copy `sourceorrery_ffi.dll`,
`libsourceorrery_ffi.so` or `libsourceorrery_ffi.dylib` from
`target/release` next to it, or name that directory in
`SOURCEORRERY_NATIVE_DIR`.

To run the tests, the example and the conformance harness, build the CLI
too, which creates the test vault, and run the rest in Bash (Git Bash on
Windows) from the repository root:

```bash
cargo build --release -p sourceorrery-cli -p sourceorrery-ffi
eval "$(bash scripts/ci/fixture-vault.sh)"       # a throwaway vault, the variables the tests read, SOURCEORRERY_NATIVE_DIR
dotnet test bindings/dotnet/SourceOrrery.sln
dotnet run --project bindings/dotnet/examples/GetSecret -- "$SOURCEORRERY_TEST_VAULT" database-password
dotnet build bindings/dotnet/conformance -c Release
python tests/conformance/sdk/harness.py --runner dotnet
```

What the fixture script creates: [The SDK test vault](../building.md#the-sdk-test-vault).
Source: [`bindings/dotnet`](../../bindings/dotnet/README.md).
