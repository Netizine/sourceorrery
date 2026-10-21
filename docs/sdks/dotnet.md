# .NET

## Install

### From the release

`SourceOrrery.0.1.3.nupkg` on the
[v0.1.3 release](https://github.com/Netizine/sourceorrery/releases/tag/v0.1.3)
carries the native library for `win-x64`, `win-arm64`, `osx-x64`,
`osx-arm64`, `linux-x64` and `linux-arm64` under `runtimes/<rid>/native`, so
one package serves every platform. Put it in a folder, register that folder
as a package source in the repository's `nuget.config`, and add the package:

<!-- tabs: os -->

#### Windows

```powershell
New-Item -ItemType Directory -Force packages | Out-Null
Invoke-WebRequest https://github.com/Netizine/sourceorrery/releases/download/v0.1.3/SourceOrrery.0.1.3.nupkg -OutFile packages\SourceOrrery.0.1.3.nupkg
dotnet new nugetconfig                        # once per repository, if it has no nuget.config yet
dotnet nuget add source .\packages --name sourceorrery-release --configfile nuget.config
dotnet add package SourceOrrery --version 0.1.3
```

#### macOS

```bash
mkdir -p packages
curl -L -o packages/SourceOrrery.0.1.3.nupkg https://github.com/Netizine/sourceorrery/releases/download/v0.1.3/SourceOrrery.0.1.3.nupkg
dotnet new nugetconfig                        # once per repository, if it has no nuget.config yet
dotnet nuget add source ./packages --name sourceorrery-release --configfile nuget.config
dotnet add package SourceOrrery --version 0.1.3
```

#### Linux

```bash
mkdir -p packages
curl -L -o packages/SourceOrrery.0.1.3.nupkg https://github.com/Netizine/sourceorrery/releases/download/v0.1.3/SourceOrrery.0.1.3.nupkg
dotnet new nugetconfig                        # once per repository, if it has no nuget.config yet
dotnet nuget add source ./packages --name sourceorrery-release --configfile nuget.config
dotnet add package SourceOrrery --version 0.1.3
```

<!-- /tabs -->

### From NuGet

```bash
dotnet add package SourceOrrery
```

Every release is on NuGet.

Targets .NET 8 and later. P/Invoke is source-generated with
`LibraryImport`, so the package is trimming- and AOT-compatible. Set
`SOURCEORRERY_NATIVE_DIR` to use a native library from elsewhere.

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
`MigrationRequiredException`, `SecretNotFoundException`,
`VersionNotFoundException`, `SecretDeletedException`, `PolicyException`
with `SecretDisabledException`, `SecretNotYetValidException`
(`IsTransient`), `SecretExpiredException`, `IntegrityException`,
`UnsupportedException`, `InvalidArgumentException`, `InvalidNameException`,
`ManifestException`, `PermissionDeniedException`, `StorageException`. See
[the SDK overview](index.md#errors).

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

```bash
cargo build --release -p sourceorrery-ffi
export SOURCEORRERY_NATIVE_DIR=$PWD/target/release
eval "$(bash scripts/ci/fixture-vault.sh)"
dotnet test bindings/dotnet/SourceOrrery.sln
```

Source: [`bindings/dotnet`](../../bindings/dotnet/README.md).
