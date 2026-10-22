# SourceOrrery (.NET)

Read secrets from a [SourceOrrery](https://sourceorrery.ai) vault.
Secrets belong to the runtime, not the repository.

```csharp
using SourceOrrery;

using var reader = SecretReader.Open("development");
using var secret = reader.Get("database-password");
Connect(password: secret.Value.ExposeText());   // disposed = zeroised
```

The package only reads. The vault is unlocked the way the `sourceorrery`
CLI unlocks it: OS credential store first, then `SOURCEORRERY_PASSPHRASE`,
then `SOURCEORRERY_PASSPHRASE_FILE`. Every failure is a typed exception
with a stable `Code` and a `Hint` that says what to do.

Targets .NET 8+ with `LibraryImport` P/Invoke (trimming- and AOT-safe).
The NuGet package carries the native library for win-x64, win-arm64,
osx-x64, osx-arm64, linux-x64 and linux-arm64 under `runtimes/`; set
`SOURCEORRERY_NATIVE_DIR` to use a library from elsewhere.

Documentation: <https://sourceorrery.ai/sdks/dotnet/>. Source:
`bindings/dotnet` in the repository.

## Building from source

From a clone of the repository, with Rust 1.88+, a C compiler and the .NET
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
