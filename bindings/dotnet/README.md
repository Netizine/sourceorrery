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

```bash
cargo build --release -p sourceorrery-ffi
export SOURCEORRERY_NATIVE_DIR=$PWD/target/release
eval "$(bash scripts/ci/fixture-vault.sh)"
dotnet test bindings/dotnet/SourceOrrery.sln
```
