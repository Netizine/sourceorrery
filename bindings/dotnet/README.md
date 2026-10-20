# SourceOrrery for .NET

The [SourceOrrery](https://sourceorrery.ai) secrets client for .NET 8+: an
encrypted local vault with an Azure Key Vault-style lifecycle API. Secrets
belong to the runtime, not the repository.

```csharp
using SourceOrrery;

using var client = new SecretClient("development", passphrase);
client.SetSecret("database-password", "s3cr3t", new SetSecretOptions { ContentType = "text/plain" });

using var secret = client.GetSecret("database-password");
secret.Value.Use(bytes => Connect(bytes));          // the bytes never leave native memory
Console.WriteLine(secret.Properties.Version);       // metadata only; the value prints as [REDACTED]
```

Every `SecretClient` method is a `SecretClient` method of the Rust core:
set, get, list, update, delete, recover, purge, and the audit trail. The
Rust core owns every semantic; this package carries no business logic and
passes the conformance scenarios of the core in C#.

* A value is a `SecretValue` kept in native memory until it is disposed,
  which zeroises it. `Use(...)` hands the bytes to a callback without
  copying; `CopyTo(Span<byte>)` is the plain getter. There is no string
  getter: a .NET string cannot be wiped, so decode into a buffer you can
  clear. `ToString()` returns `[REDACTED]`.
* Every failure is a `SourceOrreryException` with the core's stable `Code`
  (`not_found`, `disabled`, `locked`, ...), mapped to a typed subclass. No
  message, `ToString()` or audit event ever contains a secret value.
* `passphrase == null` uses the OS credential store, exactly as the CLI does.

The NuGet package carries the native library under `runtimes/<rid>/native/`.
Set `SOURCEORRERY_NATIVE_DIR` to load `sourceorrery_ffi` from another
directory. The managed assembly is trimming- and AOT-compatible.

## Building from source

```bash
cargo build -p sourceorrery-ffi --release
dotnet test bindings/dotnet
```

The test project copies the native library from `target/release` next to its
output; `SOURCEORRERY_NATIVE_DIR` (or the MSBuild property
`SourceOrreryNativeDir`) points it somewhere else.
