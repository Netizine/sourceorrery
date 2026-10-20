# Go

```bash
go get github.com/netizine/sourceorrery/bindings/go
```

A cgo binding over the C ABI. The header is vendored in the module; the
shared library comes from the `sourceorrery-ffi-<version>-<target>`
release archive (or `cargo build --release -p sourceorrery-ffi`). Tell
the linker and the loader where it is:

```bash
export CGO_LDFLAGS="-L/opt/sourceorrery/lib"
export LD_LIBRARY_PATH=/opt/sourceorrery/lib        # DYLD_LIBRARY_PATH on macOS, PATH on Windows
go build ./...
```

Static linking against `libsourceorrery_ffi.a` from the same archive works
too on Linux and macOS (`-lsourceorrery_ffi -lpthread -ldl -lm` on Linux).
A C toolchain is required (gcc or clang; MinGW-w64 on Windows). On Windows
the binding links `sourceorrery_ffi.dll` directly, because the static
archive next to it is built by MSVC and MinGW cannot consume it; keep the
DLL on `PATH` at run time.

## Get a secret

```go
import sourceorrery "github.com/netizine/sourceorrery/bindings/go"

reader, err := sourceorrery.Open("development", nil)
if err != nil {
    return err
}
defer reader.Close()

secret, err := reader.Get("database-password")
if err != nil {
    return err
}
defer secret.Close()                  // zeroises the value
connect(secret.Value.Text())
```

`Open(vault, nil)` behaves like the CLI: `SOURCEORRERY_HOME` locates the
vault; the OS credential store, then `SOURCEORRERY_PASSPHRASE`, then
`SOURCEORRERY_PASSPHRASE_FILE` unlock it. `&sourceorrery.OpenOptions{Home,
Passphrase, PassphraseFile, IgnoreEnvironment}` overrides any of that.

| Call | Returns |
|------|---------|
| `reader.Get(name)` | `*Secret` for the newest accessible version |
| `reader.GetVersion(name, version)` | `*Secret` for exactly that version |
| `reader.Properties(name, version)` (`""` for the newest) | `SecretProperties` (policy not applied) |
| `reader.Resolve("sourceorrery://development/database-password")` | `*Secret` |
| `reader.Descriptor()` | `VaultDescriptor` (no values) |

`Secret.Properties` (`Vault`, `Name`, `Version`, `Enabled`, `ContentType`,
`Tags`, `NotBefore`, `ExpiresOn`, `CreatedOn`, `UpdatedOn` as `time.Time`,
`RecoveryLevel`, `Reference()`) and `Secret.Value`, a `*SecretValue`:

```go
value.Bytes()    // []byte (a copy)
value.Text()     // string
value.Len()
value.Close()    // zeroise; Bytes() returns nil afterwards
value.String()   // "[REDACTED]"; encoding/json writes "[REDACTED]" too
```

## Errors

Every failure is a `*sourceorrery.Error` with `Code`, `Message` and `Hint`
(`Error()` is the message followed by the hint). `errors.Is` matches the
sentinels by code:

```go
secret, err := reader.Get("database-password")
switch {
case errors.Is(err, sourceorrery.ErrLocked):
    var e *sourceorrery.Error
    errors.As(err, &e)
    log.Println(e.Hint)                       // which passphrase sources were tried
case errors.Is(err, sourceorrery.ErrNotFound):
    log.Println(err)                          // "secret ... was not found. Store it with ..."
case errors.Is(err, sourceorrery.ErrPolicy):  // disabled, not yet valid or expired
    log.Println(err)
case err != nil:
    return err
}
```

Sentinels: `ErrNotFound`, `ErrVersionNotFound`, `ErrDeleted`,
`ErrDisabled`, `ErrNotYetValid`, `ErrExpired`, `ErrPolicy`,
`ErrInvalidName`, `ErrInvalidArgument`, `ErrPermissionDenied`,
`ErrLocked`, `ErrVaultNotFound`, `ErrMigrationRequired`, `ErrManifest`,
`ErrCrypto`, `ErrStorage`, `ErrUnsupported`. `(*Error).Transient()` is true
for `not_yet_valid`. See [the SDK overview](index.md#errors).

## Load a project

```go
project, err := sourceorrery.LoadProject("sourceorrery.toml", nil)   // "" discovers it
if err != nil {
    return err
}
defer project.Close()
for _, secret := range project.Secrets {
    os.Setenv(secret.Env, secret.Value.Text())
}
```

`LoadProject` resolves every `[secrets.*]` entry the way `sourceorrery run`
does and returns the first required secret's error if one cannot be read.

## Goroutines

A `*Reader` may be used from several goroutines at once. Each call pins
its OS thread while it reads the C ABI's per-thread error state.

## Building from source

```bash
cargo build --release -p sourceorrery-ffi -p sourceorrery-cli
eval "$(bash scripts/ci/fixture-vault.sh)"
cd bindings/go && CGO_LDFLAGS="-L$SOURCEORRERY_NATIVE_DIR" LD_LIBRARY_PATH="$SOURCEORRERY_NATIVE_DIR" go test ./...
```

Source: [`bindings/go`](../../bindings/go/README.md).
