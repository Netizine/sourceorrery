# Go

## Install

Two parts: the Go module, from the module proxy, and the native library it
links, from the release (or [built from source](#building-from-source)).

### The module

```bash
go get github.com/netizine/sourceorrery/bindings/go@v0.2.0
```

[The module on pkg.go.dev](https://pkg.go.dev/github.com/netizine/sourceorrery/bindings/go)
is served by the Go module proxy from the `bindings/go/v0.2.0` tag, and
`go` checks it against the Go checksum database. It is a cgo binding over
the C ABI with the header vendored in the module, so a C toolchain is
required: gcc or clang, or MinGW-w64 gcc on Windows.

### The native library, from the release

The shared library comes from the `sourceorrery-ffi-0.2.0-<target>`
archive on the
[v0.2.0 release](https://github.com/Netizine/sourceorrery/releases/tag/v0.2.0).
Download the archive for your platform, unpack it, and tell the linker and
the loader where it is:

<!-- tabs: os -->

#### Windows

```powershell
$release = "https://github.com/Netizine/sourceorrery/releases/download/v0.2.0"
$dir = "$env:LOCALAPPDATA\sourceorrery-ffi"
Invoke-WebRequest "$release/sourceorrery-ffi-0.2.0-x86_64-pc-windows-msvc.zip" -OutFile sourceorrery-ffi.zip   # aarch64-pc-windows-msvc on Arm
Expand-Archive sourceorrery-ffi.zip -DestinationPath $dir -Force

$env:CGO_LDFLAGS = "-L$dir"
$env:Path = "$dir;$env:Path"          # sourceorrery_ffi.dll must be on PATH at run time
go build ./...
```

On Windows the binding links `sourceorrery_ffi.dll` directly, because the
static archive next to it is built by MSVC and MinGW cannot consume it.

#### macOS

```bash
release=https://github.com/Netizine/sourceorrery/releases/download/v0.2.0
archive=sourceorrery-ffi-0.2.0-aarch64-apple-darwin        # x86_64-apple-darwin on Intel
curl -LO "$release/$archive.tar.gz"
sudo mkdir -p /opt/sourceorrery && sudo tar xzf "$archive.tar.gz" -C /opt/sourceorrery --strip-components=1

export CGO_LDFLAGS="-L/opt/sourceorrery"
export DYLD_LIBRARY_PATH=/opt/sourceorrery
go build ./...
```

#### Linux

```bash
release=https://github.com/Netizine/sourceorrery/releases/download/v0.2.0
archive=sourceorrery-ffi-0.2.0-x86_64-unknown-linux-gnu    # aarch64-unknown-linux-gnu on arm64
curl -LO "$release/$archive.tar.gz"
sudo mkdir -p /opt/sourceorrery && sudo tar xzf "$archive.tar.gz" -C /opt/sourceorrery --strip-components=1

export CGO_LDFLAGS="-L/opt/sourceorrery"
export LD_LIBRARY_PATH=/opt/sourceorrery
go build ./...
```

<!-- /tabs -->

Verify a download against the release's `SHA256SUMS` before unpacking it.
Static linking against `libsourceorrery_ffi.a` from the same archive works
too on Linux and macOS (`-lsourceorrery_ffi -lpthread -ldl -lm` on Linux),
and then nothing has to be on the loader's path at run time.

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
Passphrase, PassphraseFile, IgnoreEnvironment, Manifest}` overrides any of
that. `Manifest` names the `sourceorrery.toml` whose `[vaults.<name>]`
tables say which vaults are remote and at which provider (default: the
nearest one above the current directory); a vault with such a table is
opened at its provider instead of as a local file. Credentials come from
the provider's own environment, never from the manifest: [HashiCorp
Vault](../providers/hashicorp-vault.md) takes `VAULT_TOKEN` or the other
sources it documents, [AWS Secrets Manager](../providers/aws-secrets-manager.md)
the AWS default credential chain.

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
`ErrLocked`, `ErrVaultNotFound`, `ErrMigrationRequired`,
`ErrVaultMismatch`, `ErrManifest`, `ErrCrypto`, `ErrStorage`,
`ErrUnsupported`, `ErrUnauthenticated` (the remote provider has no
credentials for this process), `ErrProviderUnavailable` (it could not be
reached). `(*Error).Transient()` is true for `not_yet_valid` and
`provider_unavailable`. See [the SDK overview](index.md#errors).

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

You need Git, Rust 1.91.1 or newer installed with rustup, and a C compiler
(on Linux also `pkg-config` and `libdbus-1-dev`);
[Building from source](../building.md#what-you-need) has the commands for
each platform. For this SDK, also Go 1.24 or newer, with cgo's C compiler
on `PATH` (MinGW-w64 gcc on Windows).

The Go code needs no build of its own; what you build is the native
library it links:

```bash
git clone https://github.com/Netizine/sourceorrery
cd sourceorrery
git checkout v0.2.0              # or stay on main for the newest changes
cargo build --release -p sourceorrery-ffi
```

The library lands in `target/release`; use that directory wherever the
install steps above use the unpacked archive (`CGO_LDFLAGS`, and the
loader path at run time). To build your module against this checkout's Go
code instead of the published module, point `go.mod` at it:

```bash
go mod edit -replace github.com/netizine/sourceorrery/bindings/go=/path/to/sourceorrery/bindings/go
```

To run the tests, the example and the conformance harness, build the CLI
too, which creates the test vault, and run the rest in Bash (Git Bash on
Windows) from the repository root:

```bash
cargo build --release -p sourceorrery-cli -p sourceorrery-ffi
eval "$(bash scripts/ci/fixture-vault.sh)"       # a throwaway vault, the variables the tests read, SOURCEORRERY_NATIVE_DIR
cd bindings/go
export CGO_LDFLAGS="-L$SOURCEORRERY_NATIVE_DIR"
export LD_LIBRARY_PATH="$SOURCEORRERY_NATIVE_DIR" DYLD_LIBRARY_PATH="$SOURCEORRERY_NATIVE_DIR"
# Git Bash on Windows: the DLL must be on PATH instead
#   export PATH="$(cygpath -u "$SOURCEORRERY_NATIVE_DIR"):$PATH"
go test ./...
go run ./examples/get-secret "$SOURCEORRERY_TEST_VAULT" database-password
go build -o conformance-go ./conformance          # conformance-go.exe on Windows
python ../../tests/conformance/sdk/harness.py --runner go
```

What the fixture script creates: [The SDK test vault](../building.md#the-sdk-test-vault).
Source: [`bindings/go`](../../bindings/go/README.md).
