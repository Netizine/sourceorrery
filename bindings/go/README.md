# SourceOrrery (Go)

**Read secrets from [SourceOrrery](https://sourceorrery.ai) vaults in
Go.** Secrets belong to the runtime, not the repository.

```go
import sourceorrery "github.com/netizine/sourceorrery/bindings/go"

reader, err := sourceorrery.Open("development", nil)
defer reader.Close()
secret, err := reader.Get("database-password")
defer secret.Close()                 // zeroises the value
connect(secret.Value.Text())
```

SourceOrrery replaces the plaintext `.env` file with an encrypted local
vault. This module is its read-only Go SDK: it opens a vault, reads the
newest accessible version of a secret (or an exact version), its
properties and `sourceorrery://` references, and loads every secret a
project's `sourceorrery.toml` declares. It cannot create, change or delete
a secret: an application that only reads cannot be tricked into writing.

Documentation: [the Go guide](https://sourceorrery.ai/sdks/go/) ·
[Getting started](https://sourceorrery.ai/getting-started/) ·
[Threat model](https://sourceorrery.ai/security/threat-model/)

## Before you start: the CLI

This module only reads. Vaults are created, and secrets stored, with the
`sourceorrery` command-line tool, which `go get` does not install. Install
it once on the machine where you manage secrets, from the
[GitHub release](https://github.com/Netizine/sourceorrery/releases/latest)
(Windows, macOS and Linux, x64 and arm64) or with
`cargo install --locked sourceorrery-cli --version 0.2.0`
([step by step](https://sourceorrery.ai/getting-started/#install)), then:

```bash
sourceorrery vault create development
sourceorrery secret set database-password --vault development   # typed at a hidden prompt
```

The CLI does not have to be installed where your application runs: this
module opens the vault file itself, through the native library below.

## Install

```bash
go get github.com/netizine/sourceorrery/bindings/go@latest
```

It is a cgo binding over the read-only part of the SourceOrrery C ABI, so
it needs a C compiler (gcc or clang; MinGW-w64 gcc on Windows) and the
native library. The header is vendored here; the shared library
(`libsourceorrery_ffi.so` / `.dylib` / `sourceorrery_ffi.dll`) comes from
the `sourceorrery-ffi-<version>-<target>` archive on the
[GitHub release](https://github.com/Netizine/sourceorrery/releases/latest),
matching the module's version, or from
`cargo build --release -p sourceorrery-ffi`:

```bash
export CGO_LDFLAGS="-L/path/to/sourceorrery-ffi"      # where the library is
export LD_LIBRARY_PATH=/path/to/sourceorrery-ffi      # Linux (DYLD_LIBRARY_PATH on macOS, PATH on Windows)
go build ./...
```

On Windows the binding links `sourceorrery_ffi.dll` directly (MinGW-w64
gcc cannot use the MSVC static archive shipped next to it), so point
`CGO_LDFLAGS` at the directory holding the DLL and keep it on `PATH`.
Step by step per platform: [the Go guide](https://sourceorrery.ai/sdks/go/#install).

## Errors and values

Every failure is a `*sourceorrery.Error` with a stable `Code` and a `Hint`
that says what to do, such as the `sourceorrery secret set` command that
would store a missing secret; `errors.Is` matches the `Err*` sentinels. A
value is a `*SecretValue`: it prints and encodes as `[REDACTED]`, the bytes
come out only through `Bytes()` or `Text()`, and `Close()` zeroises them.

## Secrets at a provider

A secret that one of the vault's connections stores (HashiCorp Vault, AWS
Secrets Manager or Azure Key Vault) is read at that provider by the same
calls, with the credentials the connection stores or the ones the
provider's own tools find in the environment
([providers](../../docs/providers/)); `ErrUnauthenticated` /
`ErrProviderUnavailable` (transient) report a provider's failures.

## Tests

```bash
cargo build --release -p sourceorrery-ffi -p sourceorrery-cli
eval "$(bash scripts/ci/fixture-vault.sh)"
cd bindings/go && CGO_LDFLAGS="-L$SOURCEORRERY_NATIVE_DIR" LD_LIBRARY_PATH="$SOURCEORRERY_NATIVE_DIR" go test ./...
```

Every step, with the prerequisites for each platform:
<https://sourceorrery.ai/sdks/go/#building-from-source>.

## Licence

MIT or Apache-2.0, at your option. Source:
<https://github.com/Netizine/sourceorrery/tree/main/bindings/go>.
