# SourceOrrery (Go)

Read secrets from a [SourceOrrery](https://sourceorrery.ai) vault.
Secrets belong to the runtime, not the repository.

```go
import sourceorrery "github.com/netizine/sourceorrery/bindings/go"

reader, err := sourceorrery.Open("development", nil)
defer reader.Close()
secret, err := reader.Get("database-password")
defer secret.Close()                 // zeroises the value
connect(secret.Value.Text())
```

The module only reads. The vault is unlocked the way the `sourceorrery`
CLI unlocks it: OS credential store first, then `SOURCEORRERY_PASSPHRASE`,
then `SOURCEORRERY_PASSPHRASE_FILE`. Every failure is a `*sourceorrery.Error`
with a stable `Code` and a `Hint`; `errors.Is` matches the `Err*` sentinels.

It is a cgo binding over the read-only part of the C ABI. The header is
vendored here; the shared library (`libsourceorrery_ffi.so` / `.dylib` /
`sourceorrery_ffi.dll`) comes from the `sourceorrery-ffi-<version>-<target>`
release archive or `cargo build --release -p sourceorrery-ffi`:

```bash
export CGO_LDFLAGS="-L/path/to/sourceorrery-ffi"      # where the library is
export LD_LIBRARY_PATH=/path/to/sourceorrery-ffi      # Linux (DYLD_LIBRARY_PATH on macOS, PATH on Windows)
go build ./...
```

Documentation: <https://sourceorrery.ai/sdks/go/>.

## Tests

```bash
cargo build --release -p sourceorrery-ffi -p sourceorrery-cli
eval "$(bash scripts/ci/fixture-vault.sh)"
cd bindings/go && CGO_LDFLAGS="-L$SOURCEORRERY_NATIVE_DIR" LD_LIBRARY_PATH="$SOURCEORRERY_NATIVE_DIR" go test ./...
```
