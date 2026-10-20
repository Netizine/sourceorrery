# Rust

## Install

### From the v0.1.0 tag

The crate is not on crates.io yet, so depend on the tag the
[v0.1.0 release](https://github.com/Netizine/sourceorrery/releases/tag/v0.1.0)
was cut from:

```toml
[dependencies]
sourceorrery = { git = "https://github.com/Netizine/sourceorrery", tag = "v0.1.0" }
```

### From crates.io

```toml
[dependencies]
sourceorrery = "0.1"
```

This works once the crate is published on crates.io; 0.1.0 is not there yet.

The `sourceorrery` crate is the read-only client every other SDK is built
on. It depends on `sourceorrery-storage` directly (no C ABI in between)
and, like the CLI, needs a C compiler for the bundled SQLite. The
`os-keyring` feature (default) enables the OS credential store; disable it
for headless servers that only use passphrases.

## Get a secret

```rust
use sourceorrery::SecretReader;

let reader = SecretReader::open("development")?;
let secret = reader.get("database-password")?;
connect(secret.value.expose());
// `secret.value` is a SecretBytes: zeroised on drop, redacted in Debug, no Serialize
```

`SecretReader::open` behaves like the CLI: `SOURCEORRERY_HOME` locates the
vault; the OS credential store, then `SOURCEORRERY_PASSPHRASE`, then
`SOURCEORRERY_PASSPHRASE_FILE` unlock it; there is never a prompt.
`SecretReader::open_with(vault, &OpenOptions)` takes a `home`, a
`passphrase`, a `passphrase_file` and `environment(false)` to ignore the
two passphrase variables.

| Call | Returns |
|------|---------|
| `reader.get(name)` | `Secret` for the newest accessible version |
| `reader.get_version(name, version)` | `Secret` for exactly that version |
| `reader.properties(name, Some(version))` | `SecretProperties` (policy not applied) |
| `reader.resolve("sourceorrery://development/database-password")` | `Secret` |
| `reader.descriptor()` | `VaultDescriptor` (no values) |

`Secret`, `SecretProperties`, `SecretBytes` and `SecretReference` are the
core's own types, re-exported. A `SecretReader` is `Send + Sync`.

## Errors

Every method returns `sourceorrery::Result<T>`; the error carries the
stable code, an `ErrorKind`, the message and a hint:

```rust
use sourceorrery::{ErrorKind, SecretReader};

match SecretReader::open("development").and_then(|r| r.get("database-password")) {
    Ok(secret) => { /* ... */ }
    Err(err) if err.kind() == ErrorKind::Locked => eprintln!("{}", err.hint()),
    Err(err) if err.kind().is_policy() => eprintln!("{} (retry later: {})", err, err.is_transient()),
    Err(err) => eprintln!("[{}] {err}", err.code()),   // Display = message + hint
}
```

`ErrorKind` has a variant per code (`NotFound`, `VersionNotFound`,
`Deleted`, `Disabled`, `NotYetValid`, `Expired`, `InvalidName`,
`InvalidArgument`, `PermissionDenied`, `Locked`, `VaultNotFound`,
`MigrationRequired`, `Manifest`, `Crypto`, `Storage`, `Io`, `Unsupported`)
plus `Other` for codes added later. See [the SDK overview](index.md#errors)
for what each hint says.

## Load a project

```rust
use sourceorrery::{OpenOptions, Project};

let project = Project::load(Some(std::path::Path::new("sourceorrery.toml")), &OpenOptions::new())?;
for secret in project.secrets() {
    // secret.env, secret.reference, secret.properties, secret.value
}
let pairs = project.into_env();   // Vec<(String, SecretBytes)>
```

`Project::load(None, ..)` discovers the nearest `sourceorrery.toml` above
the current directory. It mirrors `sourceorrery run`: a required secret
that cannot be read fails the load with that secret's error; optional ones
are left out.

## Example and tests

```bash
cargo run -p sourceorrery --example get_secret -- development database-password
cargo test -p sourceorrery
```

Source: [`crates/sourceorrery`](../../crates/sourceorrery).
