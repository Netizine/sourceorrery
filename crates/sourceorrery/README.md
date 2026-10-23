# sourceorrery

**The read-only Rust client for [SourceOrrery](https://sourceorrery.ai)
vaults.** Secrets belong to the runtime, not the repository.

```rust
use sourceorrery::SecretReader;

let reader = SecretReader::open("development")?;
let secret = reader.get("database-password")?;
connect(secret.value.expose());
// `secret.value` is a SecretBytes: zeroised on drop, redacted in Debug, never serialisable
```

The crate opens a vault the way the `sourceorrery` CLI does, reads the
newest accessible version of a secret (or an exact version), its
properties, `sourceorrery://vault/name[/version]` references, and every
secret a project's `sourceorrery.toml` declares. It cannot create, change,
delete, recover or purge a secret, or touch protectors or the audit log:
an application that only reads cannot be tricked into writing. It is also
the core that the Python and JavaScript SDKs are built from.

Documentation: [the Rust guide](https://sourceorrery.ai/sdks/rust/) ·
[API on docs.rs](https://docs.rs/sourceorrery) ·
[sourceorrery.ai](https://sourceorrery.ai)

## Before you start: the CLI

This crate only reads. Vaults are created, and secrets stored, with the
`sourceorrery` command-line tool, which is a separate install:

```bash
cargo install --locked sourceorrery-cli      # or a prebuilt binary from the GitHub release
sourceorrery vault create development
sourceorrery secret set database-password --vault development
```

The CLI does not have to be installed where your application runs: this
crate opens the vault file itself. See
[Getting started](https://sourceorrery.ai/getting-started/).

## Install

```bash
cargo add sourceorrery
```

The crate reads the vault directly (there is no C ABI in between), so it
needs what the CLI needs to build: Rust 1.91.1 or newer and a C compiler for
the bundled SQLite, and on Linux `pkg-config` and `libdbus-1-dev` for the
Secret Service. For headless servers that only use passphrases,
`cargo add sourceorrery --no-default-features` drops the OS credential
store (the `os-keyring` feature) and the D-Bus requirement.

## Unlocking

`SecretReader::open(vault)` looks for the vault under `SOURCEORRERY_HOME`
or the platform data directory and unlocks it with the OS credential
store, then `SOURCEORRERY_PASSPHRASE`, then the file named by
`SOURCEORRERY_PASSPHRASE_FILE`. There is never an interactive prompt.
`SecretReader::open_with(vault, &OpenOptions)` sets a home directory, a
passphrase or a passphrase file in code.

## Errors

Every error carries a stable code (`not_found`, `locked`, `expired`, …),
an `ErrorKind` and a hint, one sentence that says what to do, such as the
`sourceorrery secret set` command that would store a missing secret. No
error ever contains a secret value.

## Loading a project

```rust
use sourceorrery::{OpenOptions, Project};

let project = Project::load(None, &OpenOptions::new())?;   // finds the nearest sourceorrery.toml
for (env, value) in project.into_env() {
    // DATABASE_PASSWORD and its SecretBytes, as `sourceorrery run` would set them
}
```

## Licence

MIT or Apache-2.0, at your option. Source:
<https://github.com/Netizine/sourceorrery/tree/main/crates/sourceorrery>.
