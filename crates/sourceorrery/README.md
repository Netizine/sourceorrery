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
delete, recover or purge a secret, or manage vault keys, checks,
connections or audit history. Reads still append audit events. It is also
the core that the Python and JavaScript SDKs are built from.

Documentation: [the Rust guide](https://sourceorrery.ai/sdks/rust/) ·
[API on docs.rs](https://docs.rs/sourceorrery) ·
[sourceorrery.ai](https://sourceorrery.ai)

## Before you start: the CLI

### Option 1: Set up with the CLI

This SDK is read-only. Use the separately installed `sourceorrery` CLI to
create vaults and set secret values. Follow the
[CLI installation guide](https://sourceorrery.ai/getting-started/#install), then:

```bash
sourceorrery setup                           # screens: the vault, its checks, its storage
sourceorrery secret set database-password --vault development
```

The CLI does not have to be installed where your application runs: this
crate opens the vault file itself. See
[Getting started](https://sourceorrery.ai/getting-started/).

### Option 2: Set up with an AI coding agent

```bash
sourceorrery init --integration all
```

Use your existing coding agent and ask: "Set up SourceOrrery for this
project without showing secret values." Replace `all` with your agent's
name to install only its skills. The agent handles the manifest, code and
launch commands; you create vaults and enter values privately.
The [agent setup guide](https://sourceorrery.ai/guides/ai-agents/)
also covers updating skills from the repository independently of the CLI.

## Install

```bash
cargo add sourceorrery
```

The crate reads the vault directly (there is no C ABI in between), so it
needs what the CLI needs to build: Rust 1.91.1 or newer and a C compiler for
the bundled SQLite, and on Linux `pkg-config` and `libdbus-1-dev` for the
Secret Service. For headless servers that open vaults with their
recovery keys only, `cargo add sourceorrery --no-default-features` drops
the OS credential store (the `os-keyring` feature), the providers
(`remote`) and the D-Bus requirement.

## Opening a vault

`SecretReader::open(vault)` looks for the vault under `SOURCEORRERY_HOME`
or the platform data directory and opens it with this machine's key in
the OS credential store, else the vault's recovery key from
`SOURCEORRERY_RECOVERY_KEY` or the file named by
`SOURCEORRERY_RECOVERY_KEY_FILE`. There is never an interactive prompt, and
the vault's view check is never asked.
`SecretReader::open_with(vault, &OpenOptions)` sets a home directory, a
recovery key or a recovery-key file in code. A secret the vault keeps at a
provider is read there, through the vault's connection.

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
