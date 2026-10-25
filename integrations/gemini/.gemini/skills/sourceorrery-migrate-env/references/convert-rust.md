# Converting Rust code

SDK: `cargo add sourceorrery` (needs a C compiler for the bundled SQLite;
on Linux also `pkg-config` and `libdbus-1-dev`, or
`cargo add sourceorrery --no-default-features --features remote` for
servers without a credential store, where vaults open with their
recovery key).

## One module for every read

```rust
// src/secrets.rs
use std::sync::OnceLock;

use sourceorrery::{OpenOptions, Project};

static PROJECT: OnceLock<Project> = OnceLock::new();

/// Load the nearest sourceorrery.toml once, at start-up.
pub fn init() -> sourceorrery::Result<()> {
    let project = Project::load(None, &OpenOptions::new())?;
    let _ = PROJECT.set(project);
    Ok(())
}

/// The value delivered as environment variable `name`.
pub fn get(name: &str) -> Option<&'static str> {
    PROJECT.get()?.env(name)?.expose_utf8()
}
```

Call `secrets::init()?` first thing in `main`.

## Replacements

| Before | After |
|--------|-------|
| `std::env::var("DATABASE_URL")?` | `secrets::get("DATABASE_URL").ok_or("DATABASE_URL is not available")?` |
| `env::var("X").unwrap_or_else(\|_\| "30".into())` | `secrets::get("X").unwrap_or("30")` |
| `dotenvy::dotenv().ok();` | delete, once every key is covered |
| `env!("X")`, `option_env!("X")` | compile-time: the value would be baked into the binary. Ask the user; usually it should become a run-time read |

Remove `dotenvy` / `dotenv` from `Cargo.toml` when nothing loads `.env`
any more. `envy`, `config` and `figment` read the environment: keep them
and start under `sourceorrery run --`, or build their input from
`secrets::get`.

## Tests

`sourceorrery run -- cargo test`, or call `secrets::init()` in a test
helper.
