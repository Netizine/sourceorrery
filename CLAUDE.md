# SourceOrrery — notes for coding agents

SourceOrrery is a Rust workspace: an encrypted local secrets vault with an
Azure Key Vault–style lifecycle API and a CLI. Read `docs/architecture.md`
and `docs/threat-model.md` before changing anything security-relevant.

## Layout

- `crates/sourceorrery-core` — contracts and semantics only (no crypto, no I/O
  except manifest loading). `SecretClient` trait, `SecretError` codes,
  policy, audit types, `sourceorrery.toml` manifest.
- `crates/sourceorrery-crypto` — wrappers over RustCrypto. No algorithms here.
- `crates/sourceorrery-storage` — encrypted SQLite vault, key protectors,
  OS keyring access, vault registry (paths).
- `crates/sourceorrery-cli` — the `sourceorrery` binary.
- `tests/conformance` — lifecycle + security suite every backend/SDK must pass.

## Rules that are not negotiable

- A secret value lives only in `SecretBytes` / `SymmetricKey`. Never put a
  value in a log, error message, audit `detail`, metadata struct, `Debug`
  output or a test fixture that is written to disk unencrypted.
- `SecretBytes` has no `Serialize`. Do not add one. The CLI reveals values
  only in `output::print_revealed` and the JSON branch of `secret get --reveal`.
- The CLI never accepts a secret value as a command-line argument.
- `SecretError::code()` strings are append-only.
- New semantics go in core with a conformance test, not in a backend.
- Tests use passphrase protectors with `Argon2Params::TESTING`; never touch
  the real OS credential store in tests.

## Commands

```bash
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings   # pedantic is on
cargo test --workspace
cargo run -p sourceorrery-cli -- --help
```

For manual testing use an isolated home and a passphrase vault:

```bash
export SOURCEORRERY_HOME=/tmp/so-home SOURCEORRERY_PASSPHRASE=dev-only
sourceorrery vault create development --protector passphrase
```

## Conventions

- Rust 2024 edition, `#![forbid(unsafe_code)]` in every crate.
- Timestamps: RFC 3339 at the edges, Unix nanoseconds (i64) in SQLite.
- Secret names: Azure Key Vault rules (letters, digits, hyphens; max 127).
  Vault names: lowercase, digits, hyphens; max 64.
- Keep docs in `docs/` in sync with behaviour; `docs/cli.md` is the CLI
  reference.
