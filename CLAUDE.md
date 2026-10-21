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
- `crates/sourceorrery-cli` — the `sourceorrery` binary. `src/ui/` is the
  Ratatui vault browser (`sourceorrery ui`, cargo feature `ui`, on by
  default).
- `crates/sourceorrery` — the read-only client (the Rust SDK): CLI unlock
  order, `Project::load` mirroring `sourceorrery run`, and the actionable
  `hint` every error carries. All SDK logic lives here.
- `crates/sourceorrery-ffi` — the C ABI (cbindgen header checked in CI).
  `so_reader_*` / `so_project_*` are read-only and are what SDKs link;
  `so_vault_*` is for tooling. The only crate allowed to use `unsafe`.
- `bindings/{python,node,java,dotnet,go,cpp,php}` — the SDKs. Python and
  Node are native extensions over `crates/sourceorrery` (own workspace
  roots, own lock files); the rest call the C ABI. `bindings/README.md` is
  the C ABI reference and index.
- `tests/conformance` — lifecycle + security suite every backend/SDK must pass.
  `tests/conformance/sdk/` is the cross-language harness: `scenarios.json`
  is the contract, `harness.py` drives one SDK's runner (`conformance/`
  under each binding, `examples/conformance.rs|.c` for Rust and C) and
  judges what it observed. A new read-only behaviour gets a scenario there;
  a new op means a change to every runner.
- `scripts/ci/fixture-vault.sh` — creates, with the CLI only, the vault
  every SDK test suite reads; `scripts/release/set-version.py` stamps a
  release version into every manifest.

## Rules that are not negotiable

- A secret value lives only in `SecretBytes` / `SymmetricKey`. Never put a
  value in a log, error message, audit `detail`, metadata struct, `Debug`
  output or a test fixture that is written to disk unencrypted.
- `SecretBytes` has no `Serialize`. Do not add one. The CLI reveals values
  only in `output::print_revealed` and the JSON branch of `secret get --reveal`.
- The CLI never accepts a secret value as a command-line argument.
- The `ui` browser reads a vault only through `ui::source::MetadataSource`,
  which never gains an operation that returns a value: no screen renders,
  copies or holds one. Changes go through `ui::editor::MetadataEditor`,
  which only `ui::app` uses, once `ui::edit` has checked them and the user
  has confirmed; it never gains purge, protector or acknowledgement
  operations. A new value comes only from `prompt::read_hidden` with the
  screen suspended and goes straight to the vault. Every metadata read is
  audited, so the browser reads each thing once, when it is first shown,
  and again only on an explicit refresh (or after a change); never on
  movement, search or a timer. It never asks a blocked vault
  for secrets (each refusal is recorded).
- `SecretError::code()` strings are append-only.
- New semantics go in core with a conformance test, not in a backend.
- Tests use passphrase protectors with `Argon2Params::TESTING`; never touch
  the real OS credential store in tests.
- SDKs are read-only (ADR 0005): no set/update/delete/recover/purge,
  protector or audit calls in any binding, ever. Bindings carry no logic
  beyond "stable code → typed error"; unlock order, manifest semantics and
  error hints live in `crates/sourceorrery`. A new read-only operation goes
  there and into `so_reader_*` first, then into every binding, with its
  test and example.
- Every SDK test suite and example must pass in CI against the fixture
  vault; `bindings/go/sourceorrery.h` must equal the generated header.
- `main` is branch-protected and its only required status check is the `CI`
  gate job at the end of `.github/workflows/ci.yml`; a new CI job must be
  added to that job's `needs:` list or it is not enforced. Give it
  `needs: changes` and the same `if:` as the other jobs too: changes that
  touch only docs (`scripts/ci/classify-changes.sh`) skip every build job.

## Commands

```bash
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings   # pedantic is on
cargo test --workspace
cargo run -p sourceorrery-cli -- --help
# `ui` design review: every theme and state as HTML in target/ui-snapshots
cargo test -p sourceorrery-cli ui::snapshot -- --ignored
```

For manual testing use an isolated home and a passphrase vault:

```bash
export SOURCEORRERY_HOME=/tmp/so-home SOURCEORRERY_PASSPHRASE=dev-only
sourceorrery vault create development --protector passphrase
```

SDK tests read the shared fixture vault (same thing, scripted):

```bash
cargo build --release -p sourceorrery-cli -p sourceorrery-ffi
eval "$(bash scripts/ci/fixture-vault.sh)"     # exports SOURCEORRERY_HOME, _PASSPHRASE, _TEST_*, _NATIVE_DIR
cd bindings/python && maturin develop --release && python -m pytest   # and so on per binding README
```

Bash heredocs with Rust or YAML content fail on this Windows machine; write
files with the Write tool or run a Python patch script with `python -I`.
Docker validates Linux (`rust:1-bookworm` needs `libdbus-1-dev pkg-config`).

## Conventions

- Rust 2024 edition, `#![forbid(unsafe_code)]` in every crate.
- Timestamps: RFC 3339 at the edges, Unix nanoseconds (i64) in SQLite.
- Secret names: Azure Key Vault rules (letters, digits, hyphens; max 127).
  Vault names: lowercase, digits, hyphens; max 64.
- Keep docs in `docs/` in sync with behaviour; `docs/cli.md` is the CLI
  reference.
