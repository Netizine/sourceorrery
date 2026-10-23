# SourceOrrery — notes for coding agents

SourceOrrery is a Rust workspace: an encrypted local secrets vault with an
cloud-secrets-manager-style lifecycle API and a CLI. Read `docs/architecture.md`
and `docs/threat-model.md` before changing anything security-relevant.

## Layout

- `crates/sourceorrery-core` — contracts and semantics only (no crypto, no I/O
  except manifest loading). `SecretClient` trait, `SecretError` codes,
  policy, audit types, `sourceorrery.toml` manifest, and `rotation`: the
  issue → validate → activate → retire state machine over any client,
  recorded in `sourceorrery.rotation.*` tags; it never runs a program or
  reads a value (the CLI's `commands/rotate.rs` runs the manifest's hooks
  the way `run` runs a command). `SecretClient::capabilities` is how a
  backend says what it cannot express; rotation needs
  `PerVersionProperties`.
- `crates/sourceorrery-crypto` — wrappers over RustCrypto. No algorithms here.
  `totp` (RFC 6238 over HMAC-SHA1) and `random::{recovery_code,
  random_passphrase}` live here too; `TotpSecret` is zeroising and redacted
  like every key.
- `crates/sourceorrery-storage` — encrypted SQLite vault, key protectors,
  OS keyring access, vault registry (paths).
- `crates/sourceorrery-cli` — the `sourceorrery` binary. `src/ui/` is the
  Ratatui vault browser (`sourceorrery ui`, cargo feature `ui`, on by
  default). `src/strength.rs` is the passphrase strength estimate (rules,
  no wordlist: `zxcvbn` would add 3 MB); a typed passphrase below "good"
  is refused, one from the environment or a file is warned about. `skills/` is the only source of the AI-agent skills that
  `init --integration` writes (embedded with `include_str!`; the CLI never
  fetches anything). `integrations/` and `plugins/sourceorrery/` at the
  root are generated from it: after editing a skill run
  `SOURCEORRERY_BLESS=1 cargo test -p sourceorrery-cli --test integrations`.
  The skills must never tell an agent to read, print or write a value.
- `crates/sourceorrery` — the read-only client (the Rust SDK): CLI unlock
  order, `Project::load` mirroring `sourceorrery run`, and the actionable
  `hint` every error carries. All SDK logic lives here.
- `crates/sourceorrery-ffi` — the C ABI (cbindgen header checked in CI).
  `so_reader_*` / `so_project_*` are read-only and are what SDKs link;
  `so_vault_*` is for tooling. The only crate allowed to use `unsafe`.
- `crates/sourceorrery-provider` — the adapters between the two shapes of
  the contract (`Blocking<A>`: an `AsyncSecretClient` as a `SecretClient`
  on a Tokio runtime; `AsyncLocal<C>`: the reverse on the blocking pool)
  and the base the remote providers build on (ADR 0008). Adapters pass
  every call and error through unchanged; a provider's logic never lives
  here. Tokio `rt` only; HTTP providers use `reqwest` with `rustls-tls`.
  `open_remote` dispatches on the manifest's provider behind the Cargo
  features `provider-*` (`remote` = all), on by default everywhere.
- `crates/sourceorrery-provider-vault` — HashiCorp Vault KV v2 behind
  `AsyncSecretClient` (`docs/providers/hashicorp-vault.md` is the mapping).
  Policy is the core's; the crate maps paths, versions, `custom_metadata`
  and statuses, and never logs a body or puts one in a message. Its `live`
  test runs the lifecycle suite against a server named by
  `SOURCEORRERY_VAULT_TEST_ADDR` (CI: the `provider-vault` job).
- `crates/sourceorrery-provider-aws` — AWS Secrets Manager behind
  `AsyncSecretClient` over the official SDK (`docs/providers/aws-secrets-manager.md`).
  Properties are per secret there, so the lifecycle suite runs with
  `lifecycle_with(&[], ..)` (no `PerVersionProperties`); its `live` test
  needs `SOURCEORRERY_AWS_TEST_ENDPOINT` (the `motoserver/moto` container
  in the `provider-aws` job, `moto_server` locally; LocalStack's image
  needs a licence token since 2026). A new provider follows the
  same shape: a crate over core, a feature in `sourceorrery-provider`, a
  `docs/providers/<name>.md`, a CI job in the gate, and a `Capability` in
  the conformance suite for anything its service cannot express.
- `bindings/{python,node,java,dotnet,go,cpp,php}` — the SDKs. Python and
  Node are native extensions over `crates/sourceorrery` (own workspace
  roots, own lock files); the rest call the C ABI. `bindings/README.md` is
  the C ABI reference and index.
- `tests/conformance` — lifecycle + security suite every backend/SDK must pass.
  The backend-independent lifecycle scenarios are `src/lifecycle.rs`,
  functions over `&dyn SecretClient`; `lifecycle::lifecycle(fresh)` runs
  them and every backend (and each adapter) must pass it. A new semantic
  goes there, not in `tests/lifecycle.rs`, which keeps what only the SQLite
  vault does.
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
- Secret names: letters, digits, hyphens; max 127 (portable to the managed cloud secrets services).
  Vault names: lowercase, digits, hyphens; max 64.
- Keep docs in `docs/` in sync with behaviour; `docs/cli.md` is the CLI
  reference, `docs/providers/` the remote providers and
  `docs/enterprise.md` identity, policy and revocation through them.
