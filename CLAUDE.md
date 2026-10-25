# SourceOrrery — notes for coding agents

SourceOrrery is a Rust workspace: an encrypted local secrets vault with an
cloud-secrets-manager-style lifecycle API and a CLI. Read `docs/architecture.md`
and `docs/threat-model.md` before changing anything security-relevant;
`docs/security-review.md` records what the last review checked, fixed and
left open.

## Layout

- `crates/sourceorrery-core` — contracts and semantics only (no crypto, no I/O
  except manifest loading, which stops at the repository, the home
  directory and, on Unix, another owner's directories). `text::foreign`
  is how any text a server or service supplies enters a message: bounded,
  control and invisible characters replaced. `SecretClient` trait, `SecretError` codes,
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
- `crates/sourceorrery-storage` — encrypted SQLite vault, its key wraps
  (this machine's key in a `keystore::CredentialStore`, one recovery key,
  ADR 0009), the view check (`sqlite/view.rs`: an optional password with
  an authenticator on top; a check, not encryption), the vault's
  connections to providers (`sqlite/connections.rs`: settings, credentials
  sealed under the vault key, the last test; rows tagged and listed in the
  settings record) and the catalog of secrets a connection stores
  (`secrets.storage`; local operations refuse such a secret, `Routed`
  uses `storage_of` / `record_at_connection`), each secret's description
  (`sqlite/catalog.rs`, in the row tag), the project folders built from
  the vault (`sqlite/projects.rs`: path and name sealed, a keyed path MAC,
  listed in the settings record), vault export and import
  (`sqlite/export.rs`), vault registry (paths).
  `SOURCEORRERY_KEYRING=off` gives no credential store.
- `crates/sourceorrery-cli` — the `sourceorrery` binary. `src/ui/` is the
  Ratatui vault browser (`sourceorrery ui`, cargo feature `ui`, on by
  default). `src/strength.rs` is the password strength estimate (rules,
  no wordlist: `zxcvbn` would add 3 MB); a typed password below "good"
  is refused, one from a file is warned about. `Ctx::check_view` asks the
  view check before a command views the vault or reveals a value; `run`,
  `check` and `init` never ask it. The vault subcommands are `create`,
  `list`, `export`, `import` and `destroy` (ADR 0009): a vault's view
  check, recovery key and connections change on the setup screens;
  without them, `vault create` and `vault import` set the password from
  `--password-file`. `vault create` takes a flag set per provider that adds a
  connection, and `secret set` / `import` take `--storage`
  (`commands/connections.rs`; credentials from files only). `init`
  (`commands/init.rs`) writes or extends `sourceorrery.toml` from the
  vault's catalog by name (`--all` / `--secret`), editing an existing file
  in place with `toml_edit`, and records the folder in the vault.
  `ui/setup/` is the setup wizard of `setup` and `vault create [NAME]`
  on a terminal (create a vault, or change one after its view check or
  recovery key, typed on the screen); its review commits everything in
  one `SqliteVault::change_settings` transaction. `setup --guide`, or no
  terminal, prints the non-interactive `vault create` instead
  (`commands/setup.rs`), which makes the vault with `--password-file`
  and its connections in the same transaction. `skills/` is the only source of the AI-agent skills that
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
  `so_vault_*` is for tooling. One of the two crates allowed `unsafe`.
- `crates/sourceorrery-os` — `create_private_new(path)`: a new, empty file
  only its creator can open, for a recovery key about to be written
  (Windows: `CreateFileW` with an owner-and-SYSTEM-only, protected DACL,
  read back and checked through the handle; Unix: `O_EXCL`, mode `0600`).
  The other crate allowed `unsafe` (ADR 0010), over `windows-sys`: one safe
  function, every `unsafe` block documented, `unsafe_op_in_unsafe_fn` and
  `undocumented_unsafe_blocks` denied as in `sourceorrery-ffi`. Nothing
  else goes in it.
- `crates/sourceorrery-provider` — the adapters between the two shapes of
  the contract (`Blocking<A>`: an `AsyncSecretClient` as a `SecretClient`
  on a Tokio runtime; `AsyncLocal<C>`: the reverse on the blocking pool)
  and the base the remote providers build on (ADR 0008). Adapters pass
  every call and error through unchanged; a provider's logic never lives
  here. Tokio `rt` only; HTTP providers use `reqwest` with `rustls-tls`.
  `open_connection` dispatches on a connection's provider (`ConnectionSettings`
  and optional stored `Credentials` from `core::connection`) behind the
  Cargo features `provider-*` (`remote` = all), on by default everywhere.
  `Routed` (`src/routed.rs`) is the vault over every storage: a
  `SecretClient` over a `SqliteVault` that routes by `storage_of` and
  records each provider call with `record_at_connection`; dispatch only.
  Capabilities are per secret (`SecretClient::capabilities_of`).
- `crates/sourceorrery-provider-vault` — HashiCorp Vault KV v2 behind
  `AsyncSecretClient` (`docs/providers/hashicorp-vault.md` is the mapping).
  Policy is the core's; the crate maps paths, versions, `custom_metadata`
  and statuses, and never logs a body or puts one in a message. Its `live`
  test runs the lifecycle suite against a server named by
  `SOURCEORRERY_VAULT_TEST_ADDR` (CI: the `provider-vault` job).
- `crates/sourceorrery-provider-aws` — AWS Secrets Manager behind
  `AsyncSecretClient` over the official SDK (`docs/providers/aws-secrets-manager.md`).
  Properties are per secret there, so the lifecycle suite runs with
  `lifecycle_with(&[ClearableTimeWindow], ..)` (no `PerVersionProperties`);
  its `live` test needs `SOURCEORRERY_AWS_TEST_ENDPOINT` (LocalStack in the
  `provider-aws` job and coverage, started by `scripts/ci/localstack.sh`
  through lstk with the image pinned in `.lstk/config.toml` and the
  `LOCALSTACK_AUTH_TOKEN` secret; LocalStack refuses to list a deleted
  secret's versions, so the deletion tests skip only the time comparison
  there and warn).
- `crates/sourceorrery-provider-azure` — Azure Key Vault behind
  `AsyncSecretClient` over the official Azure SDK for Rust
  (`docs/providers/azure-key-vault.md`). Properties are per version, so the
  suite runs with `PerVersionProperties`; Key Vault cannot remove a time
  window, so not `ClearableTimeWindow`. Its own credential chain
  (`credential.rs`: service principal, workload identity, developer tools,
  managed identity behind a one-second metadata-endpoint probe) stands in
  for the `DefaultAzureCredential` the Rust SDK lacks; reserved
  `sourceorrery:` tags carry precise version times and base64 marking. Its
  `live` test needs `SOURCEORRERY_AZURE_TEST_ENDPOINT` and creates a vault
  per scenario through the emulator's Resource Manager (LocalStack for
  Azure from `.lstk/azure.toml`, port 4567, RBAC enforced, token secret
  `LOCALSTACK_AZURE_AUTH_TOKEN`; the identity is the emulator's `any-app`).
  The AWS and Azure emulators cannot run at once: coverage collects
  `native.sh azure` first. A new provider follows the
  same shape: a crate over core, a feature in `sourceorrery-provider`, a
  `docs/providers/<name>.md`, a CI job in the gate, and a `Capability` in
  the conformance suite for anything its service cannot express. A new
  crate also goes in `PROVIDERS` of `scripts/release/publish-crates.py` for
  its token-authenticated first publication.
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
  every SDK test suite reads; given one provider's `vault create` flags
  after the home, it also keeps secrets there for the harness's
  `--remote` scenarios (the provider jobs, credentials stored in the
  vault). `scripts/release/set-version.py` stamps a
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
  operations; its two additions are a new secret in a chosen storage and
  forgetting a project folder that is gone. A new value comes only from
  `prompt::read_hidden` with the screen suspended and goes straight to the
  vault. The browser opens vaults through `Routed`, so a secret a
  connection stores is listed (one listing per provider, each recorded)
  and changed at its provider, and `ui::edit` checks a change against the
  storage's `Capability`s before it is sent; the vault's settings change
  on the setup screens (`c`, and `n` on the Vaults view), never through
  the editor. Every metadata read is audited, so the browser reads each
  thing once, when it is first shown, and again only on an explicit
  refresh (or after a change); never on movement, search or a timer. A
  project's manifest on disk is a file read, not a vault read. It never
  asks a blocked vault for secrets (each refusal is recorded).
- `init`'s screens (`ui::init`) read a vault's catalog only (names,
  storage, descriptions). A new secret's value is typed there into a
  hidden field (a zeroising buffer, drawn as dots from its length) and
  goes to the vault as `SecretBytes` at `[ Store ]`; no screen shows or
  reads a value, and nothing is written to the manifest before the
  review is confirmed.
- The setup wizard (`ui::setup`) keeps what it collects in memory until
  the review: typed passwords, recovery keys and credentials in
  zeroising buffers drawn as dots; the only things it shows are those
  shown once by design (a generated password, the authenticator key and
  its QR code until a code verifies it, a new recovery key behind the
  "written down" tick), and they leave its memory at the commit.
- `SecretError::code()` strings are append-only.
- New semantics go in core with a conformance test, not in a backend.
- Tests open vaults with their recovery keys (`NoStore`,
  `--no-keyring`, `SOURCEORRERY_KEYRING=off`) or an in-memory
  `MemoryStore`, and set view-check passwords with
  `Argon2Params::TESTING`; never touch the real OS credential store in
  tests.
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
# `ui` design review: every theme and state as HTML in target/ui-snapshots,
# drawn as the made-up user `alex`; then refresh the docs' walkthroughs
cargo test -p sourceorrery-cli ui::snapshot -- --ignored
npm --prefix site run walkthroughs
```

For manual testing use an isolated home and a vault that opens with its
recovery key only:

```bash
export SOURCEORRERY_HOME=/tmp/so-home SOURCEORRERY_KEYRING=off
sourceorrery vault create development --recovery-key-out /tmp/so-home/dev.key
export SOURCEORRERY_RECOVERY_KEY_FILE=/tmp/so-home/dev.key
```

SDK tests read the shared fixture vault (same thing, scripted):

```bash
cargo build --release -p sourceorrery-cli -p sourceorrery-ffi
eval "$(bash scripts/ci/fixture-vault.sh)"     # exports SOURCEORRERY_HOME, _RECOVERY_KEY, _TEST_*, _NATIVE_DIR
cd bindings/python && maturin develop --release && python -m pytest   # and so on per binding README
```

Bash heredocs with Rust or YAML content fail on this Windows machine; write
files with the Write tool or run a Python patch script with `python -I`.
Docker validates Linux (`rust:1-bookworm` needs `libdbus-1-dev pkg-config`).

## Conventions

- Rust 2024 edition, `#![forbid(unsafe_code)]` in every crate except
  `sourceorrery-ffi` and `sourceorrery-os` (ADR 0010), which deny
  `unsafe_op_in_unsafe_fn` and undocumented `unsafe` blocks instead.
- Timestamps: RFC 3339 at the edges, Unix nanoseconds (i64) in SQLite.
- Secret names: letters, digits, hyphens; max 127 (portable to the managed cloud secrets services).
  Vault names: letters, digits, hyphens, underscores, not starting with a
  hyphen; max 64; unique ignoring case (the registry resolves a name to
  the vault's own spelling).
- Keep docs in `docs/` in sync with behaviour; `docs/cli.md` is the CLI
  reference, `docs/providers/` the remote providers and
  `docs/enterprise.md` identity, policy and revocation through them.
