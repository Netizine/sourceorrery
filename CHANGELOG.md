# Changelog

All notable changes to SourceOrrery are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project
uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added — `sourceorrery ui`: changing secrets

* In the Secrets and Deleted views: `space` enables or disables a
  version, `e` changes its metadata (enabled, content type, tags, not
  before, expires), `n` stores a new version, `a` a new secret, `d`
  deletes and `u` recovers. Each change is checked with the vault's own
  rules first, so a refused one is never sent, then confirmed; deleting
  for good in a purgeable vault means typing the name.
* New values are never typed into the browser: confirming `n` or `a`
  suspends the screen and asks twice at the same hidden prompt as
  `secret set`, then stores the value and returns.
* Changes go through a separate write interface, `ui::editor::MetadataEditor`,
  that the views cannot reach. Purge, protectors, destroy, migrate and
  acknowledging a truncation stay CLI-only; a blocked vault cannot be
  changed. `--read-only` refuses every change and marks the header.

### Added — `sourceorrery ui`: the overview and the idle lock

* A new first view, Overview, where a vault opens: secrets by status (with
  bars) and by expiry; what expires or activates next; the audit chain's
  state, verified when the view is first shown and again on `v`; 14 days
  of audit activity with denials and failures marked, the last value read
  and the last failed unlock; the vault's file and key protectors. It is
  drawn from what the browser already holds; the deleted list it shows is
  read once (one `secret_list`), the rest is not audited.
* Idle lock: after `--lock-after` minutes without a key (default 10,
  `SOURCEORRERY_UI_LOCK_AFTER`, `0` for never) the browser drops the open
  vault, zeroising its key, and forgets what it read; `L` locks at once and
  `Enter` unlocks again with the ordinary unlock order.
* Views are now `1` Overview, `2` Secrets, `3` Deleted, `4` Audit log,
  `5` Vaults.

### Added — `sourceorrery ui`: the read-only vault browser

* Four views: Secrets, Deleted (with purge date and days left), Audit log
  (the newest 1000 events, denials and failures marked) and Vaults (the
  vault files in the home directory; listing needs no unlock). Switch with
  `Tab`, `Shift-Tab`, `←` `→` or the digits.
* `Enter` on a secret opens its details: every field and the reference,
  every version (newest first) and the secret's recent audit events.
* `/` searches the current view: words match anywhere; `tag:KEY[=VALUE]`,
  `status:`, `type:` and `expires:<30d` narrow secrets, `op:`, `outcome:`,
  `secret:` and `actor:` the audit log. Searching reads nothing.
* With no vault named, `ui` starts on Vaults; opening one suspends the
  screen for the usual unlock and prompt. Vaults are opened for inspection,
  as `audit` opens them: a blocked vault shows its audit log and a callout
  naming the truncation, and is never asked for secrets.
* Each thing is read once, when first shown, and kept until `r`: the
  secret list and the deleted list are one `secret_list` each, a secret's
  details one `secret_inspect`; the audit log, the vault list, moving and
  searching record nothing. `?` shows the keys, the search syntax and this.
* Keys: `Esc` now goes back (help, search, details, filter) and no longer
  quits; `q` and `Ctrl-C` quit.

### Added — `sourceorrery ui`, the interactive vault browser (groundwork)

* `sourceorrery ui [--vault NAME] [--theme dark|light|terminal]` opens a
  Ratatui browser on one vault: its settings and every live secret with
  status, short version id, last update, expiry and tags, with keyboard
  navigation (`↑↓`/`jk`, `PgUp`/`PgDn`, `g`/`G`, `r` to reload, `q` to
  quit). Metadata only: the browser reaches the vault through
  `MetadataSource`, which has no operation that returns a value. Stored
  text goes through the same escaping as the rest of the CLI's output.
* Themes: `dark` (the default) and `light` are the documentation site's
  paper palettes, painted over the whole screen, with the nearest xterm
  256 colours where the terminal has no 24-bit colour; `terminal` keeps
  the terminal's own colours. `SOURCEORRERY_THEME` sets the default;
  `NO_COLOR` turns colour off.
* The vault is unlocked with the usual order and prompt before the screen
  is taken over; without a terminal, or with `-o json`, `ui` is refused
  before unlocking. A session records one `vault_open` and one
  `secret_list` per load; moving and redrawing read nothing.
* New `ui` cargo feature of `sourceorrery-cli`, on by default; builds
  without it have no `ui` command.

### Fixed — terminal escape injection in CLI output

* Human-readable output shows control and bidirectional-formatting
  characters as escapes (`\u{1b}`) in every table cell and in status,
  note, error and prompt lines. Text read from the vault file (protector
  labels, keyring accounts, the vault name before unlock, audit rows
  written before unlock) can be planted by anyone who can write the file,
  and could otherwise move the cursor, erase lines (hiding audit rows the
  owner reviews before `audit --acknowledge`) or set the clipboard. JSON
  output and revealed values are unchanged.

## [0.1.2] - 2026-10-21

### Changed

* npm: the JavaScript/TypeScript SDK is published as `@sourceorreryai/sdk`,
  with platform packages `@sourceorreryai/sdk-<platform>`, the npm scope
  SourceOrrery owns; imports change from `'@sourceorrery/sdk'` to
  `'@sourceorreryai/sdk'`. The 0.1.0 and 0.1.1 release tarballs keep the
  old name and were never on npm, so 0.1.2 is the first version there.
* Release workflows: npm publishes with trusted publishing (GitHub OIDC,
  npm 11, provenance) instead of a stored token. `NPM_TOKEN` is no longer
  read; the repository variable `NPM_TRUSTED_PUBLISHING` switches npm on
  once each package lists its trusted publishers (`docs/release.md`).
* Docs: the install instructions point at the v0.1.1 release and say
  which registries carry 0.1.1; `cargo install sourceorrery-cli` is listed.

### Fixed

* Release workflow: the Linux wheel builds install `dbus-devel` and
  `pkgconf-pkg-config` with EPEL disabled. Both come from AlmaLinux's own
  repositories, and a broken EPEL mirror failed the first 0.1.1 release
  run.

## [0.1.1] - 2026-10-21

### Added

* **Release packages** workflow (`.github/workflows/ReleasePackages.yaml`):
  publishes an existing GitHub Release's packages to npm, PyPI, NuGet,
  crates.io, Maven Central, Packagist and pkg.go.dev, for a registry whose
  secret was added after the release ran. It checks every registry's files
  before uploading, skips versions already published and registries without
  a secret, and refuses an npm main tarball without its loader (0.1.0's).
  `docs/release.md` now has setup steps per registry.

### Changed

* Release workflows: NuGet publishes with trusted publishing instead of a
  stored API key. `NuGet/login` trades the job's GitHub OIDC token for a
  one-hour key that nuget.org grants only to the workflows its policy
  names; the repository secret is now `NUGET_USER` (the nuget.org profile
  name) and `NUGET_API_KEY` is no longer read (`docs/release.md`).
* PHP: the Composer manifest is now `composer.json` at the repository
  root, the only place Packagist and Composer `vcs` repositories read it,
  so `composer require sourceorrery/sourceorrery` resolves every release
  tag from the next one on; `bindings/php/composer.json` is gone and 0.1.0
  is still installed from its tag as a `path` repository. The manifest
  also maps the files that hold more than one class
  (`SourceOrreryException.php`, `Project.php`), so Composer's autoloader
  finds every exception class the way the bundled `autoload.php` already
  did. `scripts/ci/php-package-install.sh` proves the install from a tag
  in CI and in the release workflow's `php` job, and `publish-packagist`
  fails with a pointer to the one-time submission when Packagist does not
  know the repository, then waits for the version to appear
  (`docs/release.md`, *The PHP package and Packagist*).

### Fixed

* Release workflow: `publish-packagist` waited for `0.1.1` while Packagist
  lists a tag's version as `v0.1.1`, so it always timed out after five
  minutes with a warning; it now matches the tag.
* Release workflow: the `@sourceorrery/sdk` npm tarball now contains the
  loader (`index.js`) and the types (`index.d.ts`) that `napi build`
  generates. The 0.1.0 tarball shipped without them, so
  `require('@sourceorrery/sdk')` failed with `MODULE_NOT_FOUND` (the six
  platform tarballs were fine). The `node-build` job keeps the two files
  as an artifact that `node-package` adds before `npm pack`, and the job
  then installs the packed main and `linux-x64-gnu` tarballs into a
  scratch project and requires the module, so a tarball that cannot be
  loaded fails the release instead of shipping.
* `bindings/node`: `npm ci` works with npm 11, which refuses a lock file
  that lacks entries for the declared optional dependencies (npm 10 let
  the unresolvable platform packages through). `package.json` now depends
  on the platform packages as `file:npm/<platform>` links to their
  committed manifests, so the lock resolves without the registry;
  `scripts/release/set-version.py` turns the links into the release
  version when it stamps the manifests, and the release jobs run `npm ci`
  before stamping.

## [0.1.0] - 2026-10-20

### Added — cross-language SDK conformance harness

* `tests/conformance/sdk/scenarios.json` is the contract every SDK must
  honour against the fixture vault: unlock sources, latest and explicit
  versions, references, policy refusals, missing secrets and project
  loading, each with the code, message and hint it must produce.
  `harness.py` drives one SDK's runner through all of them and judges the
  observations; each binding ships a small runner (`conformance/` under
  the binding, `examples/conformance.rs` and `examples/conformance.c` for
  Rust and C) that speaks a line-based protocol. Every SDK CI job runs it
  after the language's own suite.

### Added — milestone 2: read-only SDKs for ten languages and a release pipeline

* `sourceorrery` crate: the read-only client every SDK is built on.
  `SecretReader` opens a vault the way the CLI does (OS credential store,
  then an explicit passphrase, `SOURCEORRERY_PASSPHRASE` and
  `SOURCEORRERY_PASSPHRASE_FILE`, never a prompt), reads the newest
  accessible or an explicit version, reads properties and resolves
  `sourceorrery://` references; `Project::load` resolves a
  `sourceorrery.toml` like `sourceorrery run`. Every `Error` carries the
  stable code, an `ErrorKind` and a *hint* saying what to do (which CLI
  command creates the vault, which passphrase sources were tried, why a
  version was refused by policy, that `crypto` means comparing with a
  backup, that `unsupported` means adding a passphrase protector).
* C ABI: read-only `so_reader_*` and `so_project_*` handles over that
  crate, plus `so_last_error_hint()`; `so_vault_*` errors report hints
  too. `examples/get_secret.c` is the read-only C sample.
* SDKs, all read-only (ADR 0005), each with typed errors chosen by code,
  values that are zeroised on close and print as `[REDACTED]`, a project
  loader, a tested example and a user guide under `docs/sdks/`: Python
  (`sourceorrery` on PyPI, PyO3/maturin abi3 wheels), JavaScript/TypeScript
  (`@sourceorrery/sdk` on npm, napi-rs with platform packages), Rust (the
  crate), Java (`ai.sourceorrery:sourceorrery`, Foreign Function and Memory
  API), .NET (`SourceOrrery` on NuGet, `LibraryImport`), Go
  (`github.com/netizine/sourceorrery/bindings/go`, cgo), C, C++
  (header-only `sourceorrery.hpp`) and PHP (`sourceorrery/sourceorrery`,
  FFI). Technology choices in ADR 0006.
* CI runs every SDK's tests and example on Ubuntu, Windows and macOS
  against a vault the CLI creates in the job
  (`scripts/ci/fixture-vault.sh`), lints the extension crates and checks
  the Go module's vendored header.
* Release workflow (`release.yml`, `workflow_dispatch` with `version` and
  `dry_run`): builds the CLI and the C ABI for six targets, wheels, npm,
  Maven and NuGet packages with the native libraries embedded, a GitHub
  Release with `SHA256SUMS`, and per-registry publish jobs (crates.io,
  PyPI, npm, NuGet, Maven Central, pkg.go.dev, Packagist) that are skipped
  until their secrets exist. `scripts/release/set-version.py` stamps the
  version into every manifest. Procedure and secrets: `docs/release.md`.

### Security — a detected audit-log truncation blocks the vault until acknowledged

* **A truncation is no longer refused once and then absorbed.** A recorded
  `audit_verify` / `failure` event with no later keyed acknowledgement now
  refuses every unlock and every operation with `crypto`, naming the
  event, and each refusal is itself recorded. Only `sourceorrery audit`
  unlocks such a vault, for inspection: listing the log (with a warning),
  `audit --verify` (which now also reports `unacknowledged`) and the new
  `audit --acknowledge [--yes]`, which prints the truncation events, asks
  for confirmation and appends one keyed `audit_verify` / `success` event
  (`truncation acknowledged (events …)`). After that the vault accepts
  operations again on the surviving history; the truncation stays on
  record. The acknowledgement covers exactly the events the caller was
  shown, so a truncation detected by another process in between is refused
  rather than swept in, and removing the acknowledgement row un-acknowledges
  what it covered. `vault migrate` of a schema 2 file that recorded a
  truncation leaves the migrated vault blocked the same way.
* `sourceorrery-storage`: `OpenOptions::allow_quarantined`,
  `VaultRegistry::open_for_inspection`,
  `SqliteVault::unacknowledged_truncations`,
  `SqliteVault::acknowledge_truncations` and `Acknowledgement`;
  `AuditVerification::unacknowledged`; partial index `audit_verifications`
  over the `audit_verify` rows (created by `vault migrate` for schema 2
  files). `sourceorrery audit` listings now show each event's id.

### Security — fixes from the second 20 October 2026 review (vault schema 3)

* **Row state is bound to the audit chain.** A row's HMAC tag proved it was
  written by the vault, not that it was current, so an older authentic copy
  of a version row (from before a disable or a window change) or of a
  secret row (from before a soft delete or purge) could be put back and
  would verify. Every change now records the changed row's new tag, or its
  removal, as a *checkpoint* in its own audit event (`state_tag`,
  `version_tag`, covered by the chain hash), and a row is honoured only when
  its tag equals the newest checkpoint for it. Rows with no checkpoint,
  resurrected rows, and rows or versions removed out of band are refused
  with `crypto`. Because the newest checkpoint is what counts, a stale chain
  head now **refuses** the unlock or operation that finds it (the refusal
  is recorded and re-anchors the head; see the entry above for what
  happens next) instead of being noted and absorbed. This is on-disk
  **schema 3**; `vault migrate` brings schema 1
  and 2 files forward and checkpoints every row it finds. The audit-row
  canonical domain is now `sourceorrery/v3/audit`.
* **Concurrent `vault create` can no longer delete the winner's file.** The
  path is reserved with exclusive creation; a losing creator gets
  `vault_exists` and never touches the file.
* **At most 8 passphrase protectors can be installed**, matching the number
  unlock tries, so an accepted credential always works.
* **Every rejected operation is audited**: invalid names (not recorded),
  rejected time windows and tags, empty updates, and refused protector
  additions and removals all leave one `failure` row with the operation
  rolled back.
* `run` passes the child's exit status through whole (Windows statuses above
  255 such as `3010`; `128 + signal` for a signalled Unix child).
* The C ABI initialises output slots through the raw pointer before taking a
  reference, so an uninitialised `so_bytes out;` from C is sound.
* Argon2 runs in caller-owned, zeroised working memory with a zeroised output
  buffer, so the derived key no longer survives in freed memory.
* The docs site's error-code reference tolerates rustfmt's multiline
  `#[error(...)]` attributes; `npm run build` works again.

### Changed — version reads load only the value they return

* Both 20 October 2026 reviews noted that every read of a secret loaded the
  nonce and ciphertext of **all** its versions: `get` of one version,
  `get_secret_properties`, `versions`, `list` and `list-deleted` (which
  summarise each secret by its newest version) all materialised every
  value's ciphertext just to verify metadata. The version query is now a
  metadata projection (exactly the columns the row tag covers, plus the
  tag), and `get_secret` fetches the nonce and ciphertext of the one version
  it has selected, in the same transaction, after selection. The tag and
  checkpoint rules are unchanged and apply to every metadata row read
  exactly as before; version selection is unchanged (core policy). A value
  that is damaged on disk is therefore noticed only when that version is
  returned: the other versions of the secret list, inspect and read as
  before. On-disk format and verification rules are unchanged.

### Changed — storage module layout

* `sourceorrery-storage`'s single `sqlite.rs` is now the `sqlite/` module:
  `schema` (SQL, connections, settings record), `rows` (authenticated reads
  and writes), `audit` (chain writer, head record, verification and the
  completion helpers every operation ends with), `protectors` (unlocking and
  key protectors), `migrate` (schema 1 → 2) and the vault type with its
  `SecretClient` implementation in `mod.rs`. Pure move; no behaviour change.

### Security — fixes from the 20 October 2026 review

* **Schema rollback no longer launders edits through migration.** The vault
  key is wrapped under an AAD that names the on-disk schema, `open` refuses
  older schemas with `migration_required`, and the explicit
  `vault migrate` aborts when any key proves the file was already in the
  current format. Migration re-wraps every key it holds.
* **Vault settings are authenticated** (`settings_tag` over schema, name,
  id, created time, recovery level and retention) and re-validated on every
  unlock, so retention can no longer be shortened to force a purge.
* **Removing the whole audit history and its head is detected** and recorded
  as a truncation instead of being accepted as a fresh log.
* **Manifest errors no longer echo rejected values**: diagnostics name keys
  and positions only. `env` names are compared case-insensitively and may
  not start with `SOURCEORRERY_`.
* **`run` strips `SOURCEORRERY_PASSPHRASE` and `SOURCEORRERY_PASSPHRASE_FILE`**
  from the child's environment, and an optional secret whose vault is
  missing no longer blocks startup.
* **Keyring cleanup checks ownership**: `vault destroy` and
  `vault protector remove` delete an OS-keyring entry only when its account
  is this vault's own and no sibling vault references it (`--keep-os-key`
  opts out); protector removal deletes the entry after the database commit
  and protector creation validates labels before storing a key.
* **Metadata reads are audited** as `secret_inspect`; invalid-name failures
  are audited without recording the name.
* **Argon2 parameters read from a vault are capped** (1 GiB, 64 passes,
  16 lanes) and at most eight passphrase protectors are tried per attempt.
* `SetSecretOptions` and `UpdateSecretProperties` reject unknown fields;
  keys returned by the OS credential store are zeroised after use.
* Release profile no longer sets `panic = "abort"`, so the C ABI's
  `SO_STATUS_PANIC` contract holds in release builds; the release matrix
  uses `macos-15-intel` instead of the retired `macos-13` runner.

### Added — milestone 1: core, encrypted vault and CLI

* `sourceorrery-core`: `SecretClient` contract modelled on Azure Key Vault
  (set → new immutable version, get latest accessible, metadata-only
  listing, property updates, soft delete, recover, purge, audit). Stable
  error codes, name validation, enforced `not_before`/`expires_on`,
  `SecretBytes` (zeroising, redacted, non-serialisable), `SecretReference`
  URIs and the `sourceorrery.toml` manifest that rejects values.
* `sourceorrery-crypto`: XChaCha20-Poly1305 with AAD binding, Argon2id
  passphrase KDF, envelope key wrapping, OS randomness.
* `sourceorrery-storage`: single-file encrypted SQLite vault with multiple
  key protectors (OS credential store via `keyring-core`, passphrase),
  per-version encryption bound to vault/name/version, soft-delete
  retention with automatic purge, metadata-only audit log with failed
  unlock attempts, `secure_delete` on purge.
* `sourceorrery` CLI: `vault create|list|info|protector|destroy`,
  `secret set|get|list|versions|update|delete|recover|purge`, `audit`,
  `init`, `check`, `run -- <command>`, `completions`. Values are read
  interactively, from stdin or a file — never as an argument — and are
  shown only with `get --reveal`.
* Conformance and security test suites; CI on Ubuntu, Windows and macOS.

### Added — CLI banner

* `sourceorrery` with no arguments shows the SourceOrrery wordmark rendered
  with Unicode half blocks (plain text when piped), a clickable
  `sourceorrery.ai` link and a quick start. Colours are chosen to stay
  legible on dark and light terminals; `NO_COLOR` and `SOURCEORRERY_BANNER`
  are honoured.

### Added — metadata and audit-log integrity (vault schema 2)

* `sourceorrery-crypto`: `derive_subkey` (HKDF-SHA256) and `mac` /
  `verify_mac` (HMAC-SHA256, constant-time comparison).
* `sourceorrery-storage`: a metadata key derived from the vault DEK
  authenticates every `secrets` and `secret_versions` row (enabled flag,
  time window, content type, tags, deletion state). Tampered rows are
  refused with error code `crypto` and an audit `failure`; a forged
  deletion is neither honoured nor purged. The audit log is a keyed hash
  chain (`prev_hash`, `hash`, `keyed`) with a keyed head record in
  `vault_meta`; rows removed from the end of the log are detected on the
  next keyed write and recorded as `audit_verify` / `failure`.
  `SqliteVault::verify_audit_chain()` reports breaks, truncations and
  unkeyed (pre-unlock) rows. Writes use `BEGIN IMMEDIATE` and a busy
  timeout, and failed operations keep their audit row.
* `sourceorrery-core`: audit operations `vault_migrate` and `audit_verify`.
* CLI: `sourceorrery audit --verify` (table or JSON; exit 1 when not
  intact).
* Schema version 1 vaults are migrated to schema 2 in one transaction on
  first unlock (`vault_migrate` audit row); a newer schema is still refused
  cleanly.

### Added — milestone 2 (in progress): C ABI and language bindings

* `sourceorrery-ffi`: a stable C ABI over the encrypted vault for language
  bindings, with the header `crates/sourceorrery-ffi/include/sourceorrery.h`
  generated by cbindgen on every build and checked for staleness in CI.
  Opaque vault handles usable from several threads, UTF-8 `(ptr, len)`
  strings, metadata as JSON, secret values as caller-owned `so_bytes`
  buffers that `so_bytes_free` zeroises, and stable error codes through
  per-thread `so_last_error_code()`. It is the only crate allowed to use
  `unsafe`; every block states its invariant. Covered by Rust smoke tests
  that call the exported functions and by a C example compiled in CI.

[Unreleased]: https://github.com/Netizine/sourceorrery/compare/v0.1.2...HEAD
[0.1.2]: https://github.com/Netizine/sourceorrery/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/Netizine/sourceorrery/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/Netizine/sourceorrery/releases/tag/v0.1.0
