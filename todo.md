# Plan: close milestones 1 and 2 before milestone 3

Status of `docs/roadmap.md` at 0.1.4: nine items are unchecked across
milestone 1, milestone 2 and the supply-chain section. Everything else
before milestone 3 is done. This plan closes eight of them, one PR each
unless noted, defers one (code signing, item 8, until the project has
adoption that justifies the Apple and Windows signing costs) and ends with
the roadmap re-targeted at the release that carries them (0.2.0:
pagination changes the core API, which pre-1.0 is a minor bump).
Milestone 3 and 4 items are deliberately not here.

| # | Item | Needs from you | Size |
|---|------|----------------|------|
| 1 | Pin third-party actions to commits; automate dependency updates | nothing | S |
| 2 | Listing cost: bulk checkpoint read, pagination on `list_*` | API shape sign-off | M |
| 3 | ABI compatibility tests and semantic versioning policy | ADR sign-off | M |
| 4 | Build attestations for the release archives | nothing | S |
| 5 | Software bill of materials per release | nothing | S |
| 6 | `backup` / `restore` | format decisions (below) | L |
| 7 | Manual validation of the OS-keyring path (macOS, Linux desktop) | a Mac and a Linux desktop session | S |
| 8 | Signed and notarised macOS binaries; Authenticode Windows binaries | **Deferred** until adoption justifies the cost | — |
| 9 | Package managers: Homebrew, WinGet, Scoop | two small repos; one PAT | M |

Order: 1 first (it touches every workflow the later items edit), then
2–6 in any order (pure engineering, no accounts), then 7 and 9 which wait
on things only you can supply. 8 is deferred; nothing depends on it. The
only effect is that Windows users of the WinGet and Scoop packages see a
SmartScreen prompt on first run, which item 9's docs explain.

Every PR: `cargo fmt --all`, `cargo clippy --workspace --all-targets --
-D warnings`, `cargo test --workspace`; new CI jobs get `needs: changes`,
the shared `if:`, and a line in the `ci` gate's `needs:` list; docs in
`docs/` updated in the same PR; a `[Unreleased]` entry in `CHANGELOG.md`;
the roadmap box ticked.

---

## 1. Pin third-party actions; automated dependency updates

**Why first.** Items 3, 4, 5, 8 and 9 all edit `release.yml` and `ci.yml`;
pinning afterwards means touching the same lines twice.

**Current state.** About twenty distinct third-party actions across
`ci.yml`, `release.yml`, `ReleasePackages.yaml`, `docs.yml`, the Azure SWA
workflow and `.github/actions/sdk-fixture/action.yml`, all referenced by
tag (`@v4`, `@stable`, `@release/v1`). `ReleasePackages.yaml` still has
one `actions/checkout@v3`. No `.github/dependabot.yml`.

**Steps.**

- [x] Pin every `uses:` to a full commit SHA with the version as a trailing
      comment (`uses: actions/checkout@<sha> # v4.2.2`). `pinact run` or
      `frizbee` does the whole tree in one pass; check the diff by hand
      for `dtolnay/rust-toolchain@stable` (pin the action's commit, keep
      `stable` as the toolchain input) and `pypa/gh-action-pypi-publish`
      (pin the commit behind `release/v1`). Bump the stray `checkout@v3`.
- [x] Add `.github/dependabot.yml`, weekly, one grouped PR per ecosystem
      (minor and patch grouped; majors separate):
      `github-actions` (`/`), `cargo` (`/`, `/bindings/python`,
      `/bindings/node`; `versioning-strategy: lockfile-only` so the ranges
      in `Cargo.toml` stay as written), `npm` (`/bindings/node`, `/site`),
      `pip` (`/bindings/python`), `nuget` (`/bindings/dotnet`), `maven`
      (`/bindings/java`), `gomod` (`/bindings/go`), `composer` (`/`).
      Dependabot keeps SHA-pinned actions current and preserves the
      version comment, so pinning does not freeze the workflows.
- [x] Optional, recommended: a `workflows-lint` CI job running `zizmor`
      over `.github/`, which fails on an unpinned action and on the common
      workflow injection patterns; add it to the gate.
- [x] Docs: drop the "referred to by version tag" bullet from
      `docs/supply-chain.md` *Not done yet* and describe the pin policy
      under *From commit to package*; one paragraph in `CONTRIBUTING.md`
      on how a pinned action is updated (Dependabot PR, or by hand with
      the comment kept).
- [x] Tick the roadmap box.

---

## 2. Listing cost: bulk checkpoint read and pagination

**Current state.** `list_properties_of_secrets` and `list_deleted_secrets`
(`crates/sourceorrery-storage/src/sqlite/mod.rs`) call `candidate_names`
(one scan of every keyed state checkpoint in `audit_events`), then for
each name `load_secret_row` (one `secrets` query plus `read_checkpoints`,
a per-name scan of `audit_events`) and `newest_props` → `load_versions`
(one `secret_versions` query plus the same `read_checkpoints` again). That
is roughly 2N+1 scans of the audit table and 2N row queries for N
secrets, each checkpoint row authenticated several times.

**Design.**

*Bulk read (storage only, no API change).*

- [x] `audit::vault_checkpoints(conn, key, vault_id) -> BTreeMap<String,
      SecretCheckpoints>`: one query over every keyed checkpoint row
      ordered by id, each row authenticated once, folded per name with
      the same rules as `secret_checkpoints` (an `Absent` state clears the
      versions). `checkpointed_names` becomes a view over it.
- [x] One query for every `secrets` row and one for every
      `secret_versions` row (`query_raw_versions` without the name
      filter), grouped by name.
- [x] `load_secret_row` / `load_versions` take the checkpoints as a
      parameter (or get `_with(&SecretCheckpoints)` siblings) so the
      listing paths use the maps while the single-secret paths keep
      their per-name queries. Refusal semantics stay identical: every
      candidate name is visited; a row the chain records but the table
      lacks, and a row with no or a stale checkpoint, still fail the whole
      listing with `crypto`. The security tests
      (`secret_row_removed_out_of_band_is_rejected_not_not_found`,
      `version_row_removed_out_of_band_is_rejected`,
      `forged_checkpoint_rows_do_not_count`, the replay set) already cover
      this and must stay green unchanged.
- [x] A benchmark-shaped test in `tests/conformance/tests/lifecycle.rs`:
      a vault with 200 secrets × 5 versions lists in a bounded number of
      SQL statements (count via `rusqlite` trace hook, or assert on a
      `SqliteVault` statement counter behind `cfg(test)`), so the
      regression is caught rather than felt.

*Pagination (core API change, conformance test).*

- [x] In `sourceorrery-core`: `ListOptions { max_results: Option<usize>,
      continuation: Option<ContinuationToken> }` and
      `Page<T> { items: Vec<T>, continuation: Option<ContinuationToken> }`.
      `ContinuationToken` is an opaque string: the last name on the page
      (names are already a sorted `BTreeSet`), so a page is stable across
      concurrent writes (no duplicates, no skips of names outside the
      window; a name created or deleted during paging appears or not
      according to where its name sorts, which the docs say).
- [x] Add `list_properties_of_secrets_page(&self, ListOptions) ->
      Result<Page<SecretProperties>>` and `list_deleted_secrets_page` to
      `SecretClient` with default implementations that call the full list
      and slice, so every implementor keeps compiling; the SQLite backend
      overrides them to bound work to the names in the window
      (`WHERE name > ?1 ORDER BY name LIMIT ?2` on `secrets`, and the
      checkpoint map filtered the same way). Versions of one secret are
      not paginated: which version is newest is only decidable against
      the complete set.
- [x] Audit: one `secret_list` event per page call, documented in
      `docs/architecture.md` and `docs/vault-format.md`.
- [x] Conformance tests: paging with `max_results` 1, 7 and `None` yields
      exactly the full list in order with no duplicates and ends with
      `continuation == None`; a tampered row on page 3 is refused when
      page 3 is read; an invalid token is `invalid_argument`.
- [x] Surfaces: `secret list` and `secret list --deleted` gain
      `--limit N` and `--after NAME` (JSON output carries
      `continuation`); the `ui` keeps one full read on first show (the
      browser's read-once rule) but `MetadataSource::secrets` may switch to
      the paged call internally only if the audit event count per screen
      stays one. The read-only SDKs and `so_reader_*` have no listing and
      are untouched (ADR 0005). `so_secret_list` / `so_secret_list_deleted`
      (tooling ABI) are unchanged; add `so_secret_list_page` only if a
      tool needs it (not required to tick the box).
- [x] Docs: `docs/cli.md` secret table, `docs/architecture.md` listing
      semantics, `docs/vault-format.md` note on listing cost, remove the
      roadmap paragraph and tick the box.

**Decision for you.** Default implementations on the trait (keeps the
trait additive, recommended) versus changing the existing `list_*`
signatures to take `ListOptions` (cleaner, breaks every implementor,
still fine pre-1.0). The plan assumes the first.

---

## 3. ABI compatibility tests and semantic versioning policy

**Current state.** `SO_ABI_VERSION = 1` and `CONTRACT_VERSION = "1"`
exist and are exported; `bindings/README.md` says the ABI version is
bumped only for incompatible changes. CI diffs the generated header
against the committed one and against `bindings/go/sourceorrery.h`, which
catches drift, not incompatibility. The Go, Java, .NET and PHP bindings
expose `so_abi_version()` but none refuses a library whose ABI version is
not the one it was compiled against. There is no written policy for what
a version number promises.

**Steps.**

- [ ] **ADR 0007: Versioning and compatibility.** One release version for
      everything (already how the release workflow works). What SemVer
      covers, per surface: the CLI (commands, flags, JSON output), the
      `sourceorrery` crate and `sourceorrery-core` public API, each SDK's
      public API, the C ABI (`SO_ABI_VERSION`: additions never bump it,
      any change to an existing declaration does), `CONTRACT_VERSION`
      (semantics of the contract, bumped with a conformance change that
      an old client could observe), the vault file (`schema_version`,
      migration is explicit and one-way), error codes and audit operation
      names (append-only), the manifest format. Pre-1.0 rule: a minor
      release may break, a patch never does; from 1.0 the usual rule.
      Deprecation: one minor release of warning before removal. Record
      how `Cargo.toml` `version` requirements of the internal crates are
      kept in lockstep (`set-version.py` already does it).
- [ ] **Load-time check in the C-ABI bindings.** Go, Java, .NET, PHP and
      the C++ header compare `so_abi_version()` with the constant they
      were built against on first use and fail with a typed error naming
      both numbers. One scenario in `tests/conformance/sdk/scenarios.json`
      cannot exercise a mismatch without a second library, so cover it
      with a unit test per binding that stubs the native call where the
      language allows (Java, .NET, Go) and a doc note elsewhere.
- [ ] **Declaration-level ABI check in CI.** `scripts/ci/abi-check.py`
      parses function prototypes, struct fields and enum values out of
      two headers and fails when an existing declaration changed or
      disappeared while `SO_ABI_VERSION` stayed the same. Baseline: the
      header from the latest `v*` tag (`git show <tag>:crates/sourceorrery-ffi/include/sourceorrery.h`),
      so no second file is committed. Runs in the existing `ffi-header`
      job.
- [ ] **Previous-release contract against the current library.** New CI
      job `abi-compat` (Linux is enough): check out the latest `v*` tag
      into a worktree, build its `bindings/c/examples/conformance.c`
      against *its* header, run it with *its* `harness.py` and
      `scenarios.json` against the *current* `libsourceorrery_ffi.so`
      (built in-job) and the fixture vault. The old contract must pass on
      the new library while the ABI version is unchanged; when the version
      is bumped the job asserts the old runner refuses to load instead.
      Skip the job while no tag with the same ABI version exists.
- [ ] **Rust API check.** `cargo semver-checks` on `sourceorrery` and
      `sourceorrery-core` against the crates.io baseline
      (`obi1kenobi/cargo-semver-checks-action`), in a job added to the
      gate. Pre-1.0 it treats a minor bump as the major boundary, which
      matches the ADR.
- [ ] Docs: `bindings/README.md` *Versioning* points at the ADR;
      `docs/sdks/index.md` gains a *Compatibility* paragraph;
      `docs/release.md` step 1 asks whether the ABI or contract version
      must move; tick the box.

---

## 4. Build attestations for the release archives

**Current state.** `SHA256SUMS` only. npm and PyPI carry Sigstore
provenance; the archives, jar, nupkg and npm tarballs on the release page
carry nothing that proves which workflow run built them.

**Steps.**

- [ ] In the `release` job of `release.yml`, after *Flatten and checksum*
      and only when `publish == 'true'`: `actions/attest-build-provenance`
      over `release/*` (every archive, wheel, sdist, npm tarball, jar,
      nupkg and `SHA256SUMS` itself). Job permissions gain
      `id-token: write` and `attestations: write`. Attestations are keyed
      by digest and published to the repository's attestation store and
      the Sigstore log, so a dry run must not create them.
- [ ] Verification as the user sees it:
      `gh attestation verify sourceorrery-X.Y.Z-<target>.tar.gz --repo Netizine/sourceorrery`
      (or `--owner Netizine`). Add it to `docs/supply-chain.md` *Release
      archives*, to *Verifying a release* in `docs/release.md`, and to the
      release notes table in `release.yml`.
- [ ] `ReleasePackages.yaml` uploads files the release already has; no
      change, but say so in `docs/release.md`.
- [ ] State the claim precisely: provenance ties a file to a commit and a
      workflow run on a GitHub-hosted runner. No reproducible-build claim.
      Update the *Not done yet* warning accordingly and tick the box.

---

## 5. Software bill of materials per release

**Steps.**

- [ ] Build the CLI and the C ABI with `cargo auditable build` in the
      `native` job (one extra `cargo install cargo-auditable --locked`,
      cached). The binaries then embed their dependency list, which
      `cargo audit bin <binary>` and syft read; this is cheap and useful
      on its own.
- [ ] One CycloneDX SBOM per native archive:
      `cargo cyclonedx --manifest-path crates/sourceorrery-cli/Cargo.toml --target <triple> --format json`
      and the same for `sourceorrery-ffi`, renamed
      `sourceorrery-X.Y.Z-<target>.cdx.json` and
      `sourceorrery-ffi-X.Y.Z-<target>.cdx.json`, uploaded with the
      archives so they land in `release/` and in `SHA256SUMS`.
- [ ] SDK packages, where the ecosystem tool is a one-liner: Node
      (`@cyclonedx/cyclonedx-npm` in `node-package`), Java
      (`cyclonedx-maven-plugin` in the `java` job), .NET (`dotnet CycloneDX`
      in `dotnet`). Python and the Rust crates are covered by the Cargo
      SBOM (no runtime dependencies of their own). Go and PHP ship no
      binary of their own.
- [ ] `actions/attest-sbom` for each SBOM next to item 4's provenance,
      so the SBOM is bound to the artefact it describes.
- [ ] Docs: a *Software bill of materials* section in
      `docs/supply-chain.md` (what is in each file, how to read it,
      `cargo audit bin`), the release notes table, and the roadmap tick.

---

## 6. `backup` / `restore`: encrypted export of a vault or a secret

**Why it is more than a file copy.** The vault file is already encrypted
per value under the vault key, but that key is wrapped by protectors, and
an OS-keyring protector does not travel to another machine. A backup must
open anywhere with only a passphrase, must never contain a plaintext
value, and a restore must not bypass the integrity rules that make the
audit chain trustworthy.

**Design (recommended).**

*Format.* One file, `*.sobackup`: a small cleartext header (magic, format
version 1, source vault name and id, created-on, Argon2id parameters,
salt, nonce) followed by one XChaCha20-Poly1305 ciphertext whose AAD is
the canonical header. The key is derived from a passphrase prompted twice
(never a CLI argument; `SOURCEORRERY_BACKUP_PASSPHRASE` for scripts,
documented with the same warnings as `SOURCEORRERY_PASSPHRASE`), with the
protector `Argon2Params` (tests use `TESTING`). The plaintext is a
canonical encoding of: for each secret, its properties and every version
(id, created_on, enabled, content type, tags, time window) with the
version's value; optionally the deleted secrets with their
`deleted_on` / `scheduled_purge_on`. No audit rows: the audit log is the
file's history, not the data, and restoring one would need the chain to
be rewritten. Spec goes in a new `docs/backup-format.md`, linked from
`docs/vault-format.md`.

*Where the code lives.* The encoder and decoder live in
`sourceorrery-storage` (it holds the keys and already has `rows.rs`
reading ciphertext per version); crypto wrappers in `sourceorrery-crypto`
(`backup_seal` / `backup_open` over the existing AEAD and KDF wrappers, no
new algorithm). Values move only as `SecretBytes`: the encoder writes
each value's bytes from `expose_secret` into a zeroizing buffer, and the
decoder hands each value straight to `set_secret`. `SecretBytes` gains no
`Serialize`; the backup types that *are* serialised (header, manifest of
names and versions) never hold a value. The CLI is the only consumer: no
FFI, no SDK (ADR 0005).

*Contract in core.* New trait `VaultBackup` (`sourceorrery-core`,
implemented by `SqliteVault`): `export(&self, ExportOptions) ->
Result<Snapshot>` and `restore(&self, Snapshot, RestoreOptions) ->
Result<RestoreReport>`, with `Snapshot` an opaque in-memory type whose
`Debug` is redacted. `ExportOptions { secrets: Option<Vec<String>>,
include_deleted: bool }`. Export reads every version's value regardless of
policy (disabled and expired versions are part of a backup), which is a
new privileged read, so it is a separate trait and a separate audit
operation rather than a `get_secret` variant.

*Restore semantics.* Through the normal write path, never by inserting
rows: each version becomes a new version in the target vault via the
storage write functions, keeping the original metadata (tags, content
type, enabled, window) and recording the source version id and created-on
in reserved tags (`sourceorrery.restored-from`, `sourceorrery.restored-created-on`),
following the `imported-from` precedent. The target may be the same vault
name or `--as NAME`. A name that already exists is skipped by default and
reported; `--overwrite` adds the versions on top (mirrors `import`). A
backup of a deleted secret restores as live unless `--keep-deleted`
soft-deletes it after restore. Every restored version is one keyed,
checkpointed `secret_restore` audit event; the export is one
`vault_backup` event per secret exported (name only). Both operation names
are appended to the audit operation list, which is append-only.

**Steps.**

- [ ] `sourceorrery-crypto`: `backup_seal` / `backup_open`, tests with
      canary bytes.
- [ ] `sourceorrery-core`: `VaultBackup` trait, options and report types,
      `AuditOperation::{VaultBackup, SecretRestore}`, new error codes only
      if a refusal has no existing code (`backup_passphrase` for a wrong
      passphrase, distinct from a vault unlock failure; `backup_format`
      for a file from a newer format version).
- [ ] `sourceorrery-storage`: `backup.rs` with the encoder, the decoder,
      and the privileged version-value read (one ciphertext row per
      version, as `get` does today).
- [ ] CLI: `sourceorrery backup --out FILE [--secret NAME]...
      [--include-deleted]` and `sourceorrery restore FILE [--as NAME]
      [--only NAME]... [--overwrite] [--keep-deleted] [--dry-run]`, `-o
      json` reports names and counts only. `backup` refuses to write over
      an existing file without `--force`; `restore --dry-run` lists what
      would be created.
- [ ] Conformance tests (`tests/conformance/tests/lifecycle.rs` and
      `security.rs`): round trip preserves names, version order, metadata
      and values; the backup file never contains a plaintext value or the
      passphrase (canary); wrong passphrase refused and not retried;
      flipped byte anywhere refused; a backup from a newer format version
      refused cleanly; restore into an existing name skips without
      `--overwrite`; every operation leaves exactly the expected audit
      events, with no value in them; `Debug` of `Snapshot` is redacted.
- [ ] Docs: `docs/cli.md` (new section, and point the three "restore from
      a backup" sentences in the truncation section at the command),
      `docs/backup-format.md`, `docs/threat-model.md` (a backup file is as
      sensitive as the vault; the passphrase is the only protection),
      `docs/architecture.md` (the trait), `docs/vault-format.md` link,
      tick the box.

**Decisions for you.** (a) Restore through the write path with new
version ids (recommended, keeps every integrity invariant) versus
preserving original version ids and timestamps (needs a privileged row
insert that bypasses `set_secret` and a new checkpoint rule). (b) Whether
`backup` without `--secret` includes deleted secrets by default (the plan
says no). (c) Command placement: top-level `backup`/`restore` as the
roadmap words it, or under `vault`.

---

## 7. Manual validation of the OS-keyring path on macOS and a Linux desktop

**Current state.** CI builds with and without the `os-keyring` feature and
tests the passphrase path everywhere; `docs/threat-model.md` item 10 says
the keyring path has not been validated on macOS or a Linux desktop.
Windows is done.

**Steps.**

- [ ] `scripts/dev/keyring-smoke.sh` (and `.ps1` for parity): with an
      isolated `SOURCEORRERY_HOME`, create a vault with the `os-keyring`
      protector, `secret set` and `get --reveal` round trip, `vault
      protector list` shows `os-keyring`, a second process opens the vault
      without a prompt, `vault protector add --kind passphrase` then
      `remove` the keyring protector deletes the entry (check with
      `security find-generic-password -s sourceorrery` on macOS and
      `secret-tool search service sourceorrery` on Linux), `vault destroy`
      removes the entry and `--keep-os-key` keeps it, and a copied vault
      file makes `destroy` keep and report the shared entry. Each step
      prints PASS or FAIL; no value is printed except the round-trip
      canary the script itself set.
- [ ] You run it: once on a Mac (Keychain), once in a GNOME or KDE
      session (Secret Service through GNOME Keyring or KWallet; also note
      the behaviour when the session keyring is locked), and record the
      OS and desktop versions.
- [ ] Optional, recommended: a CI job `keyring` that runs the same script
      on `macos-latest` (create and unlock a temporary keychain with
      `security create-keychain` / `unlock-keychain` / `set-keychain-settings`)
      and on `ubuntu-latest` under `dbus-run-session -- sh -c 'gnome-keyring-daemon --unlock ...'`.
      It is not a desktop session, so it complements rather than replaces
      the manual run, but it keeps the path from rotting.
- [ ] Docs: `docs/threat-model.md` item 10 becomes "validated on <OS
      versions>; CI exercises the path headlessly"; `docs/building.md` or
      `CONTRIBUTING.md` names the script; tick the box.

---

## 8. Deferred: signed and notarised macOS binaries; Authenticode Windows binaries

**Deferred** until the project has enough adoption to justify the cost.
Apple has no free path (Developer Program, USD 99 a year). Windows has one
free option for open source, SignPath Foundation (application and review),
and a cheap one, Azure Trusted Signing (about USD 10 a month, publisher
identity validation). Nothing else in this plan depends on signing.

While it stays deferred:

- The roadmap box stays unchecked and the warning in
  `docs/supply-chain.md` *Not done yet* keeps its signing clause.
- Items 4 and 5 give users something to check instead: the attestation
  (`gh attestation verify`) proves which workflow run built an archive,
  which is stronger evidence of origin than a code-signing certificate,
  just not something Gatekeeper or SmartScreen read.
- Item 9's install docs say what the unsigned-binary prompt looks like on
  Windows (SmartScreen: *More info → Run anyway*) and on macOS for a
  browser download (Gatekeeper; `curl`, Homebrew, Scoop and WinGet do
  not set the quarantine attribute, so scripted installs are not
  affected).

Revisit when adoption warrants it; the steps below are what it takes.

**What you need to obtain first.**

- Apple: Developer Program membership, a *Developer ID Application*
  certificate exported as `.p12`, and an App Store Connect API key for
  `notarytool`. Secrets: `APPLE_CERTIFICATE_P12` (base64),
  `APPLE_CERTIFICATE_PASSWORD`, `APPLE_API_KEY_ID`, `APPLE_API_ISSUER_ID`,
  `APPLE_API_KEY_P8`.
- Windows, pick one: **Azure Trusted Signing** (the project already runs
  on Azure; cheapest; needs identity validation of the publisher) or
  **SignPath Foundation** (free for open source, approval by application;
  signing runs through their service). Both avoid a certificate file in
  the repository secrets. A classic OV certificate on a hardware token
  does not fit a hosted runner.

**Steps.**

- [ ] `native` job, macOS runners, after *Build* and before *Package*:
      import the certificate into a temporary keychain; `codesign --force
      --timestamp --options runtime --sign "Developer ID Application: …"`
      the `sourceorrery` binary and `libsourceorrery_ffi.dylib`;
      `xcrun notarytool submit --wait` a zip of each; verify with
      `codesign --verify --strict` and `spctl --assess --type execute`.
      Stapling does not apply to bare binaries; Gatekeeper checks the
      notarisation ticket online, which the docs say. The same signed
      dylib is what goes into `dist/native` and `dist/jni`, so the jar
      and the nupkg ship signed libraries too.
- [ ] `native` job, Windows runners: sign `sourceorrery.exe`,
      `sourceorrery_ffi.dll` with the chosen provider's action before
      `Compress-Archive`; verify with `Get-AuthenticodeSignature`.
- [ ] Both steps run only when their secrets exist (the Maven pattern:
      skipped, not failed) and are skipped in a dry run unless a new
      `sign` input is ticked, so a dry run can rehearse signing without
      publishing.
- [ ] Out of scope for the first cut, stated in the docs: the Python
      wheel's extension (`maturin` job) and the Node addon (`node-build`)
      are separate builds; sign them in a follow-up once the native job's
      steps are proven.
- [ ] Docs: `docs/release.md` secrets table and procedure;
      `docs/supply-chain.md` *Release archives* with the verification
      commands and the signer identity to expect; remove the *Not done
      yet* bullet and the warning's clause; tick the box.

Until then, the "signed binaries" bullet in *Not done yet* stays and the
roadmap keeps the box open.

---

## 9. Package managers: Homebrew, WinGet, Scoop

**Approach.** Our own tap and bucket (homebrew-core and the main Scoop
buckets have notability thresholds and review queues; a tap and a bucket
ship today and can be promoted later). WinGet has one community
repository, `microsoft/winget-pkgs`, fed by pull request.

**What you need to create.** Repositories `Netizine/homebrew-sourceorrery`
and `Netizine/scoop-sourceorrery`; a fine-grained PAT (or a GitHub App
installation token) that can push to both and open PRs against a fork of
`microsoft/winget-pkgs`, stored as `PACKAGING_TOKEN`; a one-time
`wingetcreate new` submission of `Netizine.SourceOrrery` so later
releases are updates.

**Steps.**

- [x] `scripts/release/package-managers.py`: from the version and
      `SHA256SUMS`, render `Formula/sourceorrery.rb` (per-target URLs and
      sha256 for the four macOS/Linux archives, `bin.install`, shell
      completions from `sourceorrery completions`), and
      `bucket/sourceorrery.json` (x64 and arm64 zips, `bin`,
      `checkver`/`autoupdate` against GitHub releases). Unit-tested
      against a fixture `SHA256SUMS`.
- [x] Release job `publish-package-managers`, after `release`, real
      releases only, skipped while `PACKAGING_TOKEN` is absent: commit the
      formula to the tap and the manifest to the bucket; `wingetcreate
      update Netizine.SourceOrrery --version X.Y.Z --urls <x64 zip> <arm64
      zip> --submit` (installer type `zip`, nested `portable`). Add the
      job to `ReleasePackages.yaml` with its own tick box so an existing
      release can be packaged later.
- [x] Smoke test in the same job: `brew install --build-from-source` the
      rendered formula on the macOS runner (or `brew audit --strict`),
      `scoop install` from the local manifest on Windows. Dry run renders
      and audits, uploads nothing.
- [x] Docs: `site/src/content/docs/getting-started.mdx` gains the three
      one-liners above the archive tabs and drops the roadmap sentence,
      plus one line on the SmartScreen prompt Windows users see while the
      binaries are unsigned (item 8 deferred) and how to check the
      download instead (`SHA256SUMS`, `gh attestation verify`);
      `docs/release.md` secrets table, procedure and the
      *Publishing an existing release* list; `docs/supply-chain.md` table
      rows for the three (what each verifies: the formula's and the
      manifest's sha256 against the release, WinGet's own hash check);
      tick the box.

---

## Closing out

- [ ] `docs/roadmap.md`: eight boxes ticked, the signing item kept open
      with a one-line note that it waits on adoption, header re-targeted
      at 0.2.0 and the "release scope" section rewritten for it.
- [ ] `docs/supply-chain.md`: *Not done yet* reduced to Maven Central's
      stored token, unsigned binaries, and the absence of a
      reproducible-build claim.
- [ ] `docs/threat-model.md` item 10 rewritten (item 7 above).
- [ ] `CHANGELOG.md` `[Unreleased]` → `[0.2.0]`; release per
      `docs/release.md`, dry run first; then the install links in
      `getting-started.mdx`, `docs/sdks/*.md`, `docs/building.md` and
      `docs/supply-chain.md` move to 0.2.0.
- [ ] Milestone 3 starts from a clean roadmap.
