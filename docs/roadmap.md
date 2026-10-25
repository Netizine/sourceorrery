# Roadmap

The [**0.2.0 release**](https://github.com/Netizine/sourceorrery/releases/tag/v0.2.0) includes the encrypted local vault,
CLI and read-only SDKs, guided setup, `.env` import, agent integrations,
and optional AWS Secrets Manager and HashiCorp Vault providers
([release scope](#release-020)). The next release reworks how a vault is
opened, checked and where it keeps secrets
([ADR 0009](#next-release-local-vaults-one-set-of-checks-storage-per-secret)).
Checked items below are implemented; unchecked items remain planned.

> [!IMPORTANT]
> The authenticated local broker remains milestone 3. SourceOrrery
> does not yet isolate secrets from processes running with the same user's
> credentials. See the [threat model](threat-model.md).

## Milestone 1 — core and local CLI

- [x] Secret contracts (`SecretClient`), stable error codes, naming rules
- [x] Enforced policy: enabled, `not_before`, `expires_on`; latest-accessible selection
- [x] Encrypted SQLite vault; per-value AEAD bound to vault/name/version
- [x] Key wraps: this machine's key in the OS credential store (Windows/macOS/Linux) and one recovery key, shown once, that opens the vault anywhere else
- [x] Versions, soft delete, recovery, purge, retention with automatic purge
- [x] Metadata-only audit log, including failed unlocks
- [x] CLI: `vault`, `secret`, `audit`, `init`, `check`, `run`, `completions`
- [x] Vault manager `sourceorrery ui` (Ratatui, `ui` feature, on by default)
  - [x] Groundwork: the command, the value-free `MetadataSource` seam, a secret list with keyboard navigation
  - [x] Read-only browser: vault picker, search over names/tags/status, secret detail with versions, deleted secrets, audit log, audit-only mode for a vault blocked by a truncation
  - [x] Dashboards (status counts, expiry timeline, audit activity, chain verification), idle auto-lock, switching vaults
  - [x] Metadata changes behind confirmations (enable/disable, tags, content type, time window, delete/recover; new versions through the hidden prompt), through a separate write-capable interface
- [x] Value-free manifest `sourceorrery.toml`; `sourceorrery://` references
- [x] Conformance + security suites; CI on Ubuntu/Windows/macOS; release workflow
- [ ] Manual validation of the OS-keyring path on macOS and a Linux desktop: `scripts/dev/keyring-smoke.sh` is the check, CI runs it headlessly on all three platforms (`keyring` job); the desktop-session runs remain to be done and recorded in the threat model
- [x] Metadata and audit-log integrity (MAC over mutable metadata)
- [x] Reads load only the value they return (metadata projection for every version query; one ciphertext row per `get`)
- [x] Listing cost: one scan of the checkpoint rows and one statement each over the names, rows and versions of a listing window, and `list_*_page` with a name-based continuation token in core, with conformance tests (`secret list --limit N --after NAME`)
- [x] `vault export` / `vault import`: a copy of a vault that opens with its recovery key only, brought onto another machine
- [x] Pre-built CLI archives for six targets on the GitHub release, with `SHA256SUMS`
- [x] Cargo installation of the CLI (`cargo install --locked sourceorrery-cli --version 0.2.0`)
- [x] Package managers: Homebrew and Scoop; the [WinGet submission](https://github.com/microsoft/winget-pkgs/pull/460455) awaits catalog approval
- [x] Docs site at sourceorrery.ai (Astro Starlight) from `docs/`, deployed by Azure Static Web Apps

## Milestone 2 — first-class language bindings

- [x] `sourceorrery-ffi`: stable C ABI (`cbindgen`), versioned `CONTRACT_VERSION`
- [x] Read-only `so_reader_*` / `so_project_*` ABI and the `sourceorrery` client crate (unlock order, manifest loading, error hints)
- [x] Read-only SDKs: Python (PyPI, maturin), JavaScript/TypeScript (npm, napi-rs), Rust (crates.io), Java (Maven Central, FFM), .NET (NuGet, LibraryImport), Go (cgo), C, C++ (header-only), PHP (Packagist, FFI); each tested and its example run in CI on Ubuntu/Windows/macOS against a vault the CLI creates
- [x] Manual release workflow: GitHub Release with checksums, registry publish jobs skipped until their secrets exist, dry-run mode
- [x] Scoped value accessors (`with` / `using` / `try-with-resources` / `defer` / RAII / `Use(span)`) in every SDK
- [x] Cross-language conformance harness: `tests/conformance/sdk/scenarios.json` + `harness.py` drive a runner per SDK through the same scenarios in every SDK CI job
- [x] Registry publication: PyPI, npm (`@sourceorreryai`), crates.io, Maven Central, NuGet, Packagist and pkg.go.dev
- [x] The npm main tarball on the release page carries the generated loader (`index.js`)
- [x] ABI compatibility tests and semantic versioning policy ([ADR 0007](adr/0007-versioning-and-compatibility.md): the header is compared with the previous release's, that release's C runner is run against the current library, every C-ABI binding refuses a mismatched library, and the release checks the Rust API against crates.io)

### Supply chain

How each package is published and how to check it: [Supply chain](supply-chain.md).

- [x] One manual release workflow builds every package from one commit; locked dependencies; `cargo audit` in the CI gate; `SHA256SUMS` on every release
- [x] npm by trusted publishing, with Sigstore provenance on every package
- [x] NuGet by trusted publishing
- [x] Maven Central artefacts signed with the release key
- [x] Build attestations for every file on the GitHub Release (`gh attestation verify`)
- [ ] Signed and notarised macOS binaries; Authenticode-signed Windows binaries
- [x] Third-party GitHub Actions pinned to commits; automated dependency updates
- [x] Software bill of materials for each release (CycloneDX per shipped binary and target, `cargo auditable` binaries)

## Release: 0.1.4

The 0.1.4 build includes these changes alongside milestones 1 and 2:

- [x] `sourceorrery import <file>`: a `.env` file into a vault and its keys into `sourceorrery.toml`, printing key names and line numbers only, never a value ([CLI reference](cli.md#import-moving-a-env-file-into-a-vault))
- [x] Skills for AI coding agents (`sourceorrery`, `sourceorrery-migrate-env`) that install SourceOrrery, import the `.env` files and convert the code that reads them without the agent seeing a value; `sourceorrery init --integration <agent>` writes them from the binary, with no download, for twelve agents; `integrations/` and a Claude Code plugin marketplace carry the same files ([AI coding agents](ai-agents.md))
- [x] A vault is only served under its own name: a file renamed, copied or swapped in from another vault is refused with `vault_mismatch` by the CLI, `ui`, the C ABI and every SDK, each with a typed error that the SDK conformance harness checks
- [x] PyPI and crates.io by trusted publishing (no stored token), with PyPI attestations
- [x] Every registry page says what its package is, that vaults are managed with the CLI, and where the documentation is; each release archive carries a README

## Release: 0.2.0

Alongside the 0.1.4 features above, this build includes remote providers
(milestone 4 below), encrypted backup and restore, paged listings, ABI
compatibility checks, release provenance and software bills of materials,
and multi-language coverage reports for SonarCloud. The full release
published the three new provider crates with a temporary credential while
existing crates used trusted publishing; all packages use **0.2.0**.
Configure the providers' trusted publishers afterward and revoke the
temporary credential. Enabling trusted publishing does not require another
release; see the [release procedure](release.md).

## Next release: local vaults, one set of checks, storage per secret

[ADR 0009](adr/0009-local-vaults-checks-and-storage.md). Vaults from earlier
releases are not read: recreate them and set their secrets again.

- [x] A vault opens with this machine's key in the OS credential store, else its recovery key (`SOURCEORRERY_RECOVERY_KEY`, `--recovery-key-file`, a prompt); passphrases, protectors and recovery codes are gone
- [x] The view check: an optional password (rated as it is typed, or generated) with a hint and an authenticator code on top, asked before anyone views the vault or reveals a value; `run`, `check`, `init` and the SDKs never ask it ([CLI reference](cli.md#the-view-check), [threat model](threat-model.md))
- [x] Storage per secret: the vault file, or HashiCorp Vault, AWS Secrets Manager or Azure Key Vault through a connection the vault holds (credentials from the provider's own sign-in or sealed in the vault); the manifest names no provider ([providers](providers/index.md))
- [x] `sourceorrery setup` and `vault create [NAME]`: one set of screens that creates a vault or changes one (view check, recovery key, storage, connections with a test), committed in one transaction at its review; `setup --guide` prints the one command that does it without the screens ([First run](getting-started.md))
- [x] `sourceorrery init`: the manifest written from the vault's secrets by name, with its own screens (All, a loop adding new secrets), adding to an existing manifest in place, and the folder recorded in the vault
- [x] The `ui` browser: storage and projects columns, a Projects view with a check on disk, new secrets in a chosen storage, the setup screens from inside it
- [x] `vault export` / `vault import` replace `backup` / `restore`
- [x] The settings record checkpointed on the audit chain: an older authentic copy of it (from before a view check was set or a connection changed) is refused like an older row ([threat model](threat-model.md), gap 6; [vault format](vault-format.md#the-settings-record))

## Milestone 3 — local broker and agent isolation

- [ ] Authenticated local protocol over Unix sockets / named pipes (length-prefixed, versioned)
- [ ] Capability-based authorisation; short-lived, secret-scoped grants
- [ ] Verified workload identity where the OS can provide it; honest labelling where it cannot
- [ ] Agent-aware access profiles: no production secrets by default, scoped test credentials, lifetime limits
- [ ] Hostile same-user process and compromised-workspace test suite
- [ ] Security review before the broker is described as a boundary

## Milestone 4 — enterprise integrations

- [x] Azure Key Vault (`sourceorrery-provider-azure`, [docs](providers/azure-key-vault.md)), tested against LocalStack for Azure; not yet released
- [x] Remote providers behind the same contract: HashiCorp Vault (`sourceorrery-provider-vault`, [docs](providers/hashicorp-vault.md)) and AWS Secrets Manager (`sourceorrery-provider-aws`, [docs](providers/aws-secrets-manager.md)); no SourceOrrery server: the providers' own services are the only remote ends
- [x] `AsyncSecretClient` ([ADR 0008](adr/0008-remote-providers.md): the async shape of the contract in core, the `Blocking` and `AsyncLocal` adapters in `sourceorrery-provider`, and the lifecycle conformance suite as a function every backend runs)
- [x] Workload identity through the providers' federation (OIDC, workload and Kubernetes identities, instance roles); RBAC, policy and revocation administered in the provider and honoured by the client ([enterprise.md](enterprise.md); no SourceOrrery server, so nothing of ours to administer centrally)
- [x] Rotation workflows with issuer cooperation (issue → validate → activate → retire): `sourceorrery secret rotate` over any vault with per-version properties, the issuer's side as commands in the manifest's `[rotation.<name>]` table ([rotation.md](rotation.md))
- [x] Audit export: the local vault's chain as JSON Lines or OTLP log records, with the chain verification as a trailer, continuously with `--follow` (`sourceorrery audit export`); remote providers' trails located and documented, with the query that shows SourceOrrery's operations ([enterprise.md](enterprise.md#collecting-the-audit-trail))
- [ ] Security review before "enterprise-ready" (the maintainer's own review, done locally over several days; not an engineering item). The engineering pass that precedes it, with what it found and fixed, is [docs/security-review.md](security-review.md)

## Milestone 5 — community expansion

- [ ] Published C ABI specification and SDK templates
- [ ] Kotlin, Swift, Ruby, Dart, Elixir bindings via the harness (Java, Go and PHP shipped in milestone 2)
- [ ] Tier 2 platforms: musl, ARMv7; community: FreeBSD, OpenBSD
