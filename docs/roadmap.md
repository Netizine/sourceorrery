# Roadmap

This documentation targets **0.1.4**: the encrypted local vault, CLI,
read-only SDKs, `.env` import and skills for AI coding agents. The build
also refuses a vault file filed under another vault's name and uses trusted
publishing for PyPI and crates.io ([release scope](#release-014)). Checked
items below are implemented; unchecked items remain planned.

> [!IMPORTANT]
> The authenticated local broker is milestone 3, after 0.1.4. SourceOrrery
> does not yet isolate secrets from processes running with the same user's
> credentials. See the [threat model](threat-model.md).

## Milestone 1 — core and local CLI

- [x] Secret contracts (`SecretClient`), stable error codes, naming rules
- [x] Enforced policy: enabled, `not_before`, `expires_on`; latest-accessible selection
- [x] Encrypted SQLite vault; per-value AEAD bound to vault/name/version
- [x] Key protectors: OS credential store (Windows/macOS/Linux) and Argon2id passphrase; several per vault
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
- [x] `backup` / `restore`: an encrypted export of a vault or of named secrets, every version with its value, restored as new versions through the audited write path ([format](backup-format.md))
- [x] Pre-built CLI archives for six targets on the GitHub release, with `SHA256SUMS`
- [x] `cargo install --locked sourceorrery-cli --version 0.1.4`
- [x] Package managers: Homebrew, WinGet, Scoop
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

## Next release — onboarding, a strong passphrase and a second factor

- [x] `sourceorrery setup`: the guided first run, from a vault to `run`, as screens on the terminal, with the same six steps printed as commands where there is no terminal ([First run](getting-started.md))
- [x] A vault passphrase typed at a prompt must rate "good" on a rule-based strength estimate (`vault passphrase check`, `vault passphrase generate`); one from the environment or a file is warned about, not refused
- [x] Recovery codes (`vault recovery codes`) that unlock the vault in place of the passphrase, and a clear-text passphrase hint shown at the prompt; `vault passphrase set` to replace the passphrase with a code in hand
- [x] An authenticator app as a second factor (`vault 2fa`, RFC 6238, the secret sealed inside the vault, a code accepted once) and the reveal guard (`vault guard`): `secret get --reveal` and `backup` ask for the passphrase, a code or both again; `run`, `check` and the SDKs are untouched ([CLI reference](cli.md#the-reveal-guard), [threat model](threat-model.md))

## Milestone 3 — local broker and agent isolation

- [ ] Authenticated local protocol over Unix sockets / named pipes (length-prefixed, versioned)
- [ ] Capability-based authorisation; short-lived, secret-scoped grants
- [ ] Verified workload identity where the OS can provide it; honest labelling where it cannot
- [ ] Agent-aware access profiles: no production secrets by default, scoped test credentials, lifetime limits
- [ ] Hostile same-user process and compromised-workspace test suite
- [ ] Security review before the broker is described as a boundary

## Milestone 4 — enterprise integrations

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
