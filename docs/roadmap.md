# Roadmap

## Milestone 1 — core and local CLI *(shipped in 0.1.0)*

- [x] Secret contracts (`SecretClient`), stable error codes, naming rules
- [x] Enforced policy: enabled, `not_before`, `expires_on`; latest-accessible selection
- [x] Encrypted SQLite vault; per-value AEAD bound to vault/name/version
- [x] Key protectors: OS credential store (Windows/macOS/Linux) and Argon2id passphrase; several per vault
- [x] Versions, soft delete, recovery, purge, retention with automatic purge
- [x] Metadata-only audit log, including failed unlocks
- [x] CLI: `vault`, `secret`, `audit`, `init`, `check`, `run`, `completions`
- [ ] Vault manager `sourceorrery ui` (Ratatui, `ui` feature, on by default)
  - [x] Groundwork: the command, the value-free `MetadataSource` seam, a secret list with keyboard navigation
  - [x] Read-only browser: vault picker, search over names/tags/status, secret detail with versions, deleted secrets, audit log, audit-only mode for a vault blocked by a truncation
  - [x] Dashboards (status counts, expiry timeline, audit activity, chain verification), idle auto-lock, switching vaults
  - [x] Metadata changes behind confirmations (enable/disable, tags, content type, time window, delete/recover; new versions through the hidden prompt), through a separate write-capable interface
- [x] Value-free manifest `sourceorrery.toml`; `sourceorrery://` references
- [x] Conformance + security suites; CI on Ubuntu/Windows/macOS; release workflow
- [ ] Manual validation of the OS-keyring path on macOS and a Linux desktop
- [x] Metadata and audit-log integrity (MAC over mutable metadata)
- [x] Reads load only the value they return (metadata projection for every version query; one ciphertext row per `get`)
- [ ] Listing cost: `list` and `list-deleted` still verify every version row and every checkpoint row of every secret, one query per secret, because which version is newest can only be judged against the complete set. A bulk checkpoint read and pagination on `list_*` are open; pagination is an API change and goes through core with a conformance test
- [ ] `backup` / `restore` (encrypted export of a vault or a secret)
- [x] Pre-built CLI archives for six targets on the GitHub release, with `SHA256SUMS`
- [x] `cargo install sourceorrery-cli` (from 0.1.1)
- [ ] Package managers: Homebrew, WinGet, Scoop; signed releases
- [x] Docs site at sourceorrery.ai (Astro Starlight) from `docs/`, deployed by Azure Static Web Apps

## Milestone 2 — first-class language bindings *(shipped in 0.1.0)*

- [x] `sourceorrery-ffi`: stable C ABI (`cbindgen`), versioned `CONTRACT_VERSION`
- [x] Read-only `so_reader_*` / `so_project_*` ABI and the `sourceorrery` client crate (unlock order, manifest loading, error hints)
- [x] Read-only SDKs: Python (PyPI, maturin), JavaScript/TypeScript (npm, napi-rs), Rust (crates.io), Java (Maven Central, FFM), .NET (NuGet, LibraryImport), Go (cgo), C, C++ (header-only), PHP (Packagist, FFI); each tested and its example run in CI on Ubuntu/Windows/macOS against a vault the CLI creates
- [x] Manual release workflow: GitHub Release with checksums, registry publish jobs skipped until their secrets exist, dry-run mode
- [x] Scoped value accessors (`with` / `using` / `try-with-resources` / `defer` / RAII / `Use(span)`) in every SDK
- [x] Cross-language conformance harness: `tests/conformance/sdk/scenarios.json` + `harness.py` drive a runner per SDK through the same scenarios in every SDK CI job
- [x] Registry publication: PyPI, crates.io, Maven Central, NuGet (trusted publishing) and Packagist from 0.1.1
- [ ] npm: `@sourceorreryai/sdk` from 0.1.2, first published by hand, then by trusted publishing
- [x] The npm main tarball on the release page carries the generated loader (`index.js`) from 0.1.1; 0.1.0's does not
- [ ] ABI compatibility tests and semantic versioning policy
- [ ] Package signing and provenance (Sigstore for npm and PyPI, cosign for the archives)

## Milestone 3 — local broker and agent isolation

- [ ] Authenticated local protocol over Unix sockets / named pipes (length-prefixed, versioned)
- [ ] Capability-based authorisation; short-lived, secret-scoped grants
- [ ] Verified workload identity where the OS can provide it; honest labelling where it cannot
- [ ] Agent-aware access profiles: no production secrets by default, scoped test credentials, lifetime limits
- [ ] Hostile same-user process and compromised-workspace test suite
- [ ] Security review before the broker is described as a boundary

## Milestone 4 — enterprise integrations

- [ ] Remote providers behind the same contract: Azure Key Vault, AWS Secrets Manager, HashiCorp Vault, SourceOrrery server
- [ ] `AsyncSecretClient`
- [ ] Workload identity federation, RBAC, centrally administered policy and revocation
- [ ] Rotation workflows with issuer cooperation (issue → validate → activate → retire)
- [ ] Central audit collection
- [ ] Security review before "enterprise-ready"

## Milestone 5 — community expansion

- [ ] Published C ABI specification and SDK templates
- [ ] Kotlin, Swift, Ruby, Dart, Elixir bindings via the harness (Java, Go and PHP shipped in milestone 2)
- [ ] Tier 2 platforms: musl, ARMv7; community: FreeBSD, OpenBSD
