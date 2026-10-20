# Roadmap

## Milestone 1 — core and local CLI *(this release)*

- [x] Secret contracts (`SecretClient`), stable error codes, naming rules
- [x] Enforced policy: enabled, `not_before`, `expires_on`; latest-accessible selection
- [x] Encrypted SQLite vault; per-value AEAD bound to vault/name/version
- [x] Key protectors: OS credential store (Windows/macOS/Linux) and Argon2id passphrase; several per vault
- [x] Versions, soft delete, recovery, purge, retention with automatic purge
- [x] Metadata-only audit log, including failed unlocks
- [x] CLI: `vault`, `secret`, `audit`, `init`, `check`, `run`, `completions`
- [x] Value-free manifest `sourceorrery.toml`; `sourceorrery://` references
- [x] Conformance + security suites; CI on Ubuntu/Windows/macOS; release workflow
- [ ] Manual validation of the OS-keyring path on macOS and a Linux desktop
- [x] Metadata and audit-log integrity (MAC over mutable metadata)
- [ ] `backup` / `restore` (encrypted export of a vault or a secret)
- [ ] Package managers: Homebrew, WinGet, Scoop, `cargo install`; signed releases
- [x] Docs site at sourceorrery.ai (Astro Starlight) from `docs/`, deployed by Azure Static Web Apps (custom domain pending)

## Milestone 2 — first-class language bindings

- [x] `sourceorrery-ffi`: stable C ABI (`cbindgen`), versioned `CONTRACT_VERSION`
- [x] Read-only `so_reader_*` / `so_project_*` ABI and the `sourceorrery` client crate (unlock order, manifest loading, error hints)
- [x] Read-only SDKs: Python (PyPI, maturin), JavaScript/TypeScript (npm, napi-rs), Rust (crates.io), Java (Maven Central, FFM), .NET (NuGet, LibraryImport), Go (cgo), C, C++ (header-only), PHP (Packagist, FFI); each tested and its example run in CI on Ubuntu/Windows/macOS against a vault the CLI creates
- [x] Manual release workflow: GitHub Release with checksums, registry publish jobs skipped until their secrets exist, dry-run mode
- [x] Scoped value accessors (`with` / `using` / `try-with-resources` / `defer` / RAII / `Use(span)`) in every SDK
- [ ] Cross-language conformance harness driving `tests/conformance` scenarios (today: one shared fixture vault and equivalent read-only test suites per language)
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
