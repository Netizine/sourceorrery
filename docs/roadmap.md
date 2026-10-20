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
- [x] Reads load only the value they return (metadata projection for every version query; one ciphertext row per `get`)
- [ ] Listing cost: `list` and `list-deleted` still verify every version row and every checkpoint row of every secret, one query per secret, because which version is newest can only be judged against the complete set. A bulk checkpoint read and pagination on `list_*` are open; pagination is an API change and goes through core with a conformance test
- [ ] `backup` / `restore` (encrypted export of a vault or a secret)
- [ ] Package managers: Homebrew, WinGet, Scoop, `cargo install`; signed releases
- [x] Docs site at sourceorrery.ai (Astro Starlight) from `docs/`, deployed by Azure Static Web Apps (custom domain pending)

## Milestone 2 — first-class language bindings

- [x] `sourceorrery-ffi`: stable C ABI (`cbindgen`), versioned `CONTRACT_VERSION`
- [ ] .NET (`SourceOrrery` NuGet), Python (PyPI wheels via Maturin), Node.js (napi-rs)
- [ ] Cross-language conformance harness driving `tests/conformance` scenarios
- [ ] Scoped value accessors (callback / `using` / context manager) in every SDK
- [ ] ABI compatibility tests and semantic versioning policy

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
- [ ] Java/Kotlin, Swift, Go, PHP, Ruby, Dart, Elixir bindings via the harness
- [ ] Tier 2 platforms: musl, ARMv7; community: FreeBSD, OpenBSD
