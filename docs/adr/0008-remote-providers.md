# ADR 0008: Remote providers behind the same contract

**Status:** accepted · **Date:** 2026-10-23

## Context

SourceOrrery's contract, `SecretClient`, is synchronous because its one
backend is a local encrypted file. Milestone 4 adds remote backends,
HashiCorp Vault and AWS Secrets Manager, whose every
operation waits on the network. Applications that use those services are
largely async Rust, while the CLI, the C ABI and every SDK built on it are
synchronous and must keep working unchanged against any backend. There is
no SourceOrrery server: the providers' own services are the only remote
ends, and the rest of the system treats a remote vault as one more backend
behind the contract.

The workspace had no async runtime, and the lifecycle conformance suite
was a set of tests written against the SQLite vault, so nothing could judge
a second backend.

## Decision

**One contract, two shapes.** `sourceorrery-core` defines `SecretClient`
(synchronous) and `AsyncSecretClient` (asynchronous) with the same methods
and the same semantics table; the docs of `SecretClient` are the contract
for both. Providers implement the async shape. The local vault stays
synchronous. Policy (`enabled`, `not_before`, `expires_on`, newest
accessible version) is evaluated in core after a provider returns metadata,
so every backend enforces it identically, and a value crosses a provider as
`SecretBytes` the moment it leaves the HTTP body.

**Object safety through `async-trait`.** A provider is chosen at run time
from the manifest, so the CLI and the client crate hold a
`Box<dyn AsyncSecretClient>`. Native `async fn` in traits cannot yet be
called through `dyn`, so the trait uses the `async-trait` crate (one
proc-macro dependency; it boxes each returned future). The trait requires
`Send + Sync` so one client serves many tasks. Revisit when `dyn`-compatible
async traits land in stable Rust; the change would be an implementation
detail for callers that use `async`/`.await`.

**Adapters, in a new crate `sourceorrery-provider`.** `Blocking<A>`
implements `SecretClient` for any `AsyncSecretClient` by driving each call
to completion on a Tokio runtime: a current-thread runtime the adapter owns
(`Blocking::new`), or a handle to the application's (`Blocking::with_handle`).
`AsyncLocal<C>` implements `AsyncSecretClient` for any `Send + Sync`
`SecretClient` by running each call on Tokio's blocking pool, so an async
application reads the local vault without stalling its executor. Neither
adapter interprets a call: arguments, results and errors pass through, and
unit tests check that all 23 error codes survive both adapters and that the
page methods and `resolve` reach the wrapped client's own implementation
rather than the trait defaults. The crate is the base the provider crates
build on; it holds no provider itself.

**Runtime and TLS.** Tokio, with only the `rt` feature in the adapter crate.
Providers that speak HTTP use `reqwest` with `rustls-tls` only, never
OpenSSL, so the Linux release archives stay free of system TLS libraries.

**Features.** The provider crates are optional dependencies behind Cargo
features `remote` (all providers) and `provider-vault`, `provider-aws`,
`provider-azure` in
`sourceorrery` and the CLI, on by default in the CLI,
the Rust SDK and the release archives of the C ABI, so `sourceorrery run`
and every SDK reach a remote vault out of the box; `--no-default-features`
builds stay local-only for size. The features are introduced with the first
provider (M4.3), when there is something for them to gate.

**Audit on a remote backend.** The provider's own service holds the audit
trail (Vault audit devices, CloudTrail). `audit_events` on a
remote client returns `unsupported` with a hint naming where the log is;
the metadata-read recording the local vault does is not emulated. How both
logs are collected is M4.8.

**Conformance as a function.** The backend-independent lifecycle scenarios
are functions over `&dyn SecretClient` in `sourceorrery_conformance::lifecycle`,
and `lifecycle(fresh)` runs them all on fresh clients and names every
failing scenario. The SQLite tests run the suite directly and through
`Blocking<AsyncLocal<SqliteVault>>`, so the adapter pair is proven before
any provider exists; each provider's CI job runs the same function through
its `Blocking` adapter against a local emulator or a test service. What
stays backend-specific (version-id shape, purgeable vaults, the audit log,
protectors, the registry, reopening, backups, file tampering) stays in the
SQLite test files. Among the scenarios is the canary test that no error,
listing or `Debug` output carries a value, so it runs against every
backend.

A provider may legitimately differ from the local vault in what its
service cannot express; each provider's documentation lists its
differences, and the scenarios a provider skips because of them are named
in its CI job. `audit_events` returning `unsupported` is the one difference
common to all.

## Measurements

Taken on the first implementation (this repository at this ADR's date, a
4-core Linux container, Rust 1.97, clean `--release` builds):

| What | Cost |
|------|------|
| Crates added to the dependency graph of `sourceorrery-core` | 1 (`async-trait`, a proc macro; its own dependencies were already present) |
| Crates added for `sourceorrery-provider` | 3 more (`tokio` with `rt` only, `pin-project-lite`, `memchr`); 37 crates in its graph against 33 for core |
| Clean release build of `sourceorrery-core` | 10 s |
| `sourceorrery-provider` on top of it (Tokio and the adapters) | 2 s |
| `libtokio.rlib`, `rt` feature only | 2.7 MB before linking |
| The release CLI with the HashiCorp Vault provider (`remote` on, `reqwest` with `rustls`, Tokio, the provider) against the same build without it | 12.5 MB against 8.7 MB on x86_64 Linux: 3.8 MB for the HTTP and TLS stack, which the next providers share |
| The release CLI with the AWS Secrets Manager provider added (the official SDK, `default-features = false` plus `rt-tokio` and `default-https-client`, which keeps the legacy hyper 0.14 and rustls 0.21 stack out) | 20.1 MB against 12.5 MB: 7.7 MB, the largest dependency tree in the workspace (198 crates in the provider's graph), as the plan weighed |

## Consequences

* The CLI, the C ABI and every SDK gain remote backends without a change
  to their code: a `Blocking` adapter is a `SecretClient`. Async Rust
  applications get the local vault through `AsyncLocal` and remote ones
  directly.
* `sourceorrery-core` depends on a proc macro and `sourceorrery-provider`
  on Tokio. Neither is reachable from a `--no-default-features` build of
  the CLI once the features exist; until then the CLI does not link the
  provider crate at all.
* A `Blocking` adapter must not be called from inside an async task: Tokio
  refuses to block a runtime thread and panics. Async code uses the async
  shape directly. The adapter's docs say so.
* `CONTRACT_VERSION` stays `"1"`: a second shape of the same operations is
  additive, and nothing about the C ABI, the vault file or an existing
  declaration changes (ADR 0007: a minor release, 0.3.0).
* Every future backend is judged by the same code as the local vault, and
  a backend that fails is reported scenario by scenario.

## Release-planning amendment — 2026-10-23

The provider work originally planned for 0.3.0 is included in **0.2.0**.
The original release reference above is retained as decision history.
This remains a minor release under ADR 0007: the new public `Manifest`
and `OpenOptions` fields and `AuditOperation` variants can require changes
to Rust callers. The C ABI and vault-file compatibility rules remain
separate. See the [0.2.0 release scope](../roadmap.md#release-020).
