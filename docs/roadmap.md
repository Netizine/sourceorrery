# Roadmap

The 0.3.1 source tree includes the local vault, provider connections,
interactive management and read-only application SDKs described below.
Release availability is shown in the site header; an implemented feature
is not a claim that its packages have already been published.

## Available in 0.3.1

| Area | Implemented behaviour |
|------|-----------------------|
| Local vault | Encrypted SQLite storage, immutable value versions, enabled state and enforced time windows, recoverable or permanent deletion, authenticated metadata and audit history. |
| Keys and checks | This-machine key in the OS credential store, one recovery key, an optional password/authenticator view check for interactive viewing. SDKs, `run`, `check` and `init` do not use the view check. |
| Provider connections | Per-secret storage in the local file, HashiCorp Vault KV v2, AWS Secrets Manager or Azure Key Vault. Connection settings and optionally sealed credentials belong to the vault. |
| CLI | Setup, metadata inspection, explicit reveal, import from `.env`, manifest creation, checking and child-process delivery, rotation hooks, audit verification/export, vault export/import and shell completions. |
| Terminal screens | Setup and project wizards; metadata-only browsing with stable selection, compact layouts, scrollable help/forms, Actions, filters, sorting, cached inspection, text editing, theme preview, refresh feedback and idle locking. |
| SDKs | Read-only clients for Python, JavaScript/TypeScript, Rust, Java, .NET, Go, C, C++ and PHP, over one Rust client and its C ABI. |
| Agent integrations | Embedded installation and migration skills for the supported coding agents. The instructions keep values out of agent context; they do not enforce process isolation. |
| Rotation and auditing | Issue → validate → activate → retire where per-version properties are supported; local audit export as JSON Lines or OTLP, with provider-native trails documented separately. |
| Distribution | A single version across packages, six release targets, native-library ABI checks, locked builds, provenance/attestations, SBOMs and release validation gates. |

The [CLI reference](cli.md), [SDK guides](sdks/index.md),
[provider mappings](providers/index.md) and [architecture](architecture.md)
describe the supported behaviour and its limits. Schema 5 is the only
supported vault format; [export and import](upgrading.md) move supported
vaults between machines without providing a legacy migration layer.

## Release validation

Local tests and emulators cover important behaviour, but they do not
replace hosted platform tests, real-service validation or an independent
security audit. The [security review status](security-review.md) and
[release procedure](release.md) describe the evidence still required.
Physical terminal key-repeat/F2 checks, screen-reader use, authenticator
scanning and first-time-user usability remain manual acceptance work.

Platform binary signing and macOS notarisation remain future distribution
work. Current releases provide build-provenance attestations and checksums;
those are separate from operating-system signatures.

## Milestone 3 — local broker and agent isolation

This is future work. There is no broker process, local IPC service or
same-user isolation boundary in 0.3.1.

- Authenticated local protocol over Unix sockets and Windows named pipes.
- Short-lived, secret-scoped grants and capability-based authorisation.
- Verified workload identity where the OS can supply it.
- OS isolation that prevents an untrusted same-user process from simply
  impersonating an application or editing it to disclose a credential.
- Hostile-process and compromised-workspace tests, followed by security
  review before any isolation guarantee is made.

Provider IAM can restrict a remote identity today. It does not create a
local boundary between applications and agents running as the same user.
See the [threat model](threat-model.md).

## Later terminal work

A path picker is deferred until a demonstrated workflow needs it.
Asynchronous or paged loading needs a separate design for explicit audited
reads, cancellation, stale results and key/session ownership. Synchronous
refresh currently blocks input until it returns; the UI says so rather
than promising cancellation or responsive idle locking during the call.

## Broader platform and language support

Potential additions include Kotlin, Swift, Ruby, Dart and Elixir bindings,
plus musl Linux, ARMv7 and community BSD targets. These are not part of the
0.3.1 package matrix. An SDK must pass the shared read-only conformance
contract before it is supported.
