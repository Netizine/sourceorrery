# SDKs

SourceOrrery ships a read-only client for ten languages. Each one does the
same five things and nothing more:

| | |
|---|---|
| **Open a vault** | by name, unlocked the way the CLI unlocks it: the OS credential store first, then `SOURCEORRERY_PASSPHRASE`, then `SOURCEORRERY_PASSPHRASE_FILE`; never an interactive prompt. `SOURCEORRERY_HOME` says where vaults live. |
| **Get a secret** | the newest *accessible* version (enabled, inside its time window) or an explicit version. |
| **Read properties** | metadata of a version, without policy, so disabled and expired versions can be inspected. |
| **Resolve a reference** | `sourceorrery://vault/name[/version]`, the form the manifest and the CLI use. |
| **Load a project** | every secret a `sourceorrery.toml` declares, resolved like `sourceorrery run`: required secrets must resolve, optional ones that cannot are left out. |

There is no `set`, `update`, `delete`, `recover` or `purge`, no protector
and no audit management in any SDK. Writing is the CLI's job; a library
that cannot write cannot be tricked into writing
([ADR 0005](adr/0005-read-only-sdks.md)).

| Language | Package | Technology | Guide |
|----------|---------|------------|-------|
| Python | `sourceorrery` on PyPI | PyO3 + maturin, abi3 wheels (3.11+) | [Python](python.md) |
| JavaScript / TypeScript | `@sourceorrery/sdk` on npm | napi-rs native addon, types included | [JavaScript](javascript.md) |
| Rust | `sourceorrery` on crates.io | the client crate itself | [Rust](rust.md) |
| Java | `ai.sourceorrery:sourceorrery` on Maven Central | Foreign Function and Memory API (Java 22+) | [Java](java.md) |
| .NET | `SourceOrrery` on NuGet | `LibraryImport` P/Invoke (.NET 8+) | [.NET](dotnet.md) |
| Go | `github.com/netizine/sourceorrery/bindings/go` | cgo | [Go](go.md) |
| C | `sourceorrery.h` in the release archive | the C ABI | [C](c.md) |
| C++ | `sourceorrery.hpp` in the release archive | header-only RAII wrapper | [C++](cpp.md) |
| PHP | `sourceorrery/sourceorrery` on Packagist | the FFI extension | [PHP](php.md) |

Why each technology: [ADR 0006](adr/0006-binding-technologies.md).

## Setting up

Every SDK reads a vault that already exists, so the first steps are the
CLI's:

```bash
sourceorrery vault create development          # OS credential store
sourceorrery secret set database-password --vault development
```

On a server, in a container or in CI there is no credential store: give
the vault a passphrase protector and hand the passphrase to the process.

```bash
sourceorrery vault protector add --kind passphrase --vault development
export SOURCEORRERY_PASSPHRASE=...            # or SOURCEORRERY_PASSPHRASE_FILE=/run/secrets/vault
```

Each SDK also accepts a passphrase, a passphrase file and a home directory
in code, for tests and unusual layouts. Prefer the environment or a file in
production: process arguments and source code are visible to more people.

## Errors

Every failure carries the core's stable [error code](../crates/sourceorrery-core/src/error.rs),
a message and a **hint**: one actionable sentence produced by the Rust
core, so every language says the same thing.

| Code | Typed error | Hint says |
|------|-------------|-----------|
| `vault_not_found` | `VaultNotFound…` | how to create the vault with the CLI, and which home directory was searched |
| `locked` | `VaultLocked…` | which passphrase sources were tried (option, `SOURCEORRERY_PASSPHRASE`, `SOURCEORRERY_PASSPHRASE_FILE`) and how to add a protector |
| `migration_required` | `MigrationRequired…` | run `sourceorrery vault migrate <name>`; SDKs never migrate |
| `not_found` | `SecretNotFound…` | how to store the secret (`sourceorrery secret set`) |
| `version_not_found` | `VersionNotFound…` (a `SecretNotFound…`) | list versions, or omit the version |
| `disabled`, `not_yet_valid`, `expired` | `SecretDisabled…`, `SecretNotYetValid…`, `SecretExpired…` (all `Policy…`) | the policy decision and the `secret update` that changes it; `not_yet_valid` is marked transient |
| `deleted` | `SecretDeleted…` | `sourceorrery secret recover` |
| `crypto` | `Integrity…` | the file failed an integrity check: compare with a backup, run `audit --verify` |
| `unsupported` | `Unsupported…` | no OS credential store here: add a passphrase protector |
| `invalid_argument`, `invalid_name` | `InvalidArgument…`, `InvalidName…` | the reference and name rules |
| `manifest` | `Manifest…` | fix `sourceorrery.toml`, check with `sourceorrery check` |
| anything newer | the base type, code preserved | |

Names follow each language's conventions (`SecretNotFoundError` in
Python, `SecretNotFoundException` in Java, `ErrNotFound` sentinel in Go,
and so on). No error, message or hint ever contains a secret value.

## Values

A value is held in native memory until the application closes it, and the
library zeroises it then. The wrapper type prints as `[REDACTED]`, refuses
to be serialised where the language allows it, and hands the bytes out only
through an explicit call (`expose()`, `Text()`, `ExposeText()`). Once an
application copies the bytes out, keeping them safe is the application's
job: a Python `str`, a Java `String` or a JavaScript string cannot be
wiped, so keep such copies short-lived.

## How the SDKs are tested

Every SDK has a test suite and an example that CI runs on Ubuntu, Windows
and macOS against a vault the job creates with the CLI
(`scripts/ci/fixture-vault.sh`: a passphrase protector,
`SOURCEORRERY_PASSPHRASE` in the environment, secrets covering every
policy state). A binding whose tests do not pass does not ship. To run
them locally:

```bash
cargo build --release -p sourceorrery-cli -p sourceorrery-ffi
eval "$(bash scripts/ci/fixture-vault.sh)"
# then, per language, what its page says under "Building from source"
```

Releases: [release.md](release.md).
