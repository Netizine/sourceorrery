# SDKs

SourceOrrery ships a read-only client for ten languages. Each one does the
same five things and nothing more:

| | |
|---|---|
| **Open a vault** | by name: this machine's key in the OS credential store first, then the vault's recovery key (given in code, `SOURCEORRERY_RECOVERY_KEY`, or a file, `SOURCEORRERY_RECOVERY_KEY_FILE`), each source read only if the earlier ones did not open the vault, so a later file that is missing or empty fails only an open that needed it; never an interactive prompt and never the vault's view check. `SOURCEORRERY_HOME` says where vaults live. |
| **Get a secret** | the newest *accessible* version (enabled, inside its time window) or an explicit version. |
| **Read properties** | metadata of a version, without policy, so disabled and expired versions can be inspected. |
| **Resolve a reference** | `sourceorrery://vault/name[/version]`, the form the manifest and the CLI use. |
| **Load a project** | every secret a `sourceorrery.toml` declares, resolved like `sourceorrery run`: required secrets must resolve, optional ones that cannot are left out. |

There is no `set`, `update`, `delete`, `recover` or `purge`, no key,
check or connection management and no audit management in any SDK. Writing is the CLI's job; a library
that cannot write cannot be tricked into writing
([ADR 0005](../adr/0005-read-only-sdks.md)).

> [!IMPORTANT]
> Read-only describes the SDK's public secret-management API. Reads still
> append audit events, so the vault directory must be writable. The SDK
> does not isolate a compromised dependency from the rest of your process
> or prevent same-user code from invoking the CLI.

| Language | Package | Technology | Guide |
|----------|---------|------------|-------|
| Python | `sourceorrery` on PyPI | PyO3 + maturin, abi3 wheels (3.11+) | [Python](python.md) |
| JavaScript / TypeScript | `@sourceorreryai/sdk` on npm | napi-rs native addon, types included | [JavaScript](javascript.md) |
| Rust | `sourceorrery` on crates.io | the client crate itself | [Rust](rust.md) |
| Java | `ai.sourceorrery:sourceorrery` on Maven Central | Foreign Function and Memory API (Java 22+) | [Java](java.md) |
| .NET | `SourceOrrery` on NuGet | `LibraryImport` P/Invoke (.NET 8+) | [.NET](dotnet.md) |
| Go | `github.com/netizine/sourceorrery/bindings/go` | cgo | [Go](go.md) |
| C | `sourceorrery.h` in the release archive | the C ABI | [C](c.md) |
| C++ | `sourceorrery.hpp` in the release archive | header-only RAII wrapper | [C++](cpp.md) |
| PHP | `sourceorrery/sourceorrery` on Packagist | the FFI extension | [PHP](php.md) |

Why each technology: [ADR 0006](../adr/0006-binding-technologies.md).

## Installing

Each language page opens with its package registry. The 0.2.0 release publishes to
PyPI, npm (under the `@sourceorreryai` scope), crates.io, Maven Central, NuGet
and Packagist, with the Go module on pkg.go.dev. The
[v0.2.0 GitHub release](https://github.com/Netizine/sourceorrery/releases/tag/v0.2.0)
also carries the packages (wheels, npm tarballs, the jar, the NuGet
package) and the C ABI archive that the Go, C, C++ and PHP SDKs load. Use
these release files if a registry is still indexing the new version. Each
page ends with building that SDK from source;
[Building from source](../building.md) covers the tools every build needs.
How the packages are published and how to check them:
[Supply chain](../supply-chain.md).

## Setting up

> [!NOTE]
> Installing an SDK does not install the CLI or create a vault. Provision
> the vault with the CLI first. The SDK then opens the vault file directly;
> it does not need a CLI process running alongside your application.

Every SDK reads a vault that already exists, so the first steps are the
CLI's:

```bash
sourceorrery setup                             # screens: name, checks, recovery key, storage
sourceorrery secret set database-password --vault development
```

`setup` keeps this machine's key in the OS credential store and hands out
the vault's recovery key once. On a server, in a container or in CI there
is no credential store, or not this machine's: give the process the
recovery key in a file.

```bash
export SOURCEORRERY_RECOVERY_KEY_FILE=/run/secrets/vault-recovery-key
```

Provision that file through your environment's secret-management mechanism
and restrict it to the account running the application. Each SDK also
accepts a recovery key, a recovery-key file and a home directory in code,
for tests and unusual layouts. Avoid putting a recovery key in source code
or process arguments; an environment variable containing one can also be
inspected by other processes with sufficient privileges. The vault's view
check (a password, perhaps with an authenticator code) is for people
browsing the vault; an SDK never asks it.

### Secrets kept at a provider

A vault keeps each secret in its own file or at a provider through one of
its connections ([providers](../providers/index.md)). The SDK reads such a
secret at the provider with the same calls, signing in with the
credentials the connection stores, or with the provider's own chain on the
machine (`VAULT_TOKEN`, the AWS credential chain, an Azure identity); the
manifest never names a provider. HashiCorp Vault, AWS Secrets Manager and
Azure Key Vault are the providers; a provider the build leaves out fails
with `unsupported`, naming it. Who decides what, and the workload identity
set-up per platform: [enterprise.md](../enterprise.md).

## Errors

Every failure carries the core's stable [error code](../../crates/sourceorrery-core/src/error.rs),
a message and a **hint**: one actionable sentence produced by the Rust
core, so every language says the same thing.

| Code | Typed error | Hint says |
|------|-------------|-----------|
| `vault_not_found` | `VaultNotFound…` | how to create the vault with the CLI, and which home directory was searched |
| `locked` | `VaultLocked…` | which recovery-key sources were tried (option, `SOURCEORRERY_RECOVERY_KEY`, `SOURCEORRERY_RECOVERY_KEY_FILE`) and how to give one |
| `migration_required` | `MigrationRequired…` | the vault was written by an earlier release, which this one cannot read: recreate it with `sourceorrery setup` |
| `vault_mismatch` | `VaultMismatch…` | the file found for the vault holds another vault (renamed, copied or swapped in): move it back or restore the vault from a backup, and treat an unexplained swap as tampering |
| `not_found` | `SecretNotFound…` | how to store the secret (`sourceorrery secret set`) |
| `version_not_found` | `VersionNotFound…` (a `SecretNotFound…`) | list versions, or omit the version |
| `disabled`, `not_yet_valid`, `expired` | `SecretDisabled…`, `SecretNotYetValid…`, `SecretExpired…` (all `Policy…`) | the policy decision and the `secret update` that changes it; `not_yet_valid` is marked transient |
| `deleted` | `SecretDeleted…` | `sourceorrery secret recover` |
| `crypto` | `Integrity…` | the file failed an integrity check: compare with a backup, run `audit --verify` |
| `unsupported` | `Unsupported…` | no OS credential store here: give the recovery key; or this build has no provider for the one that stores the secret |
| `unauthenticated` | `Unauthenticated…` | store credentials in the vault's connection, or where the provider's own tools take them from (`VAULT_TOKEN`, the AWS credential chain, an Azure identity) |
| `permission_denied` | `PermissionDenied…` | the permission the provider's policy must grant this identity, and the command that shows which identity was refused |
| `provider_unavailable` | `ProviderUnavailable…` | check that the provider is reachable and the address in the vault's connection is right; transient, so retry |
| `invalid_argument`, `invalid_name` | `InvalidArgument…`, `InvalidName…` | the reference and name rules |
| `manifest` | `Manifest…` | fix `sourceorrery.toml`, check with `sourceorrery check` |
| `abi_mismatch` (Go, Java, .NET, PHP, C++) | the base type | the native library implements another C ABI version than the SDK was built for: install the `sourceorrery-ffi` library of the SDK's release. Raised by the SDK itself before anything is opened, never by the core ([ADR 0007](../adr/0007-versioning-and-compatibility.md)) |
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

> [!TIP]
> Use the language's context manager, `using`, RAII or explicit `close()`
> around the smallest scope that needs a value. Closing the SDK buffer does
> not erase a string already passed to a client library, an environment
> variable or a log.

## Compatibility

One version number covers the CLI, the crates, the C ABI and every SDK.
Before 1.0 a patch release (`0.x.y` → `0.x.(y+1)`) may add but never
breaks any of them, so an SDK and the native library it loads may differ
by a patch; a minor release may change behaviour and API, and a C ABI
change bumps `SO_ABI_VERSION`, which the bindings check when they load.
The rules per surface, and how CI checks them, are in
[ADR 0007](../adr/0007-versioning-and-compatibility.md).

## How the SDKs are tested

Every SDK has a test suite and an example that CI runs on Ubuntu, Windows
and macOS against a vault the job creates with the CLI
(`scripts/ci/fixture-vault.sh`: a vault that opens with its recovery key,
`SOURCEORRERY_RECOVERY_KEY` in the environment, secrets covering every
policy state, and in the provider jobs secrets kept at the provider
through a connection). A binding whose tests do not pass does not ship.

On top of the per-language suites, one **conformance harness** holds every
SDK to the same contract: `tests/conformance/sdk/scenarios.json` lists the
scenarios (unlock sources, latest and explicit versions, references,
policy refusals, missing secrets, project loading, with the codes,
messages and hints each must produce), each SDK ships a small *runner*
that executes one scenario, and `tests/conformance/sdk/harness.py` drives
a runner through all of them and judges the observations. CI runs it in
every SDK job; the protocol and how to add a scenario are in
[`tests/conformance/sdk/README.md`](../../tests/conformance/sdk/README.md).

To run them locally, from a clone of the repository with the tools in
[Building from source](../building.md#what-you-need), in Bash (Git Bash on
Windows):

```bash
cargo build --release -p sourceorrery-cli -p sourceorrery-ffi
eval "$(bash scripts/ci/fixture-vault.sh)"
# then, per language, what its page says under "Building from source", and
python tests/conformance/sdk/harness.py --runner python   # or rust, node, java, dotnet, go, c, cpp, php
```

Releases: [release.md](../release.md).
