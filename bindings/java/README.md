# SourceOrrery (Java)

**Read secrets from [SourceOrrery](https://sourceorrery.ai) vaults in
Java.** Secrets belong to the runtime, not the repository.

```java
try (SecretReader reader = SecretReader.open("development");
     Secret secret = reader.get("database-password")) {
    connect(secret.value().exposeText());   // closing zeroises the value
}
```

SourceOrrery replaces the plaintext `.env` file with an encrypted local
vault. This library is its read-only Java SDK: it opens a vault, reads the
newest accessible version of a secret (or an exact version), its
properties and `sourceorrery://` references, and loads every secret a
project's `sourceorrery.toml` declares. It cannot create, change or delete
a secret through its public API; reads still append audit events.

Documentation: [the Java guide](https://sourceorrery.ai/sdks/java/) ·
[Getting started](https://sourceorrery.ai/getting-started/) ·
[Threat model](https://sourceorrery.ai/security/threat-model/)

## Before you start: the CLI

### Option 1: Set up with the CLI

This SDK is read-only. Use the separately installed `sourceorrery` CLI to
create vaults and set secret values. Maven does not install the CLI. Follow
the [CLI installation guide](https://sourceorrery.ai/getting-started/#install), then:

```bash
sourceorrery vault create development
sourceorrery secret set database-password --vault development   # typed at a hidden prompt
```

The CLI does not have to be installed where your application runs: this
library opens the vault file itself.

### Option 2: Set up with an AI coding agent

```bash
sourceorrery init --integration all
```

Use your existing coding agent and ask: "Set up SourceOrrery for this
project without showing secret values." Replace `all` with your agent's
name to install only its skills. The agent handles the manifest, code and
launch commands; you create vaults and enter values privately.
The [agent setup guide](https://sourceorrery.ai/guides/ai-agents/)
also covers updating skills from the repository independently of the CLI.

## Install

```xml
<dependency>
  <groupId>ai.sourceorrery</groupId>
  <artifactId>sourceorrery</artifactId>
  <version>0.3.0</version>
</dependency>
```

From Maven Central. Requires Java 22+ (the Foreign Function and Memory
API, no JNI); run with `--enable-native-access=ALL-UNNAMED`. The jar
carries the native library for Windows, macOS and Linux (x86_64 and
aarch64) and extracts it on first use; set `SOURCEORRERY_NATIVE_DIR` to use
a library from elsewhere. Every file on Maven Central is signed with the
release key ([Supply chain](https://sourceorrery.ai/security/supply-chain/)).

## Secrets at a provider

A secret that one of the vault's connections stores (HashiCorp Vault, AWS
Secrets Manager or Azure Key Vault) is read at that provider by the same
calls, with the credentials the connection stores or the ones the
provider's own tools find in the environment
([providers](https://sourceorrery.ai/providers/)).

## Errors and values

Every failure is a `SourceOrreryException` (unchecked) or a subclass
(`SecretNotFoundException`, `VaultLockedException`,
`SecretExpiredException`, `UnauthenticatedException`,
`ProviderUnavailableException`, …) with a stable `code()` and a `hint()`
that says what to do. A value is a `SecretValue`: `toString()` is
`[REDACTED]`, the bytes come out only through `expose()`, `exposeText()`
or `use(...)`, and closing it zeroises them.

## Building from source

From a clone of the repository, with Rust 1.91.1+, a C compiler, JDK 22+
and Maven. The tests read a vault that the CLI creates; the fixture script
also points `SOURCEORRERY_NATIVE_DIR` at the library just built. In Bash
(Git Bash on Windows):

```bash
cargo build --release -p sourceorrery-cli -p sourceorrery-ffi
eval "$(bash scripts/ci/fixture-vault.sh)"
cd bindings/java && mvn test
```

Every step, with the prerequisites for each platform:
<https://sourceorrery.ai/sdks/java/#building-from-source>.

## Licence

MIT or Apache-2.0, at your option. Source:
<https://github.com/Netizine/sourceorrery/tree/main/bindings/java>.
