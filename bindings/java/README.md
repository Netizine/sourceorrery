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
a secret: an application that only reads cannot be tricked into writing.

Documentation: [the Java guide](https://sourceorrery.ai/sdks/java/) ·
[Getting started](https://sourceorrery.ai/getting-started/) ·
[Threat model](https://sourceorrery.ai/security/threat-model/)

## Before you start: the CLI

This library only reads. Vaults are created, and secrets stored, with the
`sourceorrery` command-line tool, which Maven does not install. Install it
once on the machine where you manage secrets, from the
[GitHub release](https://github.com/Netizine/sourceorrery/releases/latest)
(Windows, macOS and Linux, x64 and arm64) or with
`cargo install --locked sourceorrery-cli --version 0.1.4`
([step by step](https://sourceorrery.ai/getting-started/#install)), then:

```bash
sourceorrery vault create development
sourceorrery secret set database-password --vault development   # typed at a hidden prompt
```

The CLI does not have to be installed where your application runs: this
library opens the vault file itself.

## Install

```xml
<dependency>
  <groupId>ai.sourceorrery</groupId>
  <artifactId>sourceorrery</artifactId>
  <version>0.1.4</version>
</dependency>
```

From Maven Central. Requires Java 22+ (the Foreign Function and Memory
API, no JNI); run with `--enable-native-access=ALL-UNNAMED`. The jar
carries the native library for Windows, macOS and Linux (x86_64 and
aarch64) and extracts it on first use; set `SOURCEORRERY_NATIVE_DIR` to use
a library from elsewhere. Every file on Maven Central is signed with the
release key ([Supply chain](https://sourceorrery.ai/security/supply-chain/)).

## Errors and values

Every failure is a `SourceOrreryException` (unchecked) or a subclass
(`SecretNotFoundException`, `VaultLockedException`,
`SecretExpiredException`, …) with a stable `code()` and a `hint()` that
says what to do. A value is a `SecretValue`: `toString()` is
`[REDACTED]`, the bytes come out only through `expose()`, `exposeText()`
or `use(...)`, and closing it zeroises them.

## Building from source

From a clone of the repository, with Rust 1.88+, a C compiler, JDK 22+
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
