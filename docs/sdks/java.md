# Java

## Install

### From Maven Central

```xml
<dependency>
  <groupId>ai.sourceorrery</groupId>
  <artifactId>sourceorrery</artifactId>
  <version>0.1.3</version>
</dependency>
```

```kotlin
implementation("ai.sourceorrery:sourceorrery:0.1.3")   // Gradle
```

[`ai.sourceorrery:sourceorrery` on Maven Central](https://central.sonatype.com/artifact/ai.sourceorrery/sourceorrery)
is one jar that embeds the native library for Windows, macOS and Linux
(x64 and arm64), so the same dependency serves every platform. Every file
is signed with the release key; [Supply chain](../supply-chain.md#maven-central)
shows how to check it.

Requires Java 22 or newer: the binding uses the Foreign Function and
Memory API (`java.lang.foreign`) over the C ABI, with no JNI code and no
third-party dependency. The jar extracts the native library on first use;
set `SOURCEORRERY_NATIVE_DIR` to use a library from elsewhere. Run with
`--enable-native-access=ALL-UNNAMED` (or grant it to your module) to
silence the restricted-method warning.

### From the GitHub release

The same jar, `sourceorrery-0.1.3.jar`, is attached to the
[v0.1.3 release](https://github.com/Netizine/sourceorrery/releases/tag/v0.1.3).
Install it into your local Maven repository, then depend on it with the
coordinates above (in Gradle, with `mavenLocal()` among the repositories):

<!-- tabs: os -->

#### Windows

```powershell
Invoke-WebRequest https://github.com/Netizine/sourceorrery/releases/download/v0.1.3/sourceorrery-0.1.3.jar -OutFile sourceorrery-0.1.3.jar
mvn install:install-file "-Dfile=sourceorrery-0.1.3.jar" "-DgroupId=ai.sourceorrery" "-DartifactId=sourceorrery" "-Dversion=0.1.3" "-Dpackaging=jar"
```

#### macOS

```bash
curl -LO https://github.com/Netizine/sourceorrery/releases/download/v0.1.3/sourceorrery-0.1.3.jar
mvn install:install-file -Dfile=sourceorrery-0.1.3.jar -DgroupId=ai.sourceorrery -DartifactId=sourceorrery -Dversion=0.1.3 -Dpackaging=jar
```

#### Linux

```bash
curl -LO https://github.com/Netizine/sourceorrery/releases/download/v0.1.3/sourceorrery-0.1.3.jar
mvn install:install-file -Dfile=sourceorrery-0.1.3.jar -DgroupId=ai.sourceorrery -DartifactId=sourceorrery -Dversion=0.1.3 -Dpackaging=jar
```

<!-- /tabs -->

Without a local repository, put the jar on the classpath directly:
`implementation(files("libs/sourceorrery-0.1.3.jar"))` in Gradle, or
`--class-path sourceorrery-0.1.3.jar` on the `java` command line.

### From source

See [Building from source](#building-from-source) below.

## Get a secret

```java
import ai.sourceorrery.Secret;
import ai.sourceorrery.SecretReader;

try (SecretReader reader = SecretReader.open("development");
     Secret secret = reader.get("database-password")) {
    connect(secret.value().exposeText());
}   // closing zeroises the value and releases the vault
```

`SecretReader.open(vault)` behaves like the CLI: `SOURCEORRERY_HOME`
locates the vault; the OS credential store, then `SOURCEORRERY_PASSPHRASE`,
then `SOURCEORRERY_PASSPHRASE_FILE` unlock it. `SecretReader.open(vault,
OpenOptions.defaults().withHome(..).withPassphrase(..).withPassphraseFile(..).withEnvironment(false))`
overrides any of that.

| Call | Returns |
|------|---------|
| `reader.get(name)` | `Secret` for the newest accessible version |
| `reader.get(name, version)` | `Secret` for exactly that version |
| `reader.properties(name)` / `properties(name, Optional.of(version))` | `SecretProperties` record (policy not applied) |
| `reader.resolve("sourceorrery://development/database-password")` | `Secret` |
| `reader.descriptor()` | `VaultDescriptor` record (no values) |

`Secret` is a record of `properties()` (`vault`, `name`, `version`,
`enabled`, `contentType`, `tags`, `notBefore`, `expiresOn`, `createdOn`,
`updatedOn` as `Instant`, `recoveryLevel`, `reference()`) and `value()`, a
`SecretValue`:

```java
value.expose();                 // byte[] (a copy)
value.exposeText();             // String
value.use(bytes -> { ... });    // a copy that is wiped afterwards
value.length();
value.close();                  // zeroise; expose() throws IllegalStateException afterwards
value.toString();               // "[REDACTED]"
```

## Errors

Every failure is a `SourceOrreryException` (unchecked) or a subclass, with
`code()`, `detail()`, `hint()` and `getMessage()` (detail plus hint):

```java
try (SecretReader reader = SecretReader.open("development")) {
    reader.get("database-password");
} catch (VaultLockedException e) {
    System.err.println(e.hint());    // which passphrase sources were tried
} catch (SecretNotFoundException e) {
    System.err.println(e.hint());    // "Store it with `sourceorrery secret set ...`"
} catch (SourceOrreryException e) {
    System.err.println(e.code() + ": " + e.getMessage());
}
```

Classes: `VaultNotFoundException`, `VaultLockedException`,
`MigrationRequiredException`, `SecretNotFoundException`,
`VersionNotFoundException`, `SecretDeletedException`, `PolicyException`
with `SecretDisabledException`, `SecretNotYetValidException`
(`isTransient()`), `SecretExpiredException`, `IntegrityException`,
`UnsupportedException`, `InvalidArgumentException`, `InvalidNameException`,
`ManifestException`, `PermissionDeniedException`, `StorageException`. See
[the SDK overview](index.md#errors).

## Load a project

```java
try (Project project = Project.load("sourceorrery.toml")) {   // or Project.load() to discover it
    for (ProjectSecret secret : project.secrets()) {
        environment.put(secret.env(), secret.value().exposeText());
    }
}
```

`Project.load` resolves every `[secrets.*]` entry the way `sourceorrery run`
does and throws the first required secret's exception if one cannot be read.

## Threads

A `SecretReader` may be shared between platform or virtual threads.

## Building from source

You need Git, Rust 1.88 or newer installed with rustup, and a C compiler
(on Linux also `pkg-config` and `libdbus-1-dev`);
[Building from source](../building.md#what-you-need) has the commands for
each platform. For this SDK, also a JDK, 22 or newer (CI uses Temurin 25),
and Maven.

Get the code and build the native library the jar calls:

```bash
git clone https://github.com/Netizine/sourceorrery
cd sourceorrery
git checkout v0.1.3              # or stay on main for the newest changes
cargo build --release -p sourceorrery-ffi
```

Build the jar and install it into your local Maven repository
(`~/.m2`), where your project's build finds it:

```bash
cd bindings/java
mvn install -DskipTests          # ai.sourceorrery:sourceorrery:<version>, jar in target/
```

The version is the one committed in the repository, not the release's;
[Get the code](../building.md#get-the-code) shows how to stamp the release
version first. A jar built this way carries no native library (the release
workflow embeds one per platform), so tell it where yours is when your
application runs:

```bash
export SOURCEORRERY_NATIVE_DIR=/path/to/sourceorrery/target/release
# PowerShell: $env:SOURCEORRERY_NATIVE_DIR = "C:\path\to\sourceorrery\target\release"
```

To run the tests, the example and the conformance harness, build the CLI
too, which creates the test vault, and run the rest in Bash (Git Bash on
Windows) from the repository root:

```bash
cargo build --release -p sourceorrery-cli -p sourceorrery-ffi
eval "$(bash scripts/ci/fixture-vault.sh)"       # a throwaway vault, the variables the tests read, SOURCEORRERY_NATIVE_DIR
cd bindings/java
mvn test
java --enable-native-access=ALL-UNNAMED -cp target/classes examples/GetSecret.java "$SOURCEORRERY_TEST_VAULT" database-password
cd ../..
python tests/conformance/sdk/harness.py --runner java
```

Without the fixture's variables, `mvn test` skips the tests that read a
vault. What the fixture script creates:
[The SDK test vault](../building.md#the-sdk-test-vault).
Source: [`bindings/java`](../../bindings/java/README.md).
