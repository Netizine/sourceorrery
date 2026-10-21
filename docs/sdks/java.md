# Java

## Install

### From the release

`sourceorrery-0.1.1.jar` on the
[v0.1.1 release](https://github.com/Netizine/sourceorrery/releases/tag/v0.1.1)
embeds the native library for Windows, macOS and Linux (x64 and arm64), so
one jar serves every platform. Install it into your local Maven repository,
then depend on it as usual:

<!-- tabs: os -->

#### Windows

```powershell
Invoke-WebRequest https://github.com/Netizine/sourceorrery/releases/download/v0.1.1/sourceorrery-0.1.1.jar -OutFile sourceorrery-0.1.1.jar
mvn install:install-file "-Dfile=sourceorrery-0.1.1.jar" "-DgroupId=ai.sourceorrery" "-DartifactId=sourceorrery" "-Dversion=0.1.1" "-Dpackaging=jar"
```

#### macOS

```bash
curl -LO https://github.com/Netizine/sourceorrery/releases/download/v0.1.1/sourceorrery-0.1.1.jar
mvn install:install-file -Dfile=sourceorrery-0.1.1.jar -DgroupId=ai.sourceorrery -DartifactId=sourceorrery -Dversion=0.1.1 -Dpackaging=jar
```

#### Linux

```bash
curl -LO https://github.com/Netizine/sourceorrery/releases/download/v0.1.1/sourceorrery-0.1.1.jar
mvn install:install-file -Dfile=sourceorrery-0.1.1.jar -DgroupId=ai.sourceorrery -DartifactId=sourceorrery -Dversion=0.1.1 -Dpackaging=jar
```

<!-- /tabs -->

```xml
<dependency>
  <groupId>ai.sourceorrery</groupId>
  <artifactId>sourceorrery</artifactId>
  <version>0.1.1</version>
</dependency>
```

```kotlin
implementation("ai.sourceorrery:sourceorrery:0.1.1")   // Gradle, with mavenLocal() among the repositories
```

Without a local repository, put the jar on the classpath directly:
`implementation(files("libs/sourceorrery-0.1.1.jar"))` in Gradle, or
`--class-path sourceorrery-0.1.1.jar` on the `java` command line.

### From Maven Central

The same coordinates resolve from Maven Central for every release from
0.1.1 on; no local install is needed then.

Requires Java 22 or newer: the binding uses the Foreign Function and
Memory API (`java.lang.foreign`) over the C ABI, with no JNI code and no
third-party dependency. The jar extracts the native library on first use;
set `SOURCEORRERY_NATIVE_DIR` to use a library from elsewhere. Run with
`--enable-native-access=ALL-UNNAMED` (or grant it to your module) to
silence the restricted-method warning.

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

```bash
cargo build --release -p sourceorrery-ffi
export SOURCEORRERY_NATIVE_DIR=$PWD/target/release
eval "$(bash scripts/ci/fixture-vault.sh)"
cd bindings/java && mvn test
```

Source: [`bindings/java`](../../bindings/java/README.md).
