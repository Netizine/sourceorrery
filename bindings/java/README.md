# SourceOrrery (Java)

Read secrets from a [SourceOrrery](https://sourceorrery.ai) vault.
Secrets belong to the runtime, not the repository.

```java
try (SecretReader reader = SecretReader.open("development");
     Secret secret = reader.get("database-password")) {
    connect(secret.value().exposeText());   // closed = zeroised
}
```

The library only reads. The vault is unlocked the way the `sourceorrery`
CLI unlocks it: OS credential store first, then `SOURCEORRERY_PASSPHRASE`,
then `SOURCEORRERY_PASSPHRASE_FILE`. Every failure is a
`SourceOrreryException` subclass with a stable `code()` and a `hint()`.

Requires Java 22+ (Foreign Function and Memory API); run with
`--enable-native-access=ALL-UNNAMED`. The jar carries the native library
for Windows, macOS and Linux (x86_64 and aarch64) and extracts it on first
use; set `SOURCEORRERY_NATIVE_DIR` to use a library from elsewhere.

```xml
<dependency>
  <groupId>ai.sourceorrery</groupId>
  <artifactId>sourceorrery</artifactId>
  <version>0.1.3</version>
</dependency>
```

Documentation: <https://sourceorrery.ai/sdks/java/>. Source:
`bindings/java` in the repository.

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
