# C++

A header-only C++17 wrapper, `sourceorrery.hpp`, over the C ABI. It ships
next to `sourceorrery.h` in the `sourceorrery-ffi-<version>-<target>`
release archive; link `sourceorrery_ffi` as for [C](c.md).

## Get a secret

```cpp
#include <sourceorrery.hpp>

int main() {
    try {
        auto reader = sourceorrery::Reader::open("development");
        auto secret = reader.get("database-password");
        connect(secret.value.text());
        return 0;                          // `secret.value` is zeroised here, the reader closed
    } catch (const sourceorrery::Error& err) {
        std::cerr << '[' << err.code() << "] " << err.what() << '\n';   // what() = message + hint
        return 1;
    }
}
```

`Reader::open(vault)` behaves like the CLI: `SOURCEORRERY_HOME` locates
the vault; the OS credential store, then `SOURCEORRERY_PASSPHRASE`, then
`SOURCEORRERY_PASSPHRASE_FILE` unlock it. `Reader::open(vault, options)`
takes a `sourceorrery::OpenOptions{home, passphrase, passphrase_file,
environment}`.

| Call | Returns |
|------|---------|
| `reader.get(name)` | `Secret` for the newest accessible version |
| `reader.get(name, version)` | `Secret` for exactly that version |
| `reader.properties_json(name, version)` | the properties document (policy not applied) |
| `reader.resolve("sourceorrery://development/database-password")` | `Secret` |
| `reader.descriptor_json()` | the vault descriptor (no values) |
| `reader.close()` | releases the vault; the destructor does the same |

`Secret` holds `properties_json` (the core's JSON; `version()` and `name()`
read the two most-needed fields, `sourceorrery::json_string_field()` reads
any other flat string field, or parse it with your JSON library) and
`value`, a `SecretValue`: move-only, `data()` / `size()` / `view()` for the
bytes in place, `text()` for a copy, `close()` to zeroise early. The
destructor zeroises too.

## Errors

Every failure throws `sourceorrery::Error` (a `std::runtime_error`) or a
subclass: `VaultNotFoundError`, `VaultLockedError`,
`MigrationRequiredError`, `SecretNotFoundError` (also `version_not_found`),
`SecretDeletedError`, `PolicyError` (`disabled`, `not_yet_valid`,
`expired`), `IntegrityError`, `UnsupportedError`, `InvalidArgumentError`
(also `invalid_name`), `ManifestError`. Each has `code()`, `message()`,
`hint()`, `kind()`, `transient()` and `policy()`. See
[the SDK overview](index.md#errors).

## Load a project

```cpp
auto project = sourceorrery::Project::load("sourceorrery.toml");   // std::nullopt discovers it
for (const auto& secret : project.secrets()) {
    setenv(secret.env.c_str(), secret.value.text().c_str(), 1);
}
project.close();   // zeroise every value
```

## Building

`bindings/cpp/CMakeLists.txt` builds the example and the test against a
built `sourceorrery-ffi`:

```bash
cargo build --release -p sourceorrery-ffi
cmake -S bindings/cpp -B build/cpp -DSOURCEORRERY_NATIVE_DIR=$PWD/target/release
cmake --build build/cpp
```

CI compiles both with `-Wall -Wextra -Werror` (gcc, clang) and `/W4 /WX`
(MSVC) and runs them against a vault the CLI created. Source:
[`bindings/cpp`](../../bindings/cpp/README.md).
