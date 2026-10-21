# C++

A header-only C++17 wrapper, `sourceorrery.hpp`, over the C ABI.

## Install

`sourceorrery.hpp` ships next to `sourceorrery.h` in the `include/`
directory of the `sourceorrery-ffi-0.1.3-<target>` archive on the
[v0.1.3 release](https://github.com/Netizine/sourceorrery/releases/tag/v0.1.3),
together with the shared and static libraries. Download the one for your
platform, unpack it, and compile against it exactly as for [C](c.md#install);
the example below is `get_secret.cpp` from the next section.

<!-- tabs: os -->

#### Windows

```powershell
$release = "https://github.com/Netizine/sourceorrery/releases/download/v0.1.3"
$dir = "$env:LOCALAPPDATA\sourceorrery-ffi"
Invoke-WebRequest "$release/sourceorrery-ffi-0.1.3-x86_64-pc-windows-msvc.zip" -OutFile sourceorrery-ffi.zip   # aarch64-pc-windows-msvc on Arm
Expand-Archive sourceorrery-ffi.zip -DestinationPath $dir -Force

cl /std:c++17 /EHsc /I "$dir\include" get_secret.cpp /link "$dir\sourceorrery_ffi.dll.lib"
$env:Path = "$dir;$env:Path"          # sourceorrery_ffi.dll must be on PATH at run time
.\get_secret.exe
```

#### macOS

```bash
release=https://github.com/Netizine/sourceorrery/releases/download/v0.1.3
archive=sourceorrery-ffi-0.1.3-aarch64-apple-darwin        # x86_64-apple-darwin on Intel
curl -LO "$release/$archive.tar.gz"
sudo mkdir -p /opt/sourceorrery && sudo tar xzf "$archive.tar.gz" -C /opt/sourceorrery --strip-components=1

c++ -std=c++17 -I/opt/sourceorrery/include get_secret.cpp -L/opt/sourceorrery -lsourceorrery_ffi -o get_secret
DYLD_LIBRARY_PATH=/opt/sourceorrery ./get_secret
```

#### Linux

```bash
release=https://github.com/Netizine/sourceorrery/releases/download/v0.1.3
archive=sourceorrery-ffi-0.1.3-x86_64-unknown-linux-gnu    # aarch64-unknown-linux-gnu on arm64
curl -LO "$release/$archive.tar.gz"
sudo mkdir -p /opt/sourceorrery && sudo tar xzf "$archive.tar.gz" -C /opt/sourceorrery --strip-components=1

c++ -std=c++17 -I/opt/sourceorrery/include get_secret.cpp -L/opt/sourceorrery -lsourceorrery_ffi -Wl,-rpath,/opt/sourceorrery -o get_secret
./get_secret
```

<!-- /tabs -->

Verify a download against the release's `SHA256SUMS` before unpacking it.

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
