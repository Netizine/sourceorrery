# C++

A header-only C++17 wrapper, `sourceorrery.hpp`, over the C ABI.

## Install

The C++ SDK is not on a package registry: the release archive is the
package, or [build it from source](#building-from-source).
`sourceorrery.hpp` ships next to `sourceorrery.h` in the `include/`
directory of the `sourceorrery-ffi-0.2.0-<target>` archive on the
[v0.2.0 release](https://github.com/Netizine/sourceorrery/releases/tag/v0.2.0),
together with the shared and static libraries. Download the one for your
platform, unpack it, and compile against it exactly as for [C](c.md#install);
the example below is `get_secret.cpp` from the next section.

<!-- tabs: os -->

#### Windows

```powershell
$release = "https://github.com/Netizine/sourceorrery/releases/download/v0.2.0"
$dir = "$env:LOCALAPPDATA\sourceorrery-ffi"
Invoke-WebRequest "$release/sourceorrery-ffi-0.2.0-x86_64-pc-windows-msvc.zip" -OutFile sourceorrery-ffi.zip   # aarch64-pc-windows-msvc on Arm
Expand-Archive sourceorrery-ffi.zip -DestinationPath $dir -Force

cl /std:c++17 /EHsc /I "$dir\include" get_secret.cpp /link "$dir\sourceorrery_ffi.dll.lib"
$env:Path = "$dir;$env:Path"          # sourceorrery_ffi.dll must be on PATH at run time
.\get_secret.exe
```

#### macOS

```bash
release=https://github.com/Netizine/sourceorrery/releases/download/v0.2.0
archive=sourceorrery-ffi-0.2.0-aarch64-apple-darwin        # x86_64-apple-darwin on Intel
curl -LO "$release/$archive.tar.gz"
sudo mkdir -p /opt/sourceorrery && sudo tar xzf "$archive.tar.gz" -C /opt/sourceorrery --strip-components=1

c++ -std=c++17 -I/opt/sourceorrery/include get_secret.cpp -L/opt/sourceorrery -lsourceorrery_ffi -o get_secret
DYLD_LIBRARY_PATH=/opt/sourceorrery ./get_secret
```

#### Linux

```bash
release=https://github.com/Netizine/sourceorrery/releases/download/v0.2.0
archive=sourceorrery-ffi-0.2.0-x86_64-unknown-linux-gnu    # aarch64-unknown-linux-gnu on arm64
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
environment, manifest}`. `manifest` names the `sourceorrery.toml` whose
`[vaults.<name>]` tables say which vaults are remote and at which provider
(default: the nearest one above the current directory); a vault with such
a table is opened at its provider instead of as a local file. Credentials
come from the provider's own environment, never from the manifest: [HashiCorp
Vault](../providers/hashicorp-vault.md) takes `VAULT_TOKEN` or the other
sources it documents, [AWS Secrets Manager](../providers/aws-secrets-manager.md)
the AWS default credential chain.

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
`MigrationRequiredError`, `VaultMismatchError`, `SecretNotFoundError`
(also `version_not_found`), `SecretDeletedError`, `PolicyError`
(`disabled`, `not_yet_valid`, `expired`), `IntegrityError`,
`UnsupportedError`, `InvalidArgumentError` (also `invalid_name`),
`ManifestError`, `UnauthenticatedError` (the remote provider has no
credentials for this process), `ProviderUnavailableError` (it could not be
reached). Each has `code()`, `message()`, `hint()`, `kind()`,
`transient()` (true for `not_yet_valid` and `provider_unavailable`) and
`policy()`. See [the SDK overview](index.md#errors).

## Load a project

```cpp
auto project = sourceorrery::Project::load("sourceorrery.toml");   // std::nullopt discovers it
for (const auto& secret : project.secrets()) {
    setenv(secret.env.c_str(), secret.value.text().c_str(), 1);
}
project.close();   // zeroise every value
```

## Building from source

You need Git, Rust 1.91.1 or newer installed with rustup, and a C compiler
(on Linux also `pkg-config` and `libdbus-1-dev`);
[Building from source](../building.md#what-you-need) has the commands for
each platform. For this SDK, also a C++17 compiler, and CMake 3.16 or
newer to build the example and the test.

The wrapper is a header; what you build is the C ABI library under it:

```bash
git clone https://github.com/Netizine/sourceorrery
cd sourceorrery
git checkout v0.2.0              # or stay on main for the newest changes
cargo build --release -p sourceorrery-ffi
```

Compile against `bindings/cpp/include` (for `sourceorrery.hpp`),
`crates/sourceorrery-ffi/include` (for `sourceorrery.h`, which it
includes) and the library in `target/release`, where the install steps
above use the unpacked archive. In CMake, `bindings/cpp/CMakeLists.txt`
defines an interface target, `sourceorrery`, that carries all three.

To build and run the example, the test and the conformance runner against
the test vault the CLI creates, build the CLI too and run the rest in Bash
from the repository root:

```bash
cargo build --release -p sourceorrery-cli -p sourceorrery-ffi
eval "$(bash scripts/ci/fixture-vault.sh)"       # a throwaway vault, the variables the tests read, SOURCEORRERY_NATIVE_DIR
cmake -S bindings/cpp -B build/cpp -DSOURCEORRERY_NATIVE_DIR="$SOURCEORRERY_NATIVE_DIR"
cmake --build build/cpp --config Release         # get_secret and reader_test
c++ -std=c++17 -Wall -Wextra -Werror -I bindings/cpp/include -I crates/sourceorrery-ffi/include \
    bindings/cpp/conformance/run.cpp -L "$SOURCEORRERY_NATIVE_DIR" -lsourceorrery_ffi -o build/conformance_cpp
export LD_LIBRARY_PATH="$SOURCEORRERY_NATIVE_DIR" DYLD_LIBRARY_PATH="$SOURCEORRERY_NATIVE_DIR"
ctest --test-dir build/cpp -C Release --output-on-failure
build/cpp/get_secret "$SOURCEORRERY_TEST_VAULT" database-password
python tests/conformance/sdk/harness.py --runner cpp
```

On Windows, run this in Git Bash started from a *Developer Command Prompt
for VS*, so that MSVC's `cl` is on `PATH`, as described for
[C](c.md#building-from-source). CMake builds into `build/cpp/Release/`
there; compile the runner with
`cl -nologo -std:c++17 -EHsc -W4 -WX -I bindings/cpp/include -I crates/sourceorrery-ffi/include bindings/cpp/conformance/run.cpp -Fe:build/conformance_cpp.exe -Fo:build/ -link "$SOURCEORRERY_NATIVE_DIR/sourceorrery_ffi.dll.lib"`
and put the DLL on `PATH` with
`export PATH="$(cygpath -u "$SOURCEORRERY_NATIVE_DIR"):$PATH"`.

CI compiles everything with `-Wall -Wextra -Werror` (gcc, clang) and
`/W4 /WX` (MSVC). What the fixture script creates:
[The SDK test vault](../building.md#the-sdk-test-vault).
Source: [`bindings/cpp`](../../bindings/cpp/README.md).
