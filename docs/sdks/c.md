# C

The C ABI is the foundation of every binding that is not Python, Node or
Rust, and it is a complete SDK on its own. The full reference is
[bindings/README.md](../../bindings/README.md); this page covers the
read-only functions an application needs.

## Install

The `sourceorrery-ffi-0.1.1-<target>` archive on the
[v0.1.1 release](https://github.com/Netizine/sourceorrery/releases/tag/v0.1.1)
holds the shared library (`libsourceorrery_ffi.so` / `.dylib` /
`sourceorrery_ffi.dll` with its import library), the static library,
`include/sourceorrery.h` and the C++ header. Download the one for your
platform, unpack it, and point the compiler and the loader at it; the
example below is `get_secret.c` from the next section.

<!-- tabs: os -->

#### Windows

```powershell
$release = "https://github.com/Netizine/sourceorrery/releases/download/v0.1.1"
$dir = "$env:LOCALAPPDATA\sourceorrery-ffi"
Invoke-WebRequest "$release/sourceorrery-ffi-0.1.1-x86_64-pc-windows-msvc.zip" -OutFile sourceorrery-ffi.zip   # aarch64-pc-windows-msvc on Arm
Expand-Archive sourceorrery-ffi.zip -DestinationPath $dir -Force

cl /I "$dir\include" get_secret.c /link "$dir\sourceorrery_ffi.dll.lib"
$env:Path = "$dir;$env:Path"          # sourceorrery_ffi.dll must be on PATH at run time
.\get_secret.exe
```

#### macOS

```bash
release=https://github.com/Netizine/sourceorrery/releases/download/v0.1.1
archive=sourceorrery-ffi-0.1.1-aarch64-apple-darwin        # x86_64-apple-darwin on Intel
curl -LO "$release/$archive.tar.gz"
sudo mkdir -p /opt/sourceorrery && sudo tar xzf "$archive.tar.gz" -C /opt/sourceorrery --strip-components=1

cc -I/opt/sourceorrery/include get_secret.c -L/opt/sourceorrery -lsourceorrery_ffi -o get_secret
DYLD_LIBRARY_PATH=/opt/sourceorrery ./get_secret
```

#### Linux

```bash
release=https://github.com/Netizine/sourceorrery/releases/download/v0.1.1
archive=sourceorrery-ffi-0.1.1-x86_64-unknown-linux-gnu    # aarch64-unknown-linux-gnu on arm64
curl -LO "$release/$archive.tar.gz"
sudo mkdir -p /opt/sourceorrery && sudo tar xzf "$archive.tar.gz" -C /opt/sourceorrery --strip-components=1

cc -I/opt/sourceorrery/include get_secret.c -L/opt/sourceorrery -lsourceorrery_ffi -Wl,-rpath,/opt/sourceorrery -o get_secret
./get_secret
```

<!-- /tabs -->

Verify a download against the release's `SHA256SUMS` before unpacking it.
To link statically on Linux or macOS, use `libsourceorrery_ffi.a` from the
same directory (`-lpthread -ldl -lm` as well on Linux); on Windows the
static `sourceorrery_ffi.lib` is MSVC-built. Building the library yourself
is `cargo build --release -p sourceorrery-ffi`; it lands in
`target/release`.

## Get a secret

```c
#include <stdio.h>
#include <string.h>
#include "sourceorrery.h"

int main(void) {
    const char *vault = "development", *name = "database-password";
    so_reader *reader = NULL;
    so_bytes properties = {NULL, 0}, value = {NULL, 0};

    /* NULL options: SOURCEORRERY_HOME, the OS credential store, then
       SOURCEORRERY_PASSPHRASE and SOURCEORRERY_PASSPHRASE_FILE. */
    if (so_reader_open((const uint8_t *)vault, strlen(vault), NULL, 0, NULL, 0, &reader) != SO_STATUS_OK) {
        fprintf(stderr, "[%s] %s\n  %s\n", so_last_error_code(), so_last_error_message(), so_last_error_hint());
        return 1;
    }
    /* NULL version: the newest accessible version. */
    if (so_reader_get(reader, (const uint8_t *)name, strlen(name), NULL, 0, &properties, &value) != SO_STATUS_OK) {
        fprintf(stderr, "[%s] %s\n  %s\n", so_last_error_code(), so_last_error_message(), so_last_error_hint());
        so_reader_close(reader);
        return 1;
    }
    connect(value.ptr, value.len);          /* use the bytes ... */
    so_bytes_free(&value);                  /* ... then zeroise and free them */
    so_bytes_free(&properties);             /* JSON, NUL-terminated: properties.ptr is a C string */
    so_reader_close(reader);
    return 0;
}
```

## The read-only surface

| Function | Does |
|----------|------|
| `so_reader_open(name, options_json, passphrase, &reader)` | opens a vault. `options_json` (nullable) is `{"home": "...", "passphrase_file": "...", "environment": true}`; `passphrase` (nullable) is tried after the OS credential store and before the environment. |
| `so_reader_get(reader, name, version, &properties_json, &value)` | the newest accessible version (`version` NULL) or exactly `version` |
| `so_reader_properties(reader, name, version, &properties_json)` | metadata only, policy not applied |
| `so_reader_resolve(reader, reference, &properties_json, &value)` | `sourceorrery://vault/name[/version]` |
| `so_reader_descriptor(reader, &json)` | vault descriptor (no values) |
| `so_reader_close(reader)` | zeroises the vault key |
| `so_project_load(manifest_path, options_json, passphrase, &project)`, `so_project_count`, `so_project_info`, `so_project_entry(project, i, &entry_json, &value)`, `so_project_free` | the secrets a `sourceorrery.toml` declares, like `sourceorrery run` |
| `so_last_error_code()`, `so_last_error_message()`, `so_last_error_hint()` | per-thread error state after `SO_STATUS_ERROR`; the hint says what to do |
| `so_bytes_free(&bytes)` | zeroise and free any output buffer; NULL-safe and idempotent |

Conventions: strings in are `(ptr, len)` UTF-8, never NUL-terminated;
buffers out are `so_bytes {ptr, len}` with a hidden trailing NUL so JSON
can be read as a C string; metadata is JSON in the core's shape (keys
`vault`, `name`, `version`, `enabled`, `content_type`, `tags`,
`not_before`, `expires_on`, `created_on`, `updated_on`, `recovery_level`);
values are raw bytes and never appear in JSON, messages or hints. A reader
may be used from several threads; error state is per thread.

The write-capable `so_vault_*` / `so_secret_*` functions in the same
header exist for administrative tooling; an application should not link
them ([ADR 0005](../adr/0005-read-only-sdks.md)).

## Example and CI

`crates/sourceorrery-ffi/examples/get_secret.c` is the complete program;
CI compiles it with `cc -Wall -Wextra -Werror` and MSVC `/W4 /WX` and runs
it against a vault the CLI created.
