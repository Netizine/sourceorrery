# SourceOrrery C ABI

This archive holds the C ABI of [SourceOrrery](https://sourceorrery.ai),
the encrypted local secrets vault, built for one platform. Secrets belong
to the runtime, not the repository.

| File | What it is |
|------|------------|
| `libsourceorrery_ffi.so` (Linux), `libsourceorrery_ffi.dylib` (macOS), `sourceorrery_ffi.dll` and its import library `sourceorrery_ffi.dll.lib` (Windows) | the shared library |
| `libsourceorrery_ffi.a` (Linux, macOS), `sourceorrery_ffi.lib` (Windows, MSVC) | the static library |
| `include/sourceorrery.h` | the C header |
| `include/sourceorrery.hpp` | the header-only C++17 wrapper |
| `LICENSE-MIT`, `LICENSE-APACHE` | the licences: MIT or Apache-2.0, at your option |

Check the archive against the release's `SHA256SUMS` before unpacking it.

## Who needs it

* **C and C++ programs** compile against the headers and link the library:
  [the C guide](https://sourceorrery.ai/sdks/c/),
  [the C++ guide](https://sourceorrery.ai/sdks/cpp/).
* **The Go and PHP SDKs** load the shared library from here: point
  `CGO_LDFLAGS` (Go) or `SOURCEORRERY_NATIVE_DIR` (PHP) at this directory
  ([Go](https://sourceorrery.ai/sdks/go/),
  [PHP](https://sourceorrery.ai/sdks/php/)).
* The Python, JavaScript, Rust, Java and .NET packages already contain
  the native code they need; they do not use this archive.

Use the archive from the same release as the SDK package you installed.

## Before you start: the CLI

The library's read-only functions are what applications use. Vaults are
created, and secrets stored, with the `sourceorrery` command-line tool,
which is in the `sourceorrery-<version>-<target>` archive of the same
release (or `cargo install --locked sourceorrery-cli`):

```bash
sourceorrery vault create development
sourceorrery secret set database-password --vault development   # typed at a hidden prompt
```

The CLI does not have to be installed where your application runs: the
library opens the vault file itself. Step by step:
[Getting started](https://sourceorrery.ai/getting-started/).

## A first program

```c
#include <stdio.h>
#include <string.h>
#include "sourceorrery.h"

int main(void) {
    const char *vault = "development", *name = "database-password";
    so_reader *reader = NULL;
    so_bytes properties = {NULL, 0}, value = {NULL, 0};
    if (so_reader_open((const uint8_t *)vault, strlen(vault), NULL, 0, NULL, 0, &reader) != SO_STATUS_OK ||
        so_reader_get(reader, (const uint8_t *)name, strlen(name), NULL, 0, &properties, &value) != SO_STATUS_OK) {
        fprintf(stderr, "[%s] %s\n  %s\n", so_last_error_code(), so_last_error_message(), so_last_error_hint());
        so_reader_close(reader);
        return 1;
    }
    /* use value.ptr, value.len, then: */
    so_bytes_free(&value);          /* zeroises and frees */
    so_bytes_free(&properties);
    so_reader_close(reader);
    return 0;
}
```

```bash
# Linux (macOS: drop the -Wl,-rpath part and set DYLD_LIBRARY_PATH)
cc -I include get_secret.c -L . -lsourceorrery_ffi -Wl,-rpath,"$PWD" -o get_secret
# Windows, in a Developer Command Prompt for VS; sourceorrery_ffi.dll must be on PATH at run time
cl /I include get_secret.c /link sourceorrery_ffi.dll.lib
```

`so_reader_*` and `so_project_*` only read. The `so_vault_*` and
`so_secret_*` functions in the same header administer vaults and are meant
for tooling, not applications. Every failure leaves a stable code, a
message and a hint (what to do) in per-thread error state; no value ever
appears in any of them. The full reference:
<https://github.com/Netizine/sourceorrery/blob/main/bindings/README.md>.

Documentation: <https://sourceorrery.ai>. Source:
<https://github.com/Netizine/sourceorrery>.
