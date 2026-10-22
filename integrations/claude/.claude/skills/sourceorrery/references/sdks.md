# Reading secrets from code

Every SDK only reads: the vault must already exist and hold the secrets
(created with the CLI). Each one opens the vault the way the CLI does:
`SOURCEORRERY_HOME` locates it, then the OS credential store,
`SOURCEORRERY_PASSPHRASE` and `SOURCEORRERY_PASSPHRASE_FILE` unlock it;
there is never a prompt. `Project.load()` finds the nearest
`sourceorrery.toml`, resolves every secret it declares (a required secret
that cannot be read is an error) and `env("NAME")` returns the value
delivered as that variable, or nothing if an optional one is missing.

Keep one project object for the life of the program and read from it;
closing it zeroises the values.

| Language | Install | Load and read one variable |
|----------|---------|----------------------------|
| Python 3.11+ | `pip install sourceorrery` | `Project.load().env("DATABASE_URL").expose_text()` |
| JavaScript / TypeScript, Node.js 20+ | `npm install @sourceorreryai/sdk` | `Project.load().env('DATABASE_URL').exposeText()` |
| Rust | `cargo add sourceorrery` | `Project::load(None, &OpenOptions::new())?.env("DATABASE_URL")` (a `SecretBytes`; `.expose_utf8()`) |
| Java 22+ | `ai.sourceorrery:sourceorrery` | `Project.load().env("DATABASE_URL").orElseThrow().exposeText()` |
| .NET 8+ | `dotnet add package SourceOrrery` | `Project.Load().Env("DATABASE_URL")?.ExposeText()` |
| Go (cgo) | `go get github.com/netizine/sourceorrery/bindings/go` | `p, err := sourceorrery.LoadProject("", nil)`; `p.Env("DATABASE_URL").Text()` |
| PHP 8.2+ with FFI | `composer require sourceorrery/sourceorrery` | `Project::load()->env('DATABASE_URL')?->expose()` |
| C++17 | header in the `sourceorrery-ffi` release archive | `sourceorrery::Project::load().env("DATABASE_URL")->text()` |
| C | `sourceorrery.h` in the same archive | `so_project_load`, then `so_project_entry` per secret |

Go, PHP, C and C++ also need the C ABI library from the
`sourceorrery-ffi-<version>-<target>` archive on the GitHub release
(Python, JavaScript, Rust, Java and .NET packages carry their native code).

Reading one secret without the manifest:

```python
from sourceorrery import SecretReader

with SecretReader("development") as reader, reader.get("database-url") as secret:
    connect(secret.value.expose_text())
```

The same `SecretReader` exists in every SDK. Errors are typed and carry a
`code` and a `hint` (what to do); no error ever contains a value. Values
print as `[REDACTED]`; copying one into a string keeps an unwipeable copy,
so keep such copies short-lived and never log them.

Per-language guides: https://sourceorrery.ai/sdks/
