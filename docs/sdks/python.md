# Python

```bash
pip install sourceorrery
```

Wheels for Python 3.11+ on Windows, macOS and Linux (glibc, x86-64 and
arm64), built with PyO3 and maturin. No runtime dependencies.

## Get a secret

```python
from sourceorrery import SecretReader

with SecretReader("development") as reader, reader.get("database-password") as secret:
    connect(password=secret.value.expose_text())
# the value is zeroised when the `with` block ends
```

`SecretReader(vault, *, home=None, passphrase=None, passphrase_file=None, environment=True)`
opens the vault. With no arguments it behaves like the CLI: `SOURCEORRERY_HOME`
locates the vault; the OS credential store, then `SOURCEORRERY_PASSPHRASE`,
then `SOURCEORRERY_PASSPHRASE_FILE` unlock it. Pass `environment=False` to
ignore the two passphrase variables.

| Call | Returns |
|------|---------|
| `reader.get(name)` | `Secret` for the newest accessible version |
| `reader.get(name, version)` | `Secret` for exactly that version |
| `reader.properties(name, version=None)` | `SecretProperties` (policy not applied) |
| `reader.resolve("sourceorrery://development/database-password")` | `Secret` |
| `reader.descriptor()` | `dict` describing the vault (no values) |
| `reader.close()` | releases the vault; also a context manager |

`Secret` has `.properties` (a frozen dataclass: `vault`, `name`, `version`,
`enabled`, `content_type`, `tags`, `not_before`, `expires_on`, `created_on`,
`updated_on`, `recovery_level`, `reference`) and `.value`, a `SecretValue`:

```python
value = secret.value
value.expose()        # bytes (a copy)
value.expose_text()   # str
len(value)
value.close()         # zeroise; expose() raises ValueError afterwards
repr(value)           # 'SecretValue([REDACTED])'
```

`pickle.dumps(value)`, `copy.copy(value)` and `json.dumps(value)` raise
`TypeError`.

## Errors

All exceptions derive from `sourceorrery.SourceOrreryError` and carry
`.code`, `.message` and `.hint`; `str(err)` is the message followed by the
hint.

```python
from sourceorrery import SecretReader, SecretNotFoundError, VaultLockedError, SourceOrreryError

try:
    with SecretReader("development") as reader:
        secret = reader.get("database-password")
except VaultLockedError as err:
    print(err.hint)   # which passphrase sources were tried, how to add a protector
except SecretNotFoundError as err:
    print(err.hint)   # "Store it with `sourceorrery secret set database-password --vault development` ..."
except SourceOrreryError as err:
    print(err.code, err)
```

Classes: `VaultNotFoundError`, `VaultLockedError`, `MigrationRequiredError`,
`SecretNotFoundError`, `VersionNotFoundError`, `SecretDeletedError`,
`PolicyError` with `SecretDisabledError`, `SecretNotYetValidError`
(`.transient` is true), `SecretExpiredError`, `IntegrityError`,
`UnsupportedError`, `InvalidArgumentError`, `InvalidNameError`,
`ManifestError`, `PermissionDeniedError`, `StorageError`. See
[the SDK overview](index.md#errors) for what each hint says.

## Load a project

```python
from sourceorrery import Project

with Project.load("sourceorrery.toml") as project:      # or Project.load() to discover it
    os.environ.update({s.env: s.value.expose_text() for s in project})
```

`Project.load` resolves every `[secrets.*]` entry the way `sourceorrery run`
does and raises the first required secret's error if one cannot be read.
`project.env("DATABASE_PASSWORD")`, `project.get("database-password")` and
iteration give the resolved entries.

## Threads

A `SecretReader` may be shared between threads; the native call releases
the GIL, so reads run in parallel.

## Building from source

```bash
pip install maturin
cd bindings/python && maturin develop --release
eval "$(bash ../../scripts/ci/fixture-vault.sh)" && python -m pytest
```

Source: [`bindings/python`](../../bindings/python/README.md).
