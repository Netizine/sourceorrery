# Python

## Install

### From PyPI

```bash
pip install sourceorrery
```

[`sourceorrery` on PyPI](https://pypi.org/project/sourceorrery/) has abi3
wheels for Python 3.11+ on Windows, macOS and Linux (glibc), x64 and arm64,
built with PyO3 and maturin, with no runtime dependencies, so nothing is
compiled on install. `uv add sourceorrery` and `poetry add sourceorrery`
install the same package. On any other platform pip builds the sdist,
which needs Rust 1.88+ and a C compiler.

To pin the exact files you install, see
[Supply chain](../supply-chain.md#pypi): the wheels on PyPI are byte for
byte the ones on the GitHub release, so their hashes can be checked
against each other.

### From the GitHub release

The same wheels and sdist are attached to the
[v0.1.4 release](https://github.com/Netizine/sourceorrery/releases/tag/v0.1.4).
Install the wheel for your platform straight from it:

<!-- tabs: os -->

#### Windows

```bash
# x64
pip install https://github.com/Netizine/sourceorrery/releases/download/v0.1.4/sourceorrery-0.1.4-cp311-abi3-win_amd64.whl
# Arm64
pip install https://github.com/Netizine/sourceorrery/releases/download/v0.1.4/sourceorrery-0.1.4-cp311-abi3-win_arm64.whl
```

#### macOS

```bash
# Apple silicon
pip install https://github.com/Netizine/sourceorrery/releases/download/v0.1.4/sourceorrery-0.1.4-cp311-abi3-macosx_11_0_arm64.whl
# Intel
pip install https://github.com/Netizine/sourceorrery/releases/download/v0.1.4/sourceorrery-0.1.4-cp311-abi3-macosx_10_12_x86_64.whl
```

#### Linux

```bash
# x64
pip install https://github.com/Netizine/sourceorrery/releases/download/v0.1.4/sourceorrery-0.1.4-cp311-abi3-manylinux_2_28_x86_64.whl
# arm64
pip install https://github.com/Netizine/sourceorrery/releases/download/v0.1.4/sourceorrery-0.1.4-cp311-abi3-manylinux_2_28_aarch64.whl
```

<!-- /tabs -->

To pin it, put the same URL in `requirements.txt` as
`sourceorrery @ https://…/sourceorrery-0.1.4-cp311-abi3-win_amd64.whl`;
append `#sha256=<hash>` with the hash from the release's `SHA256SUMS` and
pip verifies the download. Any other platform builds the sdist from the same
release (`sourceorrery-0.1.4.tar.gz`; Rust 1.88+ required) with
`pip install <its URL>`.

### From source

See [Building from source](#building-from-source) below.

## Get a secret

```python
from sourceorrery import SecretReader

with SecretReader("development") as reader, reader.get("database-password") as secret:
    connect(password=secret.value.expose_text())
# the SDK's native buffer is zeroised when the `with` block ends
```

`SecretReader(vault, *, home=None, passphrase=None, passphrase_file=None, environment=True, manifest=None)`
opens the vault. With the default options, `SOURCEORRERY_HOME` locates the
vault; the OS credential store, then `SOURCEORRERY_PASSPHRASE`, then
`SOURCEORRERY_PASSPHRASE_FILE` unlock it. Pass `environment=False` to
ignore the two passphrase variables. The SDK never prompts interactively.

`manifest` is the `sourceorrery.toml` whose `[vaults.<name>]` tables say
which vaults are remote and where; the default is the nearest one above
the current directory, as `sourceorrery run` finds it. A vault declared
there is opened at its provider rather than as a local file, with the
credentials the provider's own tools expect from the environment: the
manifest never holds any. A vault without a table stays local.

> [!IMPORTANT]
> `expose_text()` returns a Python `str` copy. Leaving the `with` block
> clears the SDK's native buffer, but cannot erase that string or copies
> retained by `connect()`. Keep exposed values short-lived and out of logs.

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
        with reader.get("database-password") as secret:
            connect(password=secret.value.expose_text())
except VaultLockedError as err:
    print(err.hint)   # which passphrase sources were tried, how to add a protector
except SecretNotFoundError as err:
    print(err.hint)   # "Store it with `sourceorrery secret set database-password --vault development` ..."
except SourceOrreryError as err:
    print(err.code, err)
```

Classes: `VaultNotFoundError`, `VaultLockedError`,
`MigrationRequiredError`, `VaultMismatchError`, `SecretNotFoundError`,
`VersionNotFoundError`, `SecretDeletedError`, `PolicyError` with
`SecretDisabledError`, `SecretNotYetValidError` (`.transient` is true),
`SecretExpiredError`, `IntegrityError`, `UnsupportedError`,
`InvalidArgumentError`, `InvalidNameError`, `ManifestError`,
`PermissionDeniedError`, `StorageError`, and for remote vaults
`UnauthenticatedError` (the provider has no credentials for this process)
and `ProviderUnavailableError` (it could not be reached; `.transient` is
true). See [the SDK overview](index.md#errors) for what each hint says.

## Load a project

```python
import os
from sourceorrery import Project

with Project.load("sourceorrery.toml") as project:      # or Project.load() to discover it
    os.environ.update({s.env: s.value.expose_text() for s in project})
```

`Project.load` resolves every `[secrets.*]` entry the way `sourceorrery run`
does and raises the first required secret's error if one cannot be read.
`project.env("DATABASE_PASSWORD")`, `project.get("database-password")` and
iteration give the resolved entries.

> [!NOTE]
> This example deliberately copies values into this process's environment.
> Closing `Project` does not remove those variables or erase their string
> copies. Read individual values directly through the SDK when your
> application does not need environment-based configuration.

## Threads

A `SecretReader` may be shared between threads; the native call releases
the GIL, so reads run in parallel.

## Building from source

You need Git, Rust 1.88 or newer installed with rustup, and a C compiler
(on Linux also `pkg-config` and `libdbus-1-dev`);
[Building from source](../building.md#what-you-need) has the commands for
each platform. For this SDK, also Python 3.11 or newer with `pip`.

Get the code:

```bash
git clone https://github.com/Netizine/sourceorrery
cd sourceorrery
git checkout v0.1.4              # or stay on main for the newest changes
```

Build the package and install it into a virtual environment. pip fetches
maturin, which compiles the Rust extension; the first build takes a few
minutes.

```bash
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate (PowerShell), source .venv/Scripts/activate (Git Bash)
pip install ./bindings/python
python -c "import sourceorrery; print(sourceorrery.__version__)"
```

To install the build somewhere else, make a wheel and copy it there:

```bash
pip wheel ./bindings/python --no-deps -w dist    # dist/sourceorrery-<version>-cp311-abi3-<platform>.whl
```

The version is the one committed in the repository, not the release's;
[Get the code](../building.md#get-the-code) shows how to stamp the release
version first.

To run the tests, the example and the conformance harness, build the CLI,
which creates the test vault, and run the rest in Bash (Git Bash on
Windows) with the virtual environment active:

```bash
cargo build --release -p sourceorrery-cli
eval "$(bash scripts/ci/fixture-vault.sh)"       # a throwaway vault and the variables the tests read
pip install pytest
python -m pytest bindings/python/tests
python bindings/python/examples/get_secret.py "$SOURCEORRERY_TEST_VAULT" database-password
python tests/conformance/sdk/harness.py --runner python
```

What the fixture script creates: [The SDK test vault](../building.md#the-sdk-test-vault).
Source: [`bindings/python`](../../bindings/python/README.md).
