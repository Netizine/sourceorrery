# sourceorrery (Python)

**Read secrets from [SourceOrrery](https://sourceorrery.ai) vaults in
Python.** Secrets belong to the runtime, not the repository.

```python
from sourceorrery import SecretReader

with SecretReader("development") as reader, reader.get("database-password") as secret:
    connect(password=secret.value.expose_text())
# the value is zeroised when the `with` block ends
```

SourceOrrery replaces the plaintext `.env` file with an encrypted local
vault. This package is its read-only Python SDK: it opens a vault, reads
the newest accessible version of a secret (or an exact version), its
properties and `sourceorrery://` references, and loads every secret a
project's `sourceorrery.toml` declares. It cannot create, change or delete
a secret through its public API; reads still append audit events.

Documentation: [the Python guide](https://sourceorrery.ai/sdks/python/) ·
[Getting started](https://sourceorrery.ai/getting-started/) ·
[Threat model](https://sourceorrery.ai/security/threat-model/)

## Before you start: the CLI

This SDK is read-only. Use the separately installed `sourceorrery` CLI to
create vaults and set secret values. pip does not install the CLI. Follow
the [CLI installation guide](https://sourceorrery.ai/getting-started/#install), then:

```bash
sourceorrery vault create development
sourceorrery secret set database-password --vault development   # typed at a hidden prompt
```

The CLI does not have to be installed where your application runs: this
package opens the vault file itself.

## Install

```bash
pip install sourceorrery
```

abi3 wheels for Python 3.11+ on Windows, macOS and Linux (glibc), x64 and
arm64, with no runtime dependencies, so nothing is compiled on install.
Other platforms build the sdist, which needs Rust 1.91.1+ and a C compiler.

## Unlocking

`SecretReader("development")` finds the vault under `SOURCEORRERY_HOME`
(or the platform data directory) and opens it like the CLI: this machine's
key in the OS credential store first, then `SOURCEORRERY_RECOVERY_KEY`, then
the file named by `SOURCEORRERY_RECOVERY_KEY_FILE`; never an interactive
prompt, and never the vault's view check. On servers,
in containers and in CI, where this machine's key is not available, pass
the vault's recovery key as a file
([Headless](https://sourceorrery.ai/guides/headless/)).

A secret that one of the vault's connections stores (HashiCorp Vault, AWS
Secrets Manager or Azure Key Vault) is read at that provider by the same
calls, with the credentials the connection stores or the ones the
provider's own tools find in the environment
([providers](https://sourceorrery.ai/providers/)).

## Errors and values

Every failure is a `SourceOrreryError` subclass (`SecretNotFoundError`,
`VaultLockedError`, `SecretExpiredError`, …) with a stable `code` and a
`hint` that says what to do, such as the `sourceorrery secret set` command
that would store a missing secret. A value is a `SecretValue`: it prints
as `[REDACTED]`, refuses to be pickled, copied or serialised, and is
zeroised by `close()` or at the end of a `with` block.

## Building from source

From a clone of the repository, with Rust 1.91.1+, a C compiler and Python
3.11+, in a virtual environment:

```bash
pip install ./bindings/python    # pip fetches maturin and compiles the extension
```

The tests read a vault that the CLI creates; from the repository root, in
Bash (Git Bash on Windows):

```bash
cargo build --release -p sourceorrery-cli
eval "$(bash scripts/ci/fixture-vault.sh)"
pip install pytest
python -m pytest bindings/python/tests
```

Every step, with the prerequisites for each platform:
<https://sourceorrery.ai/sdks/python/#building-from-source>.

## Licence

MIT or Apache-2.0, at your option. Source:
<https://github.com/Netizine/sourceorrery/tree/main/bindings/python>.
