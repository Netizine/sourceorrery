# sourceorrery (Python)

Read secrets from a [SourceOrrery](https://sourceorrery.ai) vault.
Secrets belong to the runtime, not the repository.

```python
from sourceorrery import SecretReader

with SecretReader("development") as reader, reader.get("database-password") as secret:
    connect(password=secret.value.expose_text())
```

The package only reads. The vault is unlocked the way the `sourceorrery`
CLI unlocks it: OS credential store first, then `SOURCEORRERY_PASSPHRASE`,
then `SOURCEORRERY_PASSPHRASE_FILE`. Every failure is a typed exception
with a stable `code` and a `hint` that says what to do.

Documentation: <https://sourceorrery.ai/sdks/python/>. Source:
`bindings/python` in the repository.

## Building from source

From a clone of the repository, with Rust 1.88+, a C compiler and Python
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
