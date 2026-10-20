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

```bash
pip install maturin
cd bindings/python
maturin develop --release        # into the active virtualenv
```

Tests read the vault created by `scripts/ci/fixture-vault.sh`:

```bash
eval "$(bash ../../scripts/ci/fixture-vault.sh)"
python -m pytest
```
