# sourceorrery/sourceorrery (PHP)

Read secrets from a [SourceOrrery](https://sourceorrery.ai) vault.
Secrets belong to the runtime, not the repository.

```php
use SourceOrrery\SecretReader;

$reader = SecretReader::open('development');
$secret = $reader->get('database-password');
connect(password: $secret->value->expose());
$secret->close();   // zeroises the value
```

The package only reads. The vault is unlocked the way the `sourceorrery`
CLI unlocks it: OS credential store first, then `SOURCEORRERY_PASSPHRASE`,
then `SOURCEORRERY_PASSPHRASE_FILE`. Every failure is a
`SourceOrreryException` subclass with a stable `code()` and a `hint`.

Requires PHP 8.2+ with the `ffi` extension (`ffi.enable=true`, or the
default `preload` setting for CLI scripts). The native library
(`libsourceorrery_ffi.so` / `.dylib` / `sourceorrery_ffi.dll`) comes from
the `sourceorrery-ffi-<version>-<target>` release archive: put it in the
directory named by `SOURCEORRERY_NATIVE_DIR`, or under
`native/<os>-<arch>/` inside this package, or on the loader's search path.

Documentation: <https://sourceorrery.ai/sdks/php/>. Source: `bindings/php`
in the repository.

## Tests

```bash
cargo build --release -p sourceorrery-ffi -p sourceorrery-cli
eval "$(bash scripts/ci/fixture-vault.sh)"
php bindings/php/tests/run.php
```
